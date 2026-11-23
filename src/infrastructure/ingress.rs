//! Bounded, shared admission control before TLS and frame authentication.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub tcp_per_second: u32,
    pub tcp_per_ip_per_second: u32,
    pub tcp_connections_per_ip: usize,
    pub udp_per_second: u32,
    pub udp_per_ip_per_second: u32,
    pub tracked_ips: usize,
    pub agent_tcp_connections: usize,
    pub agent_assemblies: usize,
    pub agent_packets_per_second: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            tcp_per_second: 128,
            tcp_per_ip_per_second: 32,
            tcp_connections_per_ip: 16,
            udp_per_second: 50_000,
            udp_per_ip_per_second: 2_000,
            tracked_ips: 4096,
            agent_tcp_connections: 4,
            agent_assemblies: 8,
            agent_packets_per_second: 4096,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            [
                self.tcp_per_second,
                self.tcp_per_ip_per_second,
                self.udp_per_second,
                self.udp_per_ip_per_second,
                self.agent_packets_per_second
            ]
            .iter()
            .all(|n| (1..=1_000_000).contains(n)),
            "Invalid ingress packet limits"
        );
        ensure!(
            (1..=65536).contains(&self.tracked_ips)
                && (1..=4096).contains(&self.tcp_connections_per_ip)
                && (1..=4096).contains(&self.agent_tcp_connections)
                && (1..=65536).contains(&self.agent_assemblies),
            "Invalid ingress resource limits"
        );
        Ok(())
    }
}

pub(crate) struct Bucket {
    tokens: f64,
    updated: Instant,
    rate: u32,
}
impl Bucket {
    pub(crate) fn new(rate: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(rate) * 2.0,
            updated: now,
            rate,
        }
    }
    pub(crate) fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * f64::from(self.rate))
        .min(f64::from(self.rate) * 2.0);
        self.updated = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Rejection {
    GlobalRate,
    IpRate,
    IpCapacity,
    Connections,
    Authentication,
    AgentQuota,
    Assemblies,
    Oversize,
    Queue,
    Timeout,
}
const REASONS: [&str; 10] = [
    "global_rate",
    "ip_rate",
    "ip_capacity",
    "connections",
    "authentication_or_frame",
    "agent_quota",
    "assemblies",
    "oversize",
    "queue",
    "timeout",
];
struct Peer {
    tcp: Bucket,
    udp: Bucket,
    active: usize,
    seen: Instant,
}
struct State {
    tcp: Bucket,
    udp: Bucket,
    peers: HashMap<IpAddr, Peer>,
    cleanup: Instant,
    counts: [u64; 10],
}
pub struct Guard {
    limits: Limits,
    state: Mutex<State>,
    pub(crate) assemblies: Arc<Semaphore>,
}
pub struct Connection {
    guard: Arc<Guard>,
    ip: IpAddr,
}
impl Drop for Connection {
    fn drop(&mut self) {
        let mut state = self.guard.state.lock().unwrap();
        if let Some(peer) = state.peers.get_mut(&self.ip) {
            peer.active -= 1;
        }
    }
}
impl Guard {
    pub fn new(limits: Limits, assemblies: usize) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            state: Mutex::new(State {
                tcp: Bucket::new(limits.tcp_per_second, now),
                udp: Bucket::new(limits.udp_per_second, now),
                peers: HashMap::new(),
                cleanup: now,
                counts: [0; 10],
            }),
            limits,
            assemblies: Arc::new(Semaphore::new(assemblies)),
        })
    }
    fn admit(&self, ip: IpAddr, tcp: bool, now: Instant) -> bool {
        // Normalize mapped IPv4 so it cannot acquire a separate quota.
        let ip = normalize(ip);
        let mut s = self.state.lock().unwrap();
        if now.saturating_duration_since(s.cleanup) >= Duration::from_secs(1) {
            s.peers.retain(|_, p| {
                p.active > 0 || now.saturating_duration_since(p.seen) < Duration::from_secs(120)
            });
            s.cleanup = now;
        }
        if !(if tcp {
            s.tcp.take(now)
        } else {
            s.udp.take(now)
        }) {
            s.counts[Rejection::GlobalRate as usize] += 1;
            return false;
        }
        if !s.peers.contains_key(&ip) {
            if s.peers.len() >= self.limits.tracked_ips {
                s.counts[Rejection::IpCapacity as usize] += 1;
                return false;
            }
            s.peers.insert(
                ip,
                Peer {
                    tcp: Bucket::new(self.limits.tcp_per_ip_per_second, now),
                    udp: Bucket::new(self.limits.udp_per_ip_per_second, now),
                    active: 0,
                    seen: now,
                },
            );
        }
        let peer = s.peers.get_mut(&ip).unwrap();
        peer.seen = now;
        if !(if tcp {
            peer.tcp.take(now)
        } else {
            peer.udp.take(now)
        }) {
            s.counts[Rejection::IpRate as usize] += 1;
            return false;
        }
        if tcp {
            if peer.active >= self.limits.tcp_connections_per_ip {
                s.counts[Rejection::Connections as usize] += 1;
                return false;
            }
            peer.active += 1;
        }
        true
    }
    pub fn tcp(self: &Arc<Self>, ip: IpAddr) -> Option<Connection> {
        self.admit(ip, true, Instant::now()).then(|| Connection {
            guard: self.clone(),
            ip: normalize(ip),
        })
    }
    pub fn udp(&self, ip: IpAddr) -> bool {
        self.admit(ip, false, Instant::now())
    }
    pub fn reject(&self, reason: Rejection) {
        let mut state = self.state.lock().unwrap();
        state.counts[reason as usize] = state.counts[reason as usize].saturating_add(1);
    }
    /// Interval counters contain no peer addresses, names or untrusted input.
    pub fn take_rejections(&self) -> Vec<(&'static str, u64)> {
        let mut s = self.state.lock().unwrap();
        let counts = std::mem::take(&mut s.counts);
        REASONS
            .into_iter()
            .zip(counts)
            .filter(|(_, n)| *n > 0)
            .collect()
    }
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn burst_refills_and_does_not_exceed_capacity() {
        let now = Instant::now();
        let mut b = Bucket::new(2, now);
        for _ in 0..4 {
            assert!(b.take(now));
        }
        assert!(!b.take(now));
        assert!(b.take(now + Duration::from_millis(500)));
        assert!(!b.take(now + Duration::from_millis(500)));
        for _ in 0..4 {
            assert!(b.take(now + Duration::from_secs(60)));
        }
        assert!(!b.take(now + Duration::from_secs(60)));
    }
    #[test]
    fn bounded_ips_expire_and_active_connections_release() {
        let g = Guard::new(
            Limits {
                tracked_ips: 1,
                tcp_connections_per_ip: 1,
                ..Limits::default()
            },
            2,
        );
        let a = "192.0.2.1".parse().unwrap();
        let b = "192.0.2.2".parse().unwrap();
        let connection = g.tcp(a).unwrap();
        assert!(g.tcp(a).is_none());
        assert!(!g.udp(b));
        assert!(!g.admit(b, false, Instant::now() + Duration::from_secs(121)));
        drop(connection);
        assert!(g.admit(b, false, Instant::now() + Duration::from_secs(123)));
        assert_eq!(g.state.lock().unwrap().peers.len(), 1);
    }
    #[test]
    fn shared_global_and_per_ip_limits_and_counters() {
        let g = Guard::new(
            Limits {
                udp_per_second: 2,
                udp_per_ip_per_second: 1,
                ..Limits::default()
            },
            1,
        );
        let a = "192.0.2.1".parse().unwrap();
        let b = "192.0.2.2".parse().unwrap();
        let now = Instant::now();
        assert!(g.admit(a, false, now));
        assert!(g.admit(a, false, now));
        assert!(!g.admit(a, false, now));
        assert!(g.admit(b, false, now));
        assert!(!g.admit(b, false, now));
        assert_eq!(
            g.take_rejections(),
            vec![("global_rate", 1), ("ip_rate", 1)]
        );
        assert!(g.take_rejections().is_empty());
    }
    #[test]
    fn mapped_ipv4_shares_connection_quota() {
        let g = Guard::new(
            Limits {
                tcp_connections_per_ip: 1,
                ..Limits::default()
            },
            1,
        );
        let _c = g.tcp("192.0.2.1".parse().unwrap()).unwrap();
        assert!(g.tcp("::ffff:192.0.2.1".parse().unwrap()).is_none());
    }
}
