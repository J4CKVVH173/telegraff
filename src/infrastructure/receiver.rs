mod tcp;
mod udp;
pub use tcp::{tcp_loop, tcp_loop_guarded, tcp_loop_with_tls};
pub use udp::{udp_loop, udp_loop_guarded};

use super::{
    config::{AgentEntry, read_key},
    ingress::{Bucket, Guard, Limits, Rejection},
    wire::{DATA, Frame, MAX_FRAME, PART},
};
use crate::{
    application::{Family, Protocol, Transfer},
    utils::unix_time,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, oneshot},
    time::timeout,
};

pub enum Incoming {
    Transfer(Transfer),
    Dns(String, crate::application::ports::DnsObservation),
}
pub struct Intake {
    pub event: Incoming,
    pub accepted: oneshot::Sender<IntakeReply>,
}
#[derive(Debug, Default)]
pub struct IntakeReply {
    pub accepted: bool,
    pub families: Vec<Family>,
}
#[derive(Clone)]
pub struct Credential {
    pub entry: AgentEntry,
    pub key: Vec<u8>,
    quota: Arc<Mutex<(u64, usize)>>,
    packets: Arc<Mutex<Bucket>>,
    connections: Arc<Semaphore>,
    assemblies: Arc<Semaphore>,
}
pub type Registry = Arc<HashMap<String, Credential>>;
pub fn registry(entries: &[AgentEntry]) -> Result<Registry> {
    registry_with_limits(entries, &Limits::default())
}
pub fn registry_with_limits(entries: &[AgentEntry], limits: &Limits) -> Result<Registry> {
    Ok(Arc::new(
        entries
            .iter()
            .map(|e| {
                Ok((
                    e.name.clone(),
                    Credential {
                        entry: e.clone(),
                        key: read_key(&e.key_file)?,
                        quota: Arc::new(Mutex::new((0, 0))),
                        packets: Arc::new(Mutex::new(Bucket::new(
                            limits.agent_packets_per_second,
                            Instant::now(),
                        ))),
                        connections: Arc::new(Semaphore::new(limits.agent_tcp_connections)),
                        assemblies: Arc::new(Semaphore::new(limits.agent_assemblies)),
                    },
                ))
            })
            .collect::<Result<_>>()?,
    ))
}
pub fn family(ip: IpAddr) -> Family {
    match ip {
        IpAddr::V4(_) => Family::Ipv4,
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => Family::Ipv4,
        _ => Family::Ipv6,
    }
}
pub fn bind_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from_std(socket.into())?)
}
pub fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}
pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    ensure!(
        (super::wire::HEADER + super::wire::TAG..=MAX_FRAME).contains(&len),
        "Invalid frame size"
    );
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
fn authenticate(
    bytes: &[u8],
    registry: &Registry,
    peer: SocketAddr,
    protocol: Protocol,
    http: bool,
) -> Result<(Frame, Credential)> {
    let name = Frame::identity(bytes)?;
    let credential = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Unknown agent"))?;
    // Removal and key rotation revoke cached credentials before any new intake.
    ensure!(
        read_key(&credential.entry.key_file).is_ok_and(|key| key == credential.key),
        "Agent credential revoked or changed"
    );
    let frame = Frame::decode(bytes, &credential.key)?;
    ensure!(
        (frame.kind == DATA || (frame.kind == super::wire::IDENTITY && protocol == Protocol::Tcp))
            // HTTPS can terminate at an IPv4 proxy after an IPv6 client connection.
            // The family inside the authenticated frame describes that client leg.
            && (http || frame.channel.family == family(peer.ip()))
            && frame.channel.protocol == protocol,
        "Invalid channel"
    );
    ensure!(
        frame.total as usize == credential.entry.payload_bytes
            && !credential.entry.paused
            && (credential.entry.grace == credential.entry.interval
                || credential.entry.policy().accepts(frame.cycle, unix_time())),
        "Invalid cycle or total"
    );
    ensure!(
        credential.packets.lock().unwrap().take(Instant::now()),
        AgentLimit
    );
    {
        let mut quota = credential
            .quota
            .lock()
            .map_err(|_| anyhow::anyhow!("Rate limiter unavailable"))?;
        let quota_cycle = unix_time() / credential.entry.interval;
        if quota.0 != quota_cycle {
            *quota = (quota_cycle, 0);
        }
        quota.1 = quota.1.saturating_add(bytes.len());
        ensure!(quota.1 <= credential.entry.payload_bytes * 48, AgentLimit);
    }
    Ok((frame, credential.clone()))
}
#[derive(Debug)]
struct AgentLimit;
impl std::fmt::Display for AgentLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Agent resource quota reached")
    }
}
impl std::error::Error for AgentLimit {}
#[derive(Debug)]
struct QueueFull;
impl std::fmt::Display for QueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Intake queue unavailable")
    }
}
impl std::error::Error for QueueFull {}
fn rejected(guard: &Guard, error: &anyhow::Error) {
    guard.reject(if error.is::<AgentLimit>() {
        Rejection::AgentQuota
    } else if error.is::<QueueFull>() {
        Rejection::Queue
    } else {
        Rejection::Authentication
    });
}
async fn submit(
    tx: &mpsc::Sender<Intake>,
    guard: &Guard,
    frame: &Frame,
    bytes: usize,
    elapsed: Duration,
    invalid: bool,
    fingerprint: String,
) -> Option<crate::application::confirmation::Confirmation> {
    let (accepted, result) = oneshot::channel();
    let result_data = Transfer {
        agent: frame.agent.clone(),
        cycle: frame.cycle,
        channel: frame.channel,
        transfer: frame.transfer,
        bytes,
        duration_ms: elapsed.as_millis() as u64,
        invalid,
        fingerprint,
    };
    let confirmation = crate::application::confirmation::Confirmation::accepted(&result_data);
    if tx
        .try_send(Intake {
            event: Incoming::Transfer(result_data),
            accepted,
        })
        .is_err()
    {
        guard.reject(Rejection::Queue);
        return None;
    }
    match timeout(Duration::from_secs(1), result).await {
        Ok(Ok(reply)) => reply.accepted.then_some(confirmation),
        _ => {
            guard.reject(Rejection::Queue);
            None
        }
    }
}
pub struct Assembly {
    pub frame: Frame,
    pub started: Instant,
    hashes: BTreeMap<u16, [u8; 32]>,
    pub bytes: usize,
    pub invalid: bool,
    permits: Option<(
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    )>,
}
impl Assembly {
    pub fn new(frame: &Frame) -> Self {
        Self {
            frame: Frame {
                payload: Vec::new(),
                ..frame.clone()
            },
            started: Instant::now(),
            hashes: BTreeMap::new(),
            bytes: 0,
            invalid: false,
            permits: None,
        }
    }
    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        for (part, digest) in &self.hashes {
            hash.update(part.to_be_bytes());
            hash.update(digest);
        }
        hex::encode(hash.finalize())
    }
    pub fn expired(&self) -> bool {
        self.started.elapsed() >= Duration::from_secs(120)
    }
    pub fn add(&mut self, f: &Frame) -> Result<bool> {
        ensure!(!self.expired(), "UDP assembly expired");
        let total = f.total as usize;
        let parts = total.div_ceil(PART);
        ensure!(
            parts == f.parts as usize && (f.part as usize) < parts && parts > 0,
            "Invalid UDP part"
        );
        let expected = (total - f.part as usize * PART).min(PART);
        ensure!(f.payload.len() == expected, "Invalid UDP part size");
        ensure!(
            f.total == self.frame.total && f.parts == self.frame.parts,
            "Conflicting transfer metadata"
        );
        let hash: [u8; 32] = Sha256::digest(&f.payload).into();
        if let Some(old) = self.hashes.get(&f.part) {
            if *old != hash {
                self.invalid = true;
            }
            return Ok(false);
        }
        self.hashes.insert(f.part, hash);
        self.bytes += f.payload.len();
        Ok(true)
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    fn entry(dir: &std::path::Path, name: &str) -> AgentEntry {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(format!("{name}.key"));
        std::fs::write(&path, hex::encode([7; 32])).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        AgentEntry {
            name: name.into(),
            key_file: path,
            activation: 0,
            interval: 3600,
            offset: 0,
            grace: 3600,
            paused: false,
            families: vec![Family::Ipv4],
            auto: false,
            payload_bytes: 153600,
            udp_threshold: 99,
        }
    }
    fn frame(name: &str, protocol: Protocol) -> Frame {
        Frame {
            kind: DATA,
            agent: name.into(),
            cycle: unix_time(),
            channel: crate::application::Channel {
                family: Family::Ipv4,
                protocol,
            },
            transfer: 0,
            total: 153600,
            part: 0,
            parts: 153600usize.div_ceil(PART) as u16,
            payload: vec![0; PART],
        }
    }
    async fn until(mut predicate: impl FnMut() -> bool) {
        timeout(Duration::from_secs(2), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn assembly_limits_span_listeners_and_release_when_listener_stops() {
        for (global, per_agent, reason) in [(1, 8, "assemblies"), (8, 1, "agent_quota")] {
            let dir = tempfile::tempdir().unwrap();
            let limits = Limits {
                agent_assemblies: per_agent,
                ..Limits::default()
            };
            let registry = registry_with_limits(&[entry(dir.path(), "node")], &limits).unwrap();
            let guard = Guard::new(limits, global);
            let (tx, _rx) = mpsc::channel(8);
            let a = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
            let address_a = a.local_addr().unwrap();
            let b = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
            let address_b = b.local_addr().unwrap();
            let task_a = tokio::spawn(udp_loop_guarded(
                a,
                registry.clone(),
                tx.clone(),
                global,
                guard.clone(),
            ));
            let task_b = tokio::spawn(udp_loop_guarded(b, registry, tx, global, guard.clone()));
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut f = frame("node", Protocol::Udp);
            sender
                .send_to(&f.encode(&[7; 32]), address_a)
                .await
                .unwrap();
            until(|| guard.assemblies.available_permits() == global - 1).await;
            f.transfer = 1;
            sender
                .send_to(&f.encode(&[7; 32]), address_b)
                .await
                .unwrap();
            let mut rejected = 0;
            until(|| {
                for (r, n) in guard.take_rejections() {
                    assert_eq!(r, reason);
                    rejected += n;
                }
                rejected > 0
            })
            .await;
            task_a.abort();
            let _ = task_a.await;
            assert_eq!(guard.assemblies.available_permits(), global);
            sender
                .send_to(&f.encode(&[7; 32]), address_b)
                .await
                .unwrap();
            until(|| guard.assemblies.available_permits() == global - 1).await;
            task_b.abort();
            let _ = task_b.await;
            assert_eq!(guard.assemblies.available_permits(), global);
        }
    }
    #[tokio::test]
    async fn authenticated_tcp_quota_does_not_block_another_agent() {
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits {
            agent_tcp_connections: 1,
            ..Limits::default()
        };
        let registry = registry_with_limits(
            &[entry(dir.path(), "first"), entry(dir.path(), "second")],
            &limits,
        )
        .unwrap();
        let _reserved = registry["first"]
            .connections
            .clone()
            .try_acquire_owned()
            .unwrap();
        let guard = Guard::new(limits, 8);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel::<Intake>(8);
        let intake = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let _ = event.accepted.send(IntakeReply {
                    accepted: true,
                    families: Vec::new(),
                });
            }
        });
        let task = tokio::spawn(tcp_loop_guarded(
            listener,
            registry,
            tx,
            Arc::new(Semaphore::new(8)),
            None,
            guard.clone(),
        ));
        for name in ["first", "second"] {
            let mut f = frame(name, Protocol::Tcp);
            f.parts = 1;
            f.payload = vec![0; 153600];
            let mut stream = TcpStream::connect(address).await.unwrap();
            write_frame(&mut stream, &f.encode(&[7; 32])).await.unwrap();
            let result = timeout(Duration::from_secs(2), read_frame(&mut stream))
                .await
                .unwrap();
            assert_eq!(result.is_ok(), name == "second");
        }
        assert_eq!(guard.take_rejections(), vec![("agent_quota", 1)]);
        task.abort();
        intake.abort();
    }
}
