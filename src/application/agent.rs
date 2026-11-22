use super::{
    Channel, Family, Policy, Protocol,
    ports::{Clock, IdentityRequest, Resolution, Resolver, TransferRequest, Transport},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

pub struct AgentSettings {
    pub policy: Policy,
    pub hub: String,
    pub port: u16,
    pub timeout_seconds: u64,
    pub auto: bool,
}

#[derive(Debug, Serialize)]
pub struct AgentReport {
    pub agent: String,
    pub cycle: u64,
    pub dns: String,
    pub channels: Vec<ChannelReport>,
}
#[derive(Debug, Serialize)]
pub struct ChannelReport {
    pub channel: String,
    pub expected: bool,
    pub accepted: Option<bool>,
    pub receipt_received: bool,
    pub accepted_bytes: usize,
    pub transfers: Vec<Attempt>,
}
#[derive(Debug, Serialize)]
pub struct Attempt {
    pub transfer: u8,
    pub receipt_received: bool,
    pub accepted_bytes: usize,
}
impl AgentReport {
    pub fn successful(&self) -> bool {
        self.channels.iter().any(|c| c.expected)
            && self
                .channels
                .iter()
                .filter(|c| c.expected)
                .all(|c| c.accepted == Some(true) && c.receipt_received)
    }
}

pub async fn run(
    config: &AgentSettings,
    resolver: &impl Resolver,
    transport: &mut impl Transport,
    clock: &impl Clock,
) -> Result<AgentReport> {
    let policy = &config.policy;
    ensure!(!policy.paused, "Agent is paused");
    let cycle = policy
        .cycle_at(clock.now())
        .ok_or_else(|| anyhow::anyhow!("Agent activation is in the future"))?;
    ensure!(
        policy.accepts(cycle, clock.now()),
        "Outside the scheduled cycle window"
    );
    let started = Instant::now();
    let resolution = resolver.resolve(&config.hub).await.unwrap_or(Resolution {
        addresses: Vec::new(),
        ipv4_error: true,
        ipv6_error: true,
    });
    let enrolled = transport
        .identify(IdentityRequest {
            addresses: resolution
                .addresses
                .iter()
                .map(|ip| SocketAddr::new(*ip, config.port))
                .collect(),
            agent: policy.name.clone(),
            cycle,
            total: policy.payload_bytes,
            observation: resolution.observation(),
        })
        .await;
    let expected = if config.auto {
        enrolled
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| resolution.families())
    } else {
        policy.families.clone()
    };
    let mut families = expected.clone();
    for f in resolution.families() {
        if !families.contains(&f) {
            families.push(f);
        }
    }
    let deadline = (started + Duration::from_secs(config.timeout_seconds)).min(
        Instant::now()
            + Duration::from_secs(
                cycle
                    .saturating_add(policy.grace)
                    .saturating_sub(clock.now()),
            ),
    );
    let mut report = AgentReport {
        agent: policy.name.clone(),
        cycle,
        dns: resolution.summary(),
        channels: Vec::new(),
    };
    let channels: Vec<_> = families
        .iter()
        .flat_map(|&family| {
            [
                Channel {
                    family,
                    protocol: Protocol::Tcp,
                },
                Channel {
                    family,
                    protocol: Protocol::Udp,
                },
            ]
        })
        .collect();
    for (channel_index, channel) in channels.iter().copied().enumerate() {
        let f = channel.family;
        let protocol = channel.protocol;
        let channel_deadline = Instant::now()
            + deadline.saturating_duration_since(Instant::now())
                / ((channels.len() - channel_index) as u32);
        let addresses: Vec<_> = resolution
            .addresses
            .iter()
            .filter(|ip| {
                if ip.is_ipv4() {
                    Family::Ipv4 == f
                } else {
                    Family::Ipv6 == f
                }
            })
            .map(|ip| SocketAddr::new(*ip, config.port))
            .collect();
        let mut result = ChannelReport {
            channel: channel.label(),
            expected: expected.contains(&f),
            accepted: None,
            receipt_received: false,
            accepted_bytes: 0,
            transfers: Vec::new(),
        };
        for transfer in 0..3 {
            let mut accepted_bytes = 0;
            let mut received = false;
            let transfer_deadline = Instant::now()
                + channel_deadline.saturating_duration_since(Instant::now())
                    / u32::from(3 - transfer);
            for (address_index, address) in addresses.iter().enumerate() {
                let remaining = transfer_deadline.saturating_duration_since(Instant::now())
                    / ((addresses.len() - address_index) as u32);
                if remaining.is_zero() {
                    break;
                }
                let request = TransferRequest {
                    agent: policy.name.clone(),
                    cycle,
                    channel,
                    transfer,
                    total: policy.payload_bytes,
                };
                let attempt = transport.send(*address, request, remaining).await;
                if let Ok(bytes) = attempt {
                    accepted_bytes = bytes;
                    received = true;
                    break;
                }
            }
            let passed = match protocol {
                Protocol::Tcp => accepted_bytes == policy.payload_bytes,
                Protocol::Udp => {
                    accepted_bytes * 100 >= policy.payload_bytes * usize::from(policy.udp_threshold)
                }
            };
            if received {
                result.accepted = Some(result.accepted.unwrap_or(false) || passed);
            }
            result.receipt_received |= received && passed;
            result.accepted_bytes = result.accepted_bytes.max(accepted_bytes);
            result.transfers.push(Attempt {
                transfer,
                receipt_received: received,
                accepted_bytes,
            });
        }
        report.channels.push(result);
    }
    Ok(report)
}
