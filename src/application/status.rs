use super::{Channel, Family, Policy, Protocol, State};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct Status {
    pub last_observation: u64,
    pub queued_notifications: usize,
    pub agents: Vec<AgentStatus>,
    pub dns: BTreeMap<String, String>,
    pub observation_gaps: Vec<(u64, u64)>,
}
#[derive(Serialize)]
pub struct AgentStatus {
    pub name: String,
    pub overall: String,
    pub enrollment_failures: u32,
    pub channels: Vec<ChannelStatus>,
}
#[derive(Serialize)]
pub struct ChannelStatus {
    pub channel: String,
    pub expected: bool,
    pub state: String,
    pub failures: u32,
    pub last_success: Option<u64>,
    pub last_transfer_cycle: Option<u64>,
    pub accepted_bytes: usize,
    pub udp_loss_percent: Option<f64>,
}
impl Status {
    pub fn new(state: &State, policies: &[Policy]) -> Self {
        let agents = policies
            .iter()
            .map(|p| {
                let mut channels = Vec::new();
                for family in [Family::Ipv4, Family::Ipv6] {
                    for protocol in [Protocol::Tcp, Protocol::Udp] {
                        let channel = Channel { family, protocol };
                        let label = channel.label();
                        let expected = p.families.contains(&family);
                        let saved = state
                            .channels
                            .get(&p.name)
                            .and_then(|s| s.get(&label))
                            .cloned()
                            .unwrap_or_default();
                        let last = state
                            .transfers
                            .iter()
                            .filter(|t| t.agent == p.name && t.channel == channel)
                            .max_by_key(|t| (t.cycle, t.bytes));
                        let bytes = last.map_or(0, |t| t.bytes);
                        channels.push(ChannelStatus {
                            channel: label,
                            expected,
                            state: if p.paused {
                                "PAUSED"
                            } else if expected {
                                saved.label()
                            } else if last.is_some() {
                                "UNENROLLED"
                            } else {
                                "NOT_APPLICABLE"
                            }
                            .into(),
                            failures: if expected { saved.failures } else { 0 },
                            last_success: saved.last_success,
                            last_transfer_cycle: last.map(|t| t.cycle),
                            accepted_bytes: bytes,
                            udp_loss_percent: (protocol == Protocol::Udp && last.is_some())
                                .then_some(100.0 * (1.0 - bytes as f64 / p.payload_bytes as f64)),
                        });
                    }
                }
                let expected: Vec<_> = channels.iter().filter(|c| c.expected).collect();
                let overall = if p.paused {
                    "PAUSED"
                } else if expected.is_empty() {
                    "PENDING"
                } else if expected.iter().all(|c| c.state == "ALERT") {
                    "MISSING"
                } else if expected.iter().any(|c| c.failures > 0) {
                    "DEGRADED"
                } else if expected.iter().all(|c| c.state == "OK") {
                    "OK"
                } else {
                    "PENDING"
                };
                AgentStatus {
                    name: p.name.clone(),
                    overall: overall.into(),
                    enrollment_failures: state
                        .enrollment_failures
                        .get(&p.name)
                        .copied()
                        .unwrap_or_default(),
                    channels,
                }
            })
            .collect();
        Self {
            last_observation: state.observed_until,
            queued_notifications: state.outbox.len(),
            agents,
            dns: state.dns.clone(),
            observation_gaps: state.gaps.clone(),
        }
    }
}
