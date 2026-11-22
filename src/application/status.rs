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

impl Status {
    /// Operator summary; machine-readable details remain available through --json.
    pub fn human(&self, now: u64) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        if self.last_observation == 0 {
            writeln!(
                out,
                "Hub: no observations yet. Start the hub to begin monitoring."
            )
            .unwrap();
        } else if self.last_observation > now {
            writeln!(
                out,
                "Hub: observation timestamp is in the future; check the system clock."
            )
            .unwrap();
        } else if now - self.last_observation > 10 {
            writeln!(out, "Hub: no recent heartbeat (last observed {}). Data may be stale; check whether the hub is running.", ago(self.last_observation, now)).unwrap();
        } else {
            writeln!(
                out,
                "Hub: recent heartbeat (observed {}).",
                ago(self.last_observation, now)
            )
            .unwrap();
        }
        if self.agents.is_empty() {
            writeln!(out, "No agents configured: no servers are being monitored.\nRun telegraff register NAME on the hub, copy NAME.toml to the agent, start the agent, and restart the hub to load the registration.").unwrap();
        } else {
            writeln!(
                out,
                "Agents: {} (results from completed monitoring intervals)",
                self.agents.len()
            )
            .unwrap();
        }
        for agent in &self.agents {
            writeln!(out, "{}: {}", agent.name, meaning(&agent.overall)).unwrap();
            if agent.enrollment_failures > 0 {
                writeln!(out, "  Address-family enrollment failed for {} interval(s); check hub DNS and restart after correcting it.", agent.enrollment_failures).unwrap();
            }
            for channel in &agent.channels {
                if !channel.expected && channel.state != "UNENROLLED" {
                    continue;
                }
                let label = if channel.state == "PENDING" && channel.accepted_bytes > 0 {
                    "data received; interval result pending"
                } else {
                    meaning(&channel.state)
                };
                write!(out, "  {}: {}", channel.channel, label).unwrap();
                if channel.failures > 0 {
                    write!(out, "; {} consecutive failed interval(s)", channel.failures).unwrap();
                }
                if let Some(time) = channel.last_success {
                    write!(out, "; last success {}", ago(time, now)).unwrap();
                }
                writeln!(out).unwrap();
            }
        }
        if self
            .dns
            .values()
            .any(|s| s.contains("ipv4_error=true") || s.contains("ipv6_error=true"))
        {
            writeln!(
                out,
                "DNS warning: one or more lookups failed; see status --json for details."
            )
            .unwrap();
        }
        writeln!(
            out,
            "Notifications waiting to be sent: {}",
            self.queued_notifications
        )
        .unwrap();
        if let Some(&(start, end)) = self.observation_gaps.last() {
            writeln!(out, "Monitoring history: last interruption lasted {}s (ended {}); {} recorded interruption(s). No observations were recorded during that time, so network health was unknown. This is a monitoring interruption, not proof of a network failure.", end.saturating_sub(start), ago(end, now), self.observation_gaps.len()).unwrap();
        }
        out
    }
}
fn ago(time: u64, now: u64) -> String {
    if time > now {
        return "in the future (check clock)".into();
    }
    let seconds = now - time;
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3600 {
        format!("{}m {}s ago", seconds / 60, seconds % 60)
    } else {
        format!("{}h {}m ago", seconds / 3600, seconds % 3600 / 60)
    }
}
fn meaning(state: &str) -> &str {
    match state {
        "OK" => "working",
        "DEGRADED" => "some channels are failing",
        "MISSING" => "all expected channels have failed for at least three intervals",
        "ALERT" => "failing; alert threshold reached",
        "FAILING" => "failing; alert after three consecutive failed intervals",
        "PENDING" => "waiting for the first completed monitoring interval",
        "PAUSED" => "monitoring paused",
        "UNENROLLED" => "unexpected address family; not enrolled for monitoring",
        "NOT_APPLICABLE" => "not monitored",
        _ => state,
    }
}
#[cfg(test)]
mod human_tests {
    use super::*;
    #[test]
    fn empty_and_stale_status_does_not_claim_healthy_monitoring() {
        let state = State {
            observed_until: 100,
            gaps: vec![(10, 94)],
            ..State::default()
        };
        let text = Status::new(&state, &[]).human(200);
        assert!(text.contains("no recent heartbeat"));
        assert!(text.contains("No agents configured"));
        assert!(text.contains("84s"));
        assert!(text.contains("not proof of a network failure"));
        assert!(!text.contains("dns_set="));
    }
}
