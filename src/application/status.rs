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
        self.human_with_color(now, false)
    }
    pub fn human_with_color(&self, now: u64, color: bool) -> String {
        use crate::utils::paint;
        use std::fmt::Write;
        let mut out = String::new();
        let (label, code) = if self.last_observation == 0 {
            ("WAIT", 33)
        } else if self.last_observation > now {
            ("CLOCK ERROR", 31)
        } else if now - self.last_observation > 10 {
            ("STALE", 33)
        } else {
            ("ACTIVE", 32)
        };
        write!(out, "Hub: {}", paint(label, code, color)).unwrap();
        if self.last_observation > 0 {
            write!(out, " (heartbeat {})", ago(self.last_observation, now)).unwrap();
        }
        writeln!(out).unwrap();
        if self.agents.is_empty() {
            writeln!(
                out,
                "{} (run telegraff register NAME)",
                paint("Agents: 0", 33, color)
            )
            .unwrap();
        }
        for agent in &self.agents {
            write!(
                out,
                "{}: {}",
                agent.name,
                short_state(&agent.overall, color)
            )
            .unwrap();
            for channel in &agent.channels {
                if !channel.expected && channel.state != "UNENROLLED" {
                    continue;
                }
                let state = if channel.state == "PENDING" && channel.accepted_bytes > 0 {
                    "RECEIVED"
                } else {
                    &channel.state
                };
                write!(out, " | {}: {}", channel.channel, short_state(state, color)).unwrap();
                if channel.failures > 0 {
                    write!(out, " ({} failed)", channel.failures).unwrap();
                }
            }
            if agent.enrollment_failures > 0 {
                write!(out, " | {}", paint("DNS enrollment failed", 31, color)).unwrap();
            }
            writeln!(out).unwrap();
        }
        if self
            .dns
            .values()
            .any(|s| s.contains("ipv4_error=true") || s.contains("ipv6_error=true"))
        {
            writeln!(out, "{}", paint("DNS: lookup failed", 33, color)).unwrap();
        }
        if self.queued_notifications > 0 {
            writeln!(
                out,
                "Notifications: {} pending",
                paint(&self.queued_notifications.to_string(), 33, color)
            )
            .unwrap();
        }
        out
    }
    pub fn verbose_with_color(&self, now: u64, color: bool) -> String {
        use crate::utils::paint;
        use std::fmt::Write;
        let mut out = String::new();
        if self.last_observation == 0 {
            writeln!(
                out,
                "{}",
                paint(
                    "Hub: no observations yet. Start the hub to begin monitoring.",
                    33,
                    color
                )
            )
            .unwrap();
        } else if self.last_observation > now {
            writeln!(
                out,
                "{}",
                paint(
                    "Hub: observation timestamp is in the future; check the system clock.",
                    33,
                    color
                )
            )
            .unwrap();
        } else if now - self.last_observation > 10 {
            writeln!(
                out,
                "{} (last observed {}). Data may be stale; check whether the hub is running.",
                paint("Hub: no recent heartbeat", 33, color),
                ago(self.last_observation, now)
            )
            .unwrap();
        } else {
            writeln!(
                out,
                "{} (observed {}).",
                paint("Hub: recent heartbeat", 32, color),
                ago(self.last_observation, now)
            )
            .unwrap();
        }
        if self.agents.is_empty() {
            writeln!(out, "{}: no servers are being monitored.\nRun telegraff register NAME on the hub, copy NAME.toml to the agent, start the agent, and restart the hub to load the registration.", paint("No agents configured", 31, color)).unwrap();
        } else {
            writeln!(
                out,
                "Agents: {} (results from completed monitoring intervals)",
                self.agents.len()
            )
            .unwrap();
        }
        for agent in &self.agents {
            writeln!(
                out,
                "{}: {}",
                agent.name,
                colored_meaning(&agent.overall, color)
            )
            .unwrap();
            if agent.enrollment_failures > 0 {
                writeln!(out, "  Address-family enrollment failed for {} interval(s); check hub DNS and restart after correcting it.", agent.enrollment_failures).unwrap();
            }
            for channel in &agent.channels {
                if !channel.expected && channel.state != "UNENROLLED" {
                    continue;
                }
                let label = if channel.state == "PENDING" && channel.accepted_bytes > 0 {
                    paint("data received; interval result pending", 33, color)
                } else {
                    colored_meaning(&channel.state, color)
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
                "{}",
                paint(
                    "DNS warning: one or more lookups failed; see status --json for details.",
                    33,
                    color
                )
            )
            .unwrap();
        }
        writeln!(
            out,
            "Notifications waiting to be sent: {}",
            paint(
                &self.queued_notifications.to_string(),
                if self.queued_notifications == 0 {
                    32
                } else {
                    33
                },
                color
            )
        )
        .unwrap();
        if let Some(&(start, end)) = self.observation_gaps.last() {
            writeln!(out, "{}: last interruption lasted {}s (ended {}); {} recorded interruption(s). No observations were recorded during that time, so network health was unknown. This is a monitoring interruption, not proof of a network failure.", paint("Monitoring history", 33, color), end.saturating_sub(start), ago(end, now), self.observation_gaps.len()).unwrap();
        }
        writeln!(out, "Last observation: {}", self.last_observation).unwrap();
        for (source, observation) in &self.dns {
            writeln!(out, "DNS {source}: {observation}").unwrap();
        }
        for agent in &self.agents {
            for channel in &agent.channels {
                writeln!(out, "{} {}: expected={} state={} failures={} last_success={:?} cycle={:?} bytes={} udp_loss={:?}%", agent.name, channel.channel, channel.expected, channel.state, channel.failures, channel.last_success, channel.last_transfer_cycle, channel.accepted_bytes, channel.udp_loss_percent).unwrap();
            }
        }
        for (start, end) in &self.observation_gaps {
            writeln!(out, "Monitoring interruption: {start}..{end}").unwrap();
        }
        out
    }
}
fn short_state(state: &str, color: bool) -> String {
    let (label, code) = match state {
        "OK" => ("OK", 32),
        "DEGRADED" | "MISSING" | "ALERT" | "FAILING" => ("FAIL", 31),
        "PENDING" => ("WAIT", 33),
        "UNENROLLED" => ("UNENROLLED", 33),
        other => (other, 33),
    };
    crate::utils::paint(label, code, color)
}
fn colored_meaning(state: &str, color: bool) -> String {
    let code = match state {
        "OK" => 32,
        "DEGRADED" | "MISSING" | "ALERT" | "FAILING" => 31,
        _ => 33,
    };
    crate::utils::paint(meaning(state), code, color)
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
        let text = Status::new(&state, &[]).verbose_with_color(200, false);
        assert!(text.contains("no recent heartbeat"));
        assert!(text.contains("No agents configured"));
        assert!(text.contains("84s"));
        assert!(text.contains("not proof of a network failure"));
        assert!(!text.contains("dns_set="));
        assert!(!text.contains('\x1b'));
        let colored = Status::new(&state, &[]).verbose_with_color(200, true);
        assert!(colored.contains("\x1b[31mNo agents configured\x1b[0m"));
        assert!(colored.contains("\x1b[33mHub: no recent heartbeat\x1b[0m"));
        let fresh = Status::new(&state, &[]).verbose_with_color(101, true);
        assert!(fresh.contains("\x1b[32mHub: recent heartbeat\x1b[0m"));
    }
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    #[test]
    fn compact_pending_and_failures_are_distinct_from_completed_success() {
        let mut status = Status {
            last_observation: 100,
            queued_notifications: 0,
            dns: BTreeMap::new(),
            observation_gaps: vec![(1, 50)],
            agents: vec![AgentStatus {
                name: "test-node".into(),
                overall: "PENDING".into(),
                enrollment_failures: 0,
                channels: vec![ChannelStatus {
                    channel: "ipv4/tcp".into(),
                    expected: true,
                    state: "PENDING".into(),
                    failures: 0,
                    last_success: None,
                    last_transfer_cycle: Some(90),
                    accepted_bytes: 153600,
                    udp_loss_percent: None,
                }],
            }],
        };
        let text = status.human(101);
        assert_eq!(
            text,
            "Hub: ACTIVE (heartbeat 1s ago)\ntest-node: WAIT | ipv4/tcp: RECEIVED\n"
        );
        assert!(!text.contains("Monitoring history"));
        assert!(
            status
                .verbose_with_color(101, false)
                .contains("Monitoring history")
        );
        assert!(
            status
                .human_with_color(101, true)
                .contains("\x1b[33mRECEIVED\x1b[0m")
        );
        status.agents[0].overall = "DEGRADED".into();
        status.agents[0].channels[0].state = "FAILING".into();
        status.agents[0].channels[0].failures = 1;
        let text = status.human_with_color(101, true);
        assert!(text.contains("\x1b[31mFAIL\x1b[0m"));
        assert!(!text.contains("RECEIVED"));
        assert!(status.human(120).contains("Hub: STALE"));
        status.agents[0].overall = "OK".into();
        status.agents[0].channels[0].state = "OK".into();
        assert!(
            status
                .human_with_color(101, true)
                .contains("\x1b[32mOK\x1b[0m")
        );
    }
}
