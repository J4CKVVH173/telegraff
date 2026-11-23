use super::{Channel, Family, Policy, Protocol, State};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct Status {
    pub last_observation: u64,
    pub queued_notifications: usize,
    pub discarded_notifications: u64,
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
    pub interval_seconds: u64,
    pub next_result_at: Option<u64>,
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
                        // Project accepted successes immediately, without changing the
                        // monitor's finalized counters or notification schedule.
                        let fresh_success = state
                            .transfers
                            .iter()
                            .filter(|t| {
                                t.agent == p.name
                                    && t.channel == channel
                                    && saved.last_finalized.is_none_or(|cycle| t.cycle > cycle)
                                    && t.passes(p)
                            })
                            .map(|t| t.cycle)
                            .max();
                        let bytes = last.map_or(0, |t| t.bytes);
                        channels.push(ChannelStatus {
                            channel: label,
                            expected,
                            state: if p.paused {
                                "PAUSED"
                            } else if expected {
                                if fresh_success.is_some() {
                                    "OK"
                                } else {
                                    saved.label()
                                }
                            } else if last.is_some() {
                                "UNENROLLED"
                            } else {
                                "NOT_APPLICABLE"
                            }
                            .into(),
                            failures: if expected && fresh_success.is_none() {
                                saved.failures
                            } else {
                                0
                            },
                            last_success: fresh_success.or(saved.last_success),
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
                let mut schedule = p.clone();
                if p.grace == p.interval
                    && let Some(&anchor) = state.cycle_anchors.get(&p.name)
                {
                    schedule.activation = anchor;
                    schedule.offset = anchor % schedule.interval;
                }
                let next_result_at = (!p.paused)
                    .then(|| {
                        p.channels()
                            .iter()
                            .map(|channel| {
                                let finalized = state
                                    .channels
                                    .get(&p.name)
                                    .and_then(|channels| channels.get(&channel.label()))
                                    .and_then(|saved| saved.last_finalized);
                                finalized
                                    .map_or_else(
                                        || schedule.first_cycle(),
                                        |cycle| cycle.saturating_add(p.interval),
                                    )
                                    .saturating_add(p.grace)
                            })
                            .min()
                    })
                    .flatten();
                AgentStatus {
                    interval_seconds: p.interval,
                    next_result_at,
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
            discarded_notifications: state.discarded_notifications,
            agents,
            dns: state.dns.clone(),
            observation_gaps: state.gaps.clone(),
        }
    }
}

impl Status {
    pub fn human(&self, now: u64) -> String {
        self.human_with_color(now, false)
    }
    pub fn human_with_color(&self, now: u64, color: bool) -> String {
        self.render(now, color, false)
    }
    pub fn verbose_with_color(&self, now: u64, color: bool) -> String {
        self.render(now, color, true)
    }
    fn render(&self, now: u64, color: bool, verbose: bool) -> String {
        use crate::utils::{duration, paint, timestamp};
        use std::fmt::Write;
        let mut out = String::new();
        let (label, code) = if self.last_observation == 0 {
            ("NO UPDATES", 33)
        } else if self.last_observation > now {
            ("CLOCK ERROR", 31)
        } else if now - self.last_observation > 10 {
            ("STALE", 33)
        } else {
            ("ACTIVE", 32)
        };
        write!(out, "Hub: {}", paint(label, code, color)).unwrap();
        if self.last_observation > 0 {
            write!(
                out,
                " (hub state updated {})",
                ago(self.last_observation, now)
            )
            .unwrap();
        }
        writeln!(out).unwrap();
        if self.discarded_notifications > 0 {
            writeln!(
                out,
                "Notification backlog overflow: {} older pending messages discarded",
                self.discarded_notifications
            )
            .unwrap();
        }
        if self.agents.is_empty() {
            writeln!(
                out,
                "{} (run telegraff register NAME)",
                paint("Agents: 0", 33, color)
            )
            .unwrap();
        }
        for agent in &self.agents {
            let expected: Vec<_> = agent.channels.iter().filter(|c| c.expected).collect();
            let received = expected.iter().filter(|c| c.accepted_bytes > 0).count();
            let summary = if agent.overall == "PENDING" {
                if expected.is_empty() {
                    "NO DATA (awaiting enrollment)".to_owned()
                } else {
                    format!("{received}/{} channels received", expected.len())
                }
            } else {
                short_state(&agent.overall).to_owned()
            };
            write!(
                out,
                "{}: {}{}",
                agent.name,
                paint(&summary, state_color(&agent.overall), color),
                if verbose {
                    format!("; interval {}", duration(agent.interval_seconds))
                } else {
                    String::new()
                }
            )
            .unwrap();
            if verbose {
                writeln!(out).unwrap();
                for channel in &agent.channels {
                    if !channel.expected && channel.state != "UNENROLLED" {
                        continue;
                    }
                    write!(
                        out,
                        "  {}: {}",
                        channel.channel,
                        channel_label(channel, color)
                    )
                    .unwrap();
                    if channel.accepted_bytes > 0 {
                        write!(out, "; {} KiB received", channel.accepted_bytes / 1024).unwrap();
                    }
                    if let Some(time) = channel.last_success {
                        write!(out, "; last OK {}", timestamp(time)).unwrap();
                    }
                    if let Some(loss) = channel.udp_loss_percent {
                        write!(out, "; loss {loss:.1}%").unwrap();
                    }
                    writeln!(out).unwrap();
                }
                if let Some(deadline) = agent.next_result_at {
                    let due = if deadline > now {
                        format!("in {}", duration(deadline - now))
                    } else {
                        "due".to_owned()
                    };
                    writeln!(
                        out,
                        "  {} result: {due}{}",
                        if agent.overall == "PENDING" {
                            "First"
                        } else {
                            "Next"
                        },
                        if label == "STALE" {
                            " (hub state is stale)"
                        } else {
                            ""
                        }
                    )
                    .unwrap();
                }
            } else {
                for channel in &agent.channels {
                    if !channel.expected && channel.state != "UNENROLLED" {
                        continue;
                    }
                    write!(
                        out,
                        " | {}: {}",
                        channel.channel,
                        channel_label(channel, color)
                    )
                    .unwrap();
                }
                writeln!(out).unwrap();
            }
            if agent.enrollment_failures > 0 {
                writeln!(out, "  {}", paint("DNS enrollment failed", 31, color)).unwrap();
            }
        }
        if verbose {
            for (source, observation) in &self.dns {
                let value = |key: &str| {
                    observation
                        .split_whitespace()
                        .find_map(|part| part.strip_prefix(key))
                        .unwrap_or("?")
                };
                let ipv4 = value("ipv4_records=");
                let ipv6 = value("ipv6_records=");
                write!(out, "DNS {source}: A={ipv4}, AAAA={ipv6}").unwrap();
                if value("ipv4_error=") == "true" {
                    write!(out, "; {}", paint("A lookup failed", 31, color)).unwrap();
                }
                if value("ipv6_error=") == "true" {
                    write!(out, "; {}", paint("AAAA lookup failed", 31, color)).unwrap();
                }
                writeln!(out).unwrap();
            }
        } else if self
            .dns
            .values()
            .any(|s| s.contains("ipv4_error=true") || s.contains("ipv6_error=true"))
        {
            writeln!(out, "{}", paint("DNS: lookup failed", 33, color)).unwrap();
        }
        if verbose || self.queued_notifications > 0 {
            writeln!(out, "Notifications: {} pending", self.queued_notifications).unwrap();
        }
        if verbose && !self.observation_gaps.is_empty() {
            writeln!(
                out,
                "Hub downtime ({} recorded; no monitoring):",
                self.observation_gaps.len()
            )
            .unwrap();
            for &(start, end) in &self.observation_gaps {
                writeln!(
                    out,
                    "  {} to {} ({})",
                    timestamp(start),
                    timestamp(end),
                    duration(end.saturating_sub(start))
                )
                .unwrap();
            }
        }
        out
    }
}
fn channel_label(channel: &ChannelStatus, color: bool) -> String {
    let label = if channel.state == "PENDING" {
        if channel.accepted_bytes > 0 {
            "RECEIVED"
        } else {
            "NO DATA"
        }
    } else {
        short_state(&channel.state)
    };
    let count = if channel.failures > 0 {
        format!(" ({} failed)", channel.failures)
    } else {
        String::new()
    };
    format!(
        "{}{count}",
        crate::utils::paint(label, state_color(&channel.state), color)
    )
}
fn short_state(state: &str) -> &str {
    match state {
        "DEGRADED" | "MISSING" | "ALERT" | "FAILING" => "FAIL",
        "PENDING" => "NO DATA",
        "NOT_APPLICABLE" => "not monitored",
        other => other,
    }
}
fn state_color(state: &str) -> u8 {
    match state {
        "OK" => 32,
        "DEGRADED" | "MISSING" | "ALERT" | "FAILING" => 31,
        _ => 33,
    }
}
fn ago(time: u64, now: u64) -> String {
    if time > now {
        "in the future (check clock)".into()
    } else {
        format!("{} ago", crate::utils::duration(now - time))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{ChannelState, Transfer};
    fn fixture() -> (State, Policy) {
        let state = State {
            observed_until: 200,
            cycle_anchors: BTreeMap::from([("node".into(), 100)]),
            dns: BTreeMap::from([("hub".into(), "ipv4_records=1 ipv6_records=0 ipv4_error=false ipv6_error=false dns_set=private-diagnostic-hash".into())]),
            gaps: vec![(1, 167)],
            transfers: vec![Transfer { agent:"node".into(), cycle:100, channel:Channel { family:Family::Ipv4, protocol:Protocol::Tcp }, transfer:0, bytes:153600, duration_ms:1, invalid:false, fingerprint:String::new() }],
            ..State::default()
        };
        let policy = Policy {
            name: "node".into(),
            activation: 0,
            interval: 3600,
            offset: 0,
            grace: 3600,
            paused: false,
            families: vec![Family::Ipv4],
            payload_bytes: 153600,
            udp_threshold: 99,
        };
        (state, policy)
    }
    #[test]
    fn initial_partial_delivery_has_a_reason_and_a_real_hub_deadline() {
        let (state, policy) = fixture();
        let status = Status::new(&state, &[policy]);
        assert_eq!(status.agents[0].next_result_at, Some(3700));
        let compact = status.human(200);
        assert_eq!(
            compact,
            "Hub: ACTIVE (hub state updated 0s ago)\nnode: 1/2 channels received | ipv4/tcp: OK | ipv4/udp: NO DATA\n"
        );
        let verbose = status.verbose_with_color(200, false);
        assert!(verbose.contains("interval 1h"));
        assert!(verbose.contains("First result: in 58m 20s"));
        assert!(verbose.contains("Hub downtime (1 recorded; no monitoring):"));
        assert!(verbose.contains("1970-01-01 00:00 UTC to 1970-01-01 00:02 UTC (2m 46s)"));
        assert!(verbose.contains("DNS hub: A=1, AAAA=0"));
        for raw in [
            "heartbeat",
            "Some(",
            "None",
            "private-diagnostic-hash",
            "expected=true",
            "not proof",
            "NOT_APPLICABLE",
        ] {
            assert!(
                !verbose.contains(raw),
                "Unexpected diagnostic representation: {raw}"
            );
        }
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["observation_gaps"][0][1], 167);
        assert_eq!(json["agents"][0]["next_result_at"], 3700);
        assert!(
            json["dns"]["hub"]
                .as_str()
                .unwrap()
                .contains("private-diagnostic-hash")
        );
    }
    #[test]
    fn successful_intake_updates_status_before_finalization() {
        let (mut state, policy) = fixture();
        let mut udp = state.transfers[0].clone();
        udp.channel.protocol = Protocol::Udp;
        state.transfers.push(udp);
        let status = Status::new(&state, std::slice::from_ref(&policy));
        assert!(status.human(200).contains("node: OK"));
        let colored = status.human_with_color(200, true);
        assert!(colored.contains("\x1b[32mOK\x1b[0m"));
        state.channels.insert(
            "node".into(),
            BTreeMap::from([
                (
                    "ipv4/tcp".into(),
                    ChannelState {
                        last_success: Some(3700),
                        last_finalized: Some(100),
                        ..ChannelState::default()
                    },
                ),
                (
                    "ipv4/udp".into(),
                    ChannelState {
                        failures: 1,
                        last_finalized: Some(100),
                        ..ChannelState::default()
                    },
                ),
            ]),
        );
        let status = Status::new(&state, &[policy]);
        assert!(
            status
                .human_with_color(200, true)
                .contains("\x1b[31mFAIL\x1b[0m")
        );
        assert!(
            status
                .human_with_color(200, true)
                .contains("\x1b[32mOK\x1b[0m")
        );
        assert_eq!(status.agents[0].next_result_at, Some(7300));
    }
    #[test]
    fn fresh_tcp_success_overrides_old_failure_but_not_udp_failure() {
        let (mut state, policy) = fixture();
        state.channels.insert(
            "node".into(),
            BTreeMap::from([
                (
                    "ipv4/tcp".into(),
                    ChannelState {
                        failures: 3,
                        last_finalized: Some(99),
                        ..Default::default()
                    },
                ),
                (
                    "ipv4/udp".into(),
                    ChannelState {
                        failures: 2,
                        last_finalized: Some(99),
                        ..Default::default()
                    },
                ),
            ]),
        );
        let status = Status::new(&state, std::slice::from_ref(&policy));
        assert!(
            status
                .human(200)
                .contains("node: FAIL | ipv4/tcp: OK | ipv4/udp: FAIL (2 failed)")
        );
        assert!(
            status
                .verbose_with_color(200, false)
                .contains("ipv4/tcp: OK; 150 KiB received")
        );
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["agents"][0]["channels"][0]["state"], "OK");
        assert_eq!(json["agents"][0]["channels"][0]["failures"], 0);
        assert_eq!(state.channels["node"]["ipv4/tcp"].failures, 3);
        // Invalid, incomplete, and already finalized receipts cannot recover it.
        for (invalid, bytes, cycle) in [(true, 153600, 100), (false, 1, 100), (false, 153600, 99)] {
            state.transfers[0].invalid = invalid;
            state.transfers[0].bytes = bytes;
            state.transfers[0].cycle = cycle;
            assert!(
                Status::new(&state, std::slice::from_ref(&policy))
                    .human(200)
                    .contains("ipv4/tcp: FAIL (3 failed)")
            );
        }
    }
    #[test]
    fn no_data_stale_paused_and_unenrolled_are_not_success() {
        let (mut state, mut policy) = fixture();
        state.transfers.clear();
        assert!(
            Status::new(&state, std::slice::from_ref(&policy))
                .human(200)
                .contains("0/2 channels received")
        );
        assert!(
            Status::new(&state, std::slice::from_ref(&policy))
                .human(220)
                .contains("Hub: STALE")
        );
        policy.families.clear();
        let status = Status::new(&state, std::slice::from_ref(&policy));
        assert!(status.human(200).contains("awaiting enrollment"));
        assert_eq!(status.agents[0].next_result_at, None);
        policy.paused = true;
        let status = Status::new(&state, &[policy]);
        assert!(status.human(200).contains("PAUSED"));
        assert_eq!(status.agents[0].next_result_at, None);
    }
    #[test]
    fn legacy_schedules_do_not_use_continuous_anchors() {
        let (state, mut policy) = fixture();
        policy.grace = 600;
        policy.activation = 500;
        policy.offset = 200;
        let status = Status::new(&state, &[policy]);
        assert_eq!(status.agents[0].next_result_at, Some(4400));
    }
}
