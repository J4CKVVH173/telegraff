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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    let continuous = policy.grace == policy.interval;
    let cycle = if continuous {
        clock.now()
    } else {
        policy
            .cycle_at(clock.now())
            .ok_or_else(|| anyhow::anyhow!("Agent activation is in the future"))?
    };
    ensure!(
        continuous || policy.accepts(cycle, clock.now()),
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
    let deadline = if continuous {
        started + Duration::from_secs(config.timeout_seconds)
    } else {
        (started + Duration::from_secs(config.timeout_seconds)).min(
            Instant::now()
                + Duration::from_secs(
                    cycle
                        .saturating_add(policy.grace)
                        .saturating_sub(clock.now()),
                ),
        )
    };
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
            let mut last_error = None;
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
                match attempt {
                    Ok(bytes) => {
                        accepted_bytes = bytes;
                        received = true;
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        last_error = Some(error.to_string());
                    }
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
                error: last_error,
                transfer,
                receipt_received: received,
                accepted_bytes,
            });
        }
        report.channels.push(result);
    }
    Ok(report)
}

impl AgentReport {
    pub fn human(&self, color: bool) -> String {
        use crate::utils::paint;
        use std::fmt::Write;
        let mut out = format!(
            "{}: {}",
            self.agent,
            paint(
                if self.successful() { "OK" } else { "FAIL" },
                if self.successful() { 32 } else { 31 },
                color
            )
        );
        for channel in &self.channels {
            let success = channel.accepted == Some(true) && channel.receipt_received;
            let label = if success { "OK" } else { "FAIL" };
            write!(
                out,
                " | {}: {}",
                channel.channel,
                paint(label, if success { 32 } else { 31 }, color)
            )
            .unwrap();
            if !channel.expected {
                out.push_str(" (optional)");
            }
            if !success {
                let error = channel
                    .transfers
                    .iter()
                    .rev()
                    .find_map(|attempt| attempt.error.as_deref());
                let reason = match error.map(str::to_ascii_lowercase) {
                    Some(e) if e.contains("certificate") || e.contains("tls") => "TLS error",
                    Some(e)
                        if e.contains("timed out")
                            || e.contains("timeout")
                            || e.contains("deadline") =>
                    {
                        "timeout"
                    }
                    Some(e) if e.contains("connect") => "connection failed",
                    _ => "no receipt",
                };
                write!(out, " ({reason})").unwrap();
            }
        }
        if self.channels.is_empty() {
            out.push_str(" | no target channels");
        }
        out.push('\n');
        out
    }
    pub fn verbose_with_color(&self, color: bool) -> String {
        use crate::utils::paint;
        use std::fmt::Write;
        let mut out = String::new();
        let (summary, code) = if self.successful() {
            ("PASS: all expected channels confirmed delivery", 32)
        } else {
            (
                "FAIL: delivery was not confirmed for every expected channel",
                31,
            )
        };
        writeln!(out, "{}: {}", self.agent, paint(summary, code, color)).unwrap();
        for channel in &self.channels {
            let success = channel.accepted == Some(true) && channel.receipt_received;
            let label = if success {
                "PASS"
            } else {
                "FAIL: no successful receipt"
            };
            let transfers = channel
                .transfers
                .iter()
                .filter(|attempt| attempt.receipt_received)
                .count();
            writeln!(
                out,
                "  {}: {}{}; receipts {}/{}; max accepted {} bytes",
                channel.channel,
                paint(label, if success { 32 } else { 31 }, color),
                if channel.expected {
                    ""
                } else {
                    " (additional channel; not required)"
                },
                transfers,
                channel.transfers.len(),
                channel.accepted_bytes
            )
            .unwrap();
            if !success
                && let Some(error) = channel
                    .transfers
                    .iter()
                    .rev()
                    .find_map(|attempt| attempt.error.as_deref())
            {
                writeln!(out, "    {}", paint(error, 31, color)).unwrap();
            }
        }
        if self.channels.is_empty() {
            writeln!(
                out,
                "No target channels available; check hub DNS and configured address families."
            )
            .unwrap();
        }
        writeln!(out, "Cycle: {}\nDNS: {}", self.cycle, self.dns).unwrap();
        for channel in &self.channels {
            for attempt in &channel.transfers {
                writeln!(
                    out,
                    "  {} attempt {}: receipt={} bytes={}{}",
                    channel.channel,
                    attempt.transfer + 1,
                    attempt.receipt_received,
                    attempt.accepted_bytes,
                    attempt
                        .error
                        .as_deref()
                        .map(|error| format!(" error={error}"))
                        .unwrap_or_default()
                )
                .unwrap();
            }
        }
        out
    }
}

#[cfg(test)]
mod human_tests {
    use super::*;
    #[test]
    fn summary_distinguishes_optional_failures_and_keeps_plain_labels() {
        let report = AgentReport {
            agent: "node-test".into(),
            cycle: 1,
            dns: String::new(),
            channels: vec![
                ChannelReport {
                    channel: "ipv4/tcp".into(),
                    expected: true,
                    accepted: Some(true),
                    receipt_received: true,
                    accepted_bytes: 153600,
                    transfers: vec![],
                },
                ChannelReport {
                    channel: "ipv6/tcp".into(),
                    expected: false,
                    accepted: None,
                    receipt_received: false,
                    accepted_bytes: 0,
                    transfers: vec![],
                },
            ],
        };
        let plain = report.verbose_with_color(false);
        assert!(plain.contains("PASS: all expected channels"));
        assert!(plain.contains("additional channel; not required"));
        assert!(plain.contains("FAIL: no successful receipt"));
        assert!(!plain.contains('\x1b'));
        let colored = report.verbose_with_color(true);
        assert!(colored.contains("\x1b[32mPASS"));
        assert!(colored.contains("\x1b[31mFAIL"));
    }
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    #[test]
    fn compact_probe_keeps_reason_and_verbose_keeps_every_attempt() {
        let report = AgentReport {
            agent: "test-node".into(),
            cycle: 123,
            dns: "dns-diagnostic".into(),
            channels: vec![ChannelReport {
                channel: "ipv4/udp".into(),
                expected: true,
                accepted: None,
                receipt_received: false,
                accepted_bytes: 0,
                transfers: vec![
                    Attempt {
                        error: Some("Transfer timed out".into()),
                        transfer: 0,
                        receipt_received: false,
                        accepted_bytes: 0,
                    },
                    Attempt {
                        error: Some("deadline has elapsed".into()),
                        transfer: 1,
                        receipt_received: false,
                        accepted_bytes: 0,
                    },
                ],
            }],
        };
        assert_eq!(
            report.human(false),
            "test-node: FAIL | ipv4/udp: FAIL (timeout)\n"
        );
        let verbose = report.verbose_with_color(false);
        assert!(verbose.contains("Cycle: 123"));
        assert!(verbose.contains("dns-diagnostic"));
        assert!(verbose.contains("attempt 1:"));
        assert!(verbose.contains("attempt 2:"));
        assert!(verbose.contains("Transfer timed out"));
        assert!(!verbose.contains('\x1b'));
    }
}
