use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub family: Family,
    pub protocol: Protocol,
}
impl Channel {
    pub fn label(self) -> String {
        format!("{:?}/{:?}", self.family, self.protocol).to_lowercase()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub activation: u64,
    pub interval: u64,
    pub offset: u64,
    pub grace: u64,
    pub paused: bool,
    pub families: Vec<Family>,
    pub payload_bytes: usize,
    pub udp_threshold: u8,
}
impl Policy {
    pub fn cycle_at(&self, now: u64) -> Option<u64> {
        if now < self.offset {
            return None;
        }
        let cycle = (now - self.offset) / self.interval * self.interval + self.offset;
        (cycle >= self.activation).then_some(cycle)
    }
    pub fn first_cycle(&self) -> u64 {
        if self.activation <= self.offset {
            self.offset
        } else {
            (self.activation - self.offset).div_ceil(self.interval) * self.interval + self.offset
        }
    }
    pub fn channels(&self) -> Vec<Channel> {
        self.families
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
            .collect()
    }
    pub fn accepts(&self, cycle: u64, now: u64) -> bool {
        !self.paused
            && cycle >= self.activation
            && cycle >= self.offset
            && (cycle - self.offset).is_multiple_of(self.interval)
            && now >= cycle
            && now < cycle.saturating_add(self.grace)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub agent: String,
    pub cycle: u64,
    pub channel: Channel,
    pub transfer: u8,
    pub bytes: usize,
    pub duration_ms: u64,
    #[serde(default)]
    pub invalid: bool,
    #[serde(default)]
    pub fingerprint: String,
}
impl Transfer {
    pub fn passes(&self, policy: &Policy) -> bool {
        if self.invalid {
            return false;
        }
        match self.channel.protocol {
            Protocol::Tcp => self.bytes == policy.payload_bytes,
            Protocol::Udp => {
                self.bytes * 100 >= policy.payload_bytes * usize::from(policy.udp_threshold)
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelState {
    pub failures: u32,
    pub last_success: Option<u64>,
    pub last_finalized: Option<u64>,
    pub incident: Option<String>,
    pub last_reminder: u64,
    pub paused: bool,
}
impl ChannelState {
    pub fn label(&self) -> &'static str {
        if self.paused {
            "PAUSED"
        } else if self.failures >= 3 {
            "ALERT"
        } else if self.failures > 0 {
            "FAILING"
        } else if self.last_success.is_some() {
            "OK"
        } else {
            "PENDING"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: u64,
    pub agent: String,
    pub created: u64,
    pub text: String,
    pub attempts: u32,
    pub next_attempt: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub channels: BTreeMap<String, BTreeMap<String, ChannelState>>,
    pub enrolled: BTreeMap<String, Vec<Family>>,
    pub enrollment_failures: BTreeMap<String, u32>,
    pub dns: BTreeMap<String, String>,
    pub transfers: Vec<Transfer>,
    pub outbox: Vec<Notification>,
    pub next_notification: u64,
    #[serde(default)]
    pub cycle_anchors: BTreeMap<String, u64>,
    #[serde(default)]
    pub cycle_tokens: BTreeMap<String, BTreeMap<u64, u64>>,
    pub observed_until: u64,
    pub gaps: Vec<(u64, u64)>,
}
impl State {
    pub fn notification_due(&self, now: u64) -> Option<&Notification> {
        self.outbox.first().filter(|n| n.next_attempt <= now)
    }
    pub fn complete_notification(&mut self, id: u64, success: bool, now: u64) -> bool {
        let Some(first) = self.outbox.first_mut().filter(|n| n.id == id) else {
            return false;
        };
        if success {
            self.outbox.remove(0);
        } else {
            first.attempts = first.attempts.saturating_add(1);
            first.next_attempt =
                now + (5u64.saturating_mul(1u64 << first.attempts.min(10))).min(3600);
        }
        true
    }
    pub fn enqueue(&mut self, agent: &str, now: u64, text: String) {
        self.next_notification += 1;
        self.outbox.push(Notification {
            id: self.next_notification,
            agent: agent.into(),
            created: now,
            text,
            attempts: 0,
            next_attempt: now,
        });
    }
}
