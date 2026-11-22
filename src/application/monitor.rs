use super::{Policy, State, Transfer};

pub struct Monitor {
    pub state: State,
    pub policies: Vec<Policy>,
    pub reminder: u64,
    pub retention: u64,
}
impl Monitor {
    pub fn accept(&mut self, result: Transfer, now: u64) -> bool {
        let Some(policy) = self.policies.iter().find(|p| p.name == result.agent) else {
            return false;
        };
        if !policy.accepts(result.cycle, now)
            || result.transfer >= 3
            || result.bytes > policy.payload_bytes
        {
            return false;
        }
        let key = result.channel.label();
        if self
            .state
            .channels
            .get(&result.agent)
            .and_then(|s| s.get(&key))
            .and_then(|s| s.last_finalized)
            .is_some_and(|c| result.cycle <= c)
        {
            return false;
        }
        if let Some(old) = self.state.transfers.iter_mut().find(|t| {
            t.agent == result.agent
                && t.cycle == result.cycle
                && t.channel == result.channel
                && t.transfer == result.transfer
        }) {
            if result.bytes < old.bytes {
                return false;
            }
            if old.invalid {
                return false;
            }
            if result.bytes == old.bytes
                && !old.fingerprint.is_empty()
                && !result.fingerprint.is_empty()
                && old.fingerprint != result.fingerprint
            {
                return false;
            }
            *old = result;
        } else {
            self.state.transfers.push(result);
        }
        true
    }

    pub fn restart(&mut self, now: u64) {
        let previous = self.state.observed_until;
        if previous > 0 && now > previous + 5 {
            self.state.gaps.push((previous, now));
            self.state.enqueue("hub", now, format!("Hub recovered at {now}. Observation gap: {previous}..{now}. Server state during this gap is unknown."));
        }
        for p in &self.policies {
            if p.families.is_empty()
                && let Some(cycle) = p.cycle_at(now.saturating_sub(p.grace))
            {
                self.state
                    .dns
                    .insert(format!("enrollment:{}", p.name), cycle.to_string());
            }
            for channel in p.channels() {
                let s = self
                    .state
                    .channels
                    .entry(p.name.clone())
                    .or_default()
                    .entry(channel.label())
                    .or_default();
                if s.paused && !p.paused {
                    s.last_finalized = p.cycle_at(now);
                    s.failures = 0;
                    s.incident = None;
                }
                s.paused = p.paused;
                // Deadlines that elapsed while the hub was absent are not observations.
                if previous > 0
                    && now > previous + 5
                    && let Some(cycle) = p.cycle_at(now.saturating_sub(p.grace))
                {
                    s.last_finalized = Some(cycle);
                }
            }
        }
        self.state.observed_until = now;
    }

    pub fn tick(&mut self, now: u64) {
        for p in &self.policies {
            if p.paused {
                continue;
            }
            let Some(last_due) = p.cycle_at(now.saturating_sub(p.grace)) else {
                continue;
            };
            let mut messages = Vec::new();
            for channel in p.channels() {
                let label = channel.label();
                let s = self
                    .state
                    .channels
                    .entry(p.name.clone())
                    .or_default()
                    .entry(label.clone())
                    .or_default();
                let mut cycle = s
                    .last_finalized
                    .map_or(p.first_cycle(), |c| c.saturating_add(p.interval));
                // Fast-forward large unobserved histories; only live deadlines count.
                if self.state.observed_until > 0
                    && cycle.saturating_add(p.grace) < self.state.observed_until.saturating_sub(5)
                {
                    cycle = p.cycle_at(self.state.observed_until).unwrap_or(cycle);
                }
                while cycle <= last_due {
                    for transfer in 0..3 {
                        if !self.state.transfers.iter().any(|t| {
                            t.agent == p.name
                                && t.cycle == cycle
                                && t.channel == channel
                                && t.transfer == transfer
                        }) {
                            self.state.transfers.push(Transfer {
                                agent: p.name.clone(),
                                cycle,
                                channel,
                                transfer,
                                bytes: 0,
                                duration_ms: 0,
                                invalid: false,
                                fingerprint: String::new(),
                            });
                        }
                    }
                    let ok = self.state.transfers.iter().any(|t| {
                        t.agent == p.name && t.cycle == cycle && t.channel == channel && t.passes(p)
                    });
                    if ok {
                        s.last_success = Some(cycle);
                        s.failures = 0;
                        if let Some(id) = s.incident.take() {
                            messages
                                .push(format!("{label} recovered; incident={id}; cycle={cycle}"));
                        }
                    } else {
                        s.failures = s.failures.saturating_add(1);
                        if s.failures == 3 {
                            let id = format!("{}-{label}-{cycle}", p.name);
                            messages.push(format!("{label} failed for 3 consecutive cycles; last_success={:?}; incident={id}", s.last_success));
                            s.incident = Some(id);
                            s.last_reminder = now;
                        }
                    }
                    s.last_finalized = Some(cycle);
                    cycle = cycle.saturating_add(p.interval);
                }
                if s.incident.is_some()
                    && self.reminder > 0
                    && now.saturating_sub(s.last_reminder) >= self.reminder
                {
                    messages.push(format!(
                        "{label} still failing; failures={}; incident={}",
                        s.failures,
                        s.incident.as_deref().unwrap_or_default()
                    ));
                    s.last_reminder = now;
                }
            }
            if !messages.is_empty() {
                self.state.enqueue(
                    &p.name,
                    now,
                    format!("{} at {now}: {}", p.name, messages.join("; ")),
                );
            }
        }
        self.state
            .transfers
            .retain(|t| now.saturating_sub(t.cycle) <= self.retention);
        self.state
            .gaps
            .retain(|(_, end)| now.saturating_sub(*end) <= self.retention);
        self.state.observed_until = now;
    }
}
