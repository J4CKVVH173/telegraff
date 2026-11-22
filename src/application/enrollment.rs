use super::{Monitor, ports::Resolution};

impl Monitor {
    pub fn observe_agent_dns(&mut self, name: &str, observation: super::ports::DnsObservation) {
        self.state
            .dns
            .insert(format!("agent:{name}"), observation.summary());
        self.compare_dns(name);
    }
    fn compare_dns(&mut self, name: &str) {
        let key = format!("view:{name}");
        if let (Some(hub), Some(agent)) = (
            self.state.dns.get("hub"),
            self.state.dns.get(&format!("agent:{name}")),
        ) {
            if hub != agent {
                self.state
                    .dns
                    .insert(key, "Agent and hub DNS observations differ".into());
            } else {
                self.state.dns.remove(&key);
            }
        }
    }

    pub fn observe_dns(&mut self, resolution: Option<&Resolution>, automatic: &[String], now: u64) {
        let families = resolution.map(|r| r.families()).unwrap_or_default();
        let complete = resolution.is_some_and(|r| !r.ipv4_error && !r.ipv6_error);
        self.state.dns.insert(
            "hub".into(),
            resolution
                .map(|r| r.summary())
                .unwrap_or_else(|| "DNS timeout or resolver failure".into()),
        );
        for policy in &mut self.policies {
            if policy.paused {
                continue;
            }
            if automatic.contains(&policy.name)
                && policy.families.is_empty()
                && complete
                && !families.is_empty()
            {
                policy.families = families.clone();
                self.state
                    .enrolled
                    .insert(policy.name.clone(), families.clone());
                if self
                    .state
                    .enrollment_failures
                    .remove(&policy.name)
                    .is_some_and(|n| n >= 3)
                {
                    self.state.enqueue(
                        &policy.name,
                        now,
                        format!("{}: DNS enrollment recovered at {now}", policy.name),
                    );
                }
            }
            if !policy.families.is_empty() && (!complete || policy.families != families) {
                self.state.dns.insert(policy.name.clone(),"DNS families differ from expected families or lookup failed; operator review required".into());
            } else {
                self.state.dns.remove(&policy.name);
            }
            if automatic.contains(&policy.name) && policy.families.is_empty() {
                let Some(cycle) = policy.cycle_at(now.saturating_sub(policy.grace)) else {
                    continue;
                };
                let marker = format!("enrollment:{}", policy.name);
                if self.state.dns.get(&marker) != Some(&cycle.to_string()) {
                    self.state.dns.insert(marker, cycle.to_string());
                    let count = self
                        .state
                        .enrollment_failures
                        .entry(policy.name.clone())
                        .or_default();
                    *count = count.saturating_add(1);
                    if *count == 3 {
                        self.state.enqueue(
                            &policy.name,
                            now,
                            format!(
                                "{}: DNS enrollment failed for 3 consecutive cycles at {now}",
                                policy.name
                            ),
                        );
                    }
                }
            }
        }
        for name in self
            .policies
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()
        {
            self.compare_dns(&name);
        }
    }
}
