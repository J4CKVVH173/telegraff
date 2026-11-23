mod common;
use anyhow::Result;
use async_trait::async_trait;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use telegraff::application::{
    Family, Protocol,
    agent::{self, AgentSettings},
    ports::{Clock, Resolution, Resolver, TransferRequest, Transport},
};

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        3610
    }
}
struct Answers(Resolution);
#[async_trait]
impl Resolver for Answers {
    async fn resolve(&self, _: &str) -> Result<Resolution> {
        Ok(self.0.clone())
    }
}
#[derive(Default)]
struct Sender {
    calls: Vec<(SocketAddr, Protocol)>,
    fail: Option<Family>,
    missing_receipts: bool,
}
#[async_trait]
impl Transport for Sender {
    async fn send(
        &mut self,
        address: SocketAddr,
        request: TransferRequest,
        _: Duration,
    ) -> Result<usize> {
        self.calls.push((address, request.channel.protocol));
        if self.missing_receipts
            || Some(request.channel.family) == self.fail
            || address.ip() == "127.0.0.2".parse::<IpAddr>().unwrap()
        {
            anyhow::bail!("No receipt");
        }
        Ok(request.total)
    }
}
fn settings() -> AgentSettings {
    AgentSettings {
        policy: common::policy(),
        hub: "hub.example.net".into(),
        port: 9477,
        udp_port: None,
        udp_hub: None,
        timeout_seconds: 120,
        auto: false,
    }
}
fn answers(ips: &[&str]) -> Answers {
    Answers(Resolution {
        addresses: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
        ipv4_error: false,
        ipv6_error: false,
    })
}

#[tokio::test]
async fn both_families_are_attempted_when_one_fails() {
    for failed in [Family::Ipv4, Family::Ipv6] {
        let mut sender = Sender {
            fail: Some(failed),
            ..Sender::default()
        };
        let report = agent::run(
            &settings(),
            &answers(&["127.0.0.1", "::1"]),
            &mut sender,
            &FixedClock,
        )
        .await
        .unwrap();
        assert!(!report.successful());
        assert_eq!(sender.calls.len(), 12);
        assert_eq!(
            report
                .channels
                .iter()
                .filter(|c| c.accepted == Some(true))
                .count(),
            2
        );
    }
}
#[tokio::test]
async fn missing_record_does_not_remove_an_expected_family() {
    let mut sender = Sender::default();
    let report = agent::run(
        &settings(),
        &answers(&["127.0.0.1"]),
        &mut sender,
        &FixedClock,
    )
    .await
    .unwrap();
    assert_eq!(report.channels.len(), 4);
    assert!(!report.successful());
    assert!(
        report
            .channels
            .iter()
            .filter(|c| c.channel.starts_with("ipv6"))
            .all(|c| c.expected && c.accepted.is_none())
    );
}
#[tokio::test]
async fn alternate_addresses_are_tried_and_extra_family_is_tested() {
    let mut config = settings();
    config.policy.families = vec![Family::Ipv4];
    let mut sender = Sender::default();
    let report = agent::run(
        &config,
        &answers(&["127.0.0.2", "127.0.0.1", "::1"]),
        &mut sender,
        &FixedClock,
    )
    .await
    .unwrap();
    assert!(report.successful());
    assert_eq!(sender.calls.len(), 18);
    assert!(
        report
            .channels
            .iter()
            .filter(|c| c.channel.starts_with("ipv6"))
            .all(|c| !c.expected && c.accepted == Some(true))
    );
}
#[tokio::test]
async fn missing_receipts_do_not_claim_hub_rejection() {
    let mut sender = Sender {
        missing_receipts: true,
        ..Sender::default()
    };
    let report = agent::run(
        &settings(),
        &answers(&["127.0.0.1", "::1"]),
        &mut sender,
        &FixedClock,
    )
    .await
    .unwrap();
    assert!(
        report
            .channels
            .iter()
            .all(|c| c.accepted.is_none() && !c.receipt_received)
    );
}
#[test]
fn auto_enrollment_freezes_families_and_requires_complete_dns() {
    let mut m = common::monitor();
    m.policies[0].families.clear();
    let auto = vec!["node-01".into()];
    let mut partial = answers(&["127.0.0.1"]).0;
    partial.ipv6_error = true;
    m.observe_dns(Some(&partial), &auto, 10);
    assert!(m.policies[0].families.is_empty());
    m.observe_dns(Some(&answers(&["127.0.0.1", "::1"]).0), &auto, 20);
    assert_eq!(m.policies[0].families, vec![Family::Ipv4, Family::Ipv6]);
    m.observe_dns(Some(&answers(&["127.0.0.1"]).0), &auto, 30);
    assert_eq!(m.policies[0].families.len(), 2);
    assert!(m.state.dns.contains_key("node-01"));
}
#[test]
fn enrollment_failure_alerts_only_after_three_due_cycles() {
    let mut m = common::monitor();
    m.policies[0].families.clear();
    let auto = vec!["node-01".into()];
    for (now, count) in [(600, 0), (601, 0), (4200, 0), (7800, 1)] {
        m.observe_dns(None, &auto, now);
        assert_eq!(m.state.outbox.len(), count);
    }
    m.observe_dns(Some(&answers(&["::1"]).0), &auto, 7900);
    assert_eq!(m.state.outbox.len(), 2);
}

#[tokio::test]
async fn single_stack_targets_do_not_require_an_absent_family() {
    for (ip, family) in [("127.0.0.1", Family::Ipv4), ("::1", Family::Ipv6)] {
        let mut config = settings();
        config.policy.families = vec![family];
        let mut sender = Sender::default();
        let report = agent::run(&config, &answers(&[ip]), &mut sender, &FixedClock)
            .await
            .unwrap();
        assert!(report.successful());
        assert_eq!(sender.calls.len(), 6);
    }
}

#[test]
fn dns_view_difference_is_detected_even_with_equal_record_counts() {
    let mut m = common::monitor();
    m.observe_dns(Some(&answers(&["127.0.0.1"]).0), &[], 10);
    m.observe_agent_dns("node-01", answers(&["127.0.0.2"]).0.observation());
    assert!(m.state.dns.contains_key("view:node-01"));
    m.observe_agent_dns("node-01", answers(&["127.0.0.1"]).0.observation());
    assert!(!m.state.dns.contains_key("view:node-01"));
}

struct SplitAnswers {
    udp_fails: bool,
}
#[async_trait]
impl Resolver for SplitAnswers {
    async fn resolve(&self, host: &str) -> Result<Resolution> {
        if host == "udp.example.net" {
            if self.udp_fails {
                anyhow::bail!("UDP DNS unavailable");
            }
            Ok(answers(&["192.0.2.2"]).0)
        } else {
            Ok(answers(&["192.0.2.1"]).0)
        }
    }
}
#[tokio::test]
async fn independent_udp_host_port_and_dns_failure() {
    let mut config = settings();
    config.policy.families = vec![Family::Ipv4];
    config.port = 443;
    config.udp_port = Some(9477);
    config.udp_hub = Some("udp.example.net".into());
    for udp_fails in [false, true] {
        let mut sender = Sender::default();
        let report = agent::run(
            &config,
            &SplitAnswers { udp_fails },
            &mut sender,
            &FixedClock,
        )
        .await
        .unwrap();
        assert_eq!(report.successful(), !udp_fails);
        assert!(
            sender
                .calls
                .iter()
                .filter(|(_, p)| *p == Protocol::Tcp)
                .all(|(a, _)| *a == "192.0.2.1:443".parse().unwrap())
        );
        let udp: Vec<_> = sender
            .calls
            .iter()
            .filter(|(_, p)| *p == Protocol::Udp)
            .collect();
        assert_eq!(udp.len(), if udp_fails { 0 } else { 3 });
        assert!(
            udp.iter()
                .all(|(a, _)| *a == "192.0.2.2:9477".parse().unwrap())
        );
    }
}
