mod common;
use common::*;
use telegraff::application::{Family::*, Protocol::*};

#[test]
fn third_miss_opens_one_incident_and_success_recovers() {
    let mut m = monitor();
    for (cycle, notifications) in [(0, 0), (3600, 0), (7200, 1), (10800, 1)] {
        m.tick(cycle + 600);
        assert_eq!(m.state.outbox.len(), notifications);
    }
    for channel in m.policies[0].channels() {
        assert!(m.accept(
            transfer(14400, channel.family, channel.protocol, 153600),
            14410
        ));
    }
    m.tick(15000);
    assert_eq!(m.state.outbox.len(), 2);
    assert!(
        m.state.channels["node-01"]
            .values()
            .all(|s| s.failures == 0 && s.incident.is_none())
    );
}
#[test]
fn working_ipv4_does_not_hide_failed_ipv6_or_udp() {
    let mut m = monitor();
    for cycle in [0, 3600, 7200] {
        assert!(m.accept(transfer(cycle, Ipv4, Tcp, 153600), cycle + 10));
        m.tick(cycle + 600);
    }
    let s = &m.state.channels["node-01"];
    assert_eq!(s["ipv4/tcp"].label(), "OK");
    for name in ["ipv4/udp", "ipv6/tcp", "ipv6/udp"] {
        assert_eq!(s[name].label(), "ALERT");
    }
    assert_eq!(m.state.outbox.len(), 1);
}
#[test]
fn udp_threshold_and_late_cycles_are_exact() {
    let mut m = monitor();
    assert!(m.accept(transfer(0, Ipv4, Udp, 152064), 10));
    assert!(m.accept(transfer(0, Ipv6, Udp, 152063), 10));
    m.tick(600);
    assert_eq!(m.state.channels["node-01"]["ipv4/udp"].failures, 0);
    assert_eq!(m.state.channels["node-01"]["ipv6/udp"].failures, 1);
    assert!(!m.accept(transfer(0, Ipv6, Udp, 153600), 601));
    assert!(!m.accept(transfer(3601, Ipv4, Tcp, 153600), 3610));
}
#[test]
fn successful_cycle_resets_counter_and_duplicates_do_not_add_cycles() {
    let mut m = monitor();
    m.tick(600);
    m.tick(4200);
    for _ in 0..2 {
        assert!(m.accept(transfer(7200, Ipv4, Tcp, 153600), 7210));
    }
    m.tick(7800);
    assert_eq!(m.state.channels["node-01"]["ipv4/tcp"].failures, 0);
    assert_eq!(
        m.state
            .transfers
            .iter()
            .filter(|t| t.cycle == 7200
                && t.channel.family == Ipv4
                && t.channel.protocol == Tcp
                && t.bytes > 0)
            .count(),
        1
    );
    m.tick(11400);
    assert_eq!(m.state.channels["node-01"]["ipv4/tcp"].failures, 1);
}
#[test]
fn restart_records_gap_without_counting_unobserved_deadlines() {
    let mut m = monitor();
    m.tick(600);
    let before = m.state.channels["node-01"]["ipv4/tcp"].failures;
    m.restart(15000);
    m.tick(15000);
    assert_eq!(m.state.gaps, vec![(600, 15000)]);
    assert_eq!(m.state.channels["node-01"]["ipv4/tcp"].failures, before);
    m.tick(18600);
    assert_eq!(m.state.channels["node-01"]["ipv4/tcp"].failures, before + 1);
}
#[test]
fn maintenance_resume_does_not_count_backlog() {
    let mut m = monitor();
    m.policies[0].paused = true;
    m.restart(0);
    m.tick(15000);
    assert!(m.state.outbox.is_empty());
    m.policies[0].paused = false;
    m.restart(15001);
    m.tick(15001);
    assert_eq!(m.state.channels["node-01"]["ipv4/tcp"].failures, 0);
}

#[test]
fn contradictory_duplicates_cannot_replace_accepted_data() {
    let mut m = monitor();
    let mut first = transfer(0, Ipv4, Tcp, 153600);
    first.fingerprint = "first".into();
    assert!(m.accept(first, 10));
    let mut duplicate = transfer(0, Ipv4, Tcp, 153600);
    duplicate.fingerprint = "different".into();
    assert!(!m.accept(duplicate, 11));
    assert_eq!(m.state.transfers[0].fingerprint, "first");
}
#[test]
fn status_reports_partial_failure_and_unenrolled_channels() {
    let mut m = monitor();
    m.policies[0].families = vec![Ipv4];
    assert!(m.accept(transfer(0, Ipv4, Tcp, 153600), 10));
    assert!(m.accept(transfer(0, Ipv6, Tcp, 153600), 10));
    m.tick(600);
    let status = telegraff::application::status::Status::new(&m.state, &m.policies);
    assert_eq!(status.agents[0].overall, "DEGRADED");
    let channel = &status.agents[0].channels[2];
    assert!(!channel.expected);
    assert_eq!(channel.state, "UNENROLLED");
}

#[test]
fn continuous_cycles_use_hub_time_and_reject_replays_after_restart() {
    use telegraff::application::ports::Repository;
    use telegraff::infrastructure::store::SqliteStore;
    let mut m = monitor();
    m.policies[0].activation = 123;
    m.policies[0].offset = 123;
    m.policies[0].grace = 3600;
    m.state.cycle_anchors.insert("node-01".into(), 123);
    // Token intentionally bears no relation to hub time.
    assert!(m.accept(transfer(9_000_000, Ipv4, Tcp, 153600), 200));
    assert_eq!(m.state.transfers[0].cycle, 123);
    let mut fresh = transfer(9_000_001, Ipv4, Tcp, 153600);
    fresh.fingerprint = "fresh-run".into();
    m.state.transfers[0].fingerprint = "first-run".into();
    assert!(m.accept(fresh, 300));
    m.tick(3723);
    assert_eq!(m.state.channels["node-01"]["ipv4/tcp"].failures, 0);
    let dir = tempfile::tempdir().unwrap();
    let mut store = SqliteStore::open(&dir.path().join("state.sqlite")).unwrap();
    store.save(&m.state).unwrap();
    m.state = store.load().unwrap();
    assert_eq!(m.state.cycle_anchors["node-01"], 123);
    assert!(!m.accept(transfer(9_000_000, Ipv4, Tcp, 153600), 3800));
    assert!(m.accept(transfer(7, Ipv4, Tcp, 153600), 3800));
    assert_eq!(m.state.transfers.last().unwrap().cycle, 3723);
}

#[test]
fn forgetting_an_agent_cancels_its_alerts_and_preserves_history_and_other_agents() {
    let mut m = monitor();
    m.state.enrolled.insert("node-01".into(), vec![Ipv4]);
    m.state.enrolled.insert("keeper".into(), vec![Ipv4]);
    m.state
        .enqueue("node-01", 100, "removed agent alert".into());
    m.state.enqueue("keeper", 100, "keep this alert".into());
    m.state.transfers.push(transfer(0, Ipv4, Tcp, 153600));
    m.forget("node-01");
    assert!(m.policies.is_empty());
    assert!(!m.state.enrolled.contains_key("node-01"));
    assert!(m.state.enrolled.contains_key("keeper"));
    assert_eq!(m.state.outbox.len(), 1);
    assert_eq!(m.state.outbox[0].agent, "keeper");
    assert_eq!(m.state.transfers.len(), 1);
}

#[test]
fn bounded_replay_tokens_reject_retired_messages_after_restart() {
    use telegraff::application::ports::Repository;
    use telegraff::infrastructure::store::SqliteStore;
    let mut m = monitor();
    m.policies[0].grace = 3600;
    for token in 1..=1024 {
        assert!(m.accept(transfer(token, Ipv4, Tcp, 153600), 100));
    }
    assert!(!m.accept(transfer(1025, Ipv4, Tcp, 153600), 100));
    assert_eq!(m.state.cycle_tokens["node-01"].len(), 1024);
    m.tick(7200);
    assert!(m.state.cycle_tokens["node-01"].is_empty());
    assert!(m.accept(transfer(1025, Ipv4, Tcp, 153600), 7200));
    let dir = tempfile::tempdir().unwrap();
    let mut store = SqliteStore::open(&dir.path().join("replay.sqlite")).unwrap();
    store.save(&m.state).unwrap();
    m.state = store.load().unwrap();
    assert_eq!(m.state.retired_tokens["node-01"], 1024);
    assert!(!m.accept(transfer(1, Ipv4, Tcp, 153600), 7300));
    assert!(m.accept(transfer(1026, Ipv4, Tcp, 153600), 7300));
}
