mod common;
use telegraff::application::{Family, ports::Resolution};

fn readable(text: &str) {
    assert!(text.starts_with("📡 "), "{text}");
    assert!(text.contains(" UTC\n\n"), "{text}");
    for internal in [
        "Some(",
        "None",
        "incident=",
        "cycle=",
        "last_success=",
        " at ",
    ] {
        assert!(!text.contains(internal), "{text}");
    }
}
#[test]
fn failure_reminder_recovery_and_hub_gap_use_one_format() {
    let mut m = common::monitor();
    for cycle in [0, 3600, 7200] {
        m.tick(cycle + 600);
    }
    let failure = &m.state.outbox[0].text;
    readable(failure);
    assert!(failure.contains("🔴 UDP · IPv4: нет успешной передачи 3 проверки подряд."));
    assert!(failure.contains("Последний успех: ещё не было."));
    m.reminder = 3600;
    m.tick(11400);
    readable(&m.state.outbox[1].text);
    assert!(m.state.outbox[1].text.contains("🟠 UDP · IPv4"));
    for channel in m.policies[0].channels() {
        assert!(m.accept(
            common::transfer(14400, channel.family, channel.protocol, 153600),
            14410
        ));
    }
    m.tick(15000);
    let recovery = &m.state.outbox.last().unwrap().text;
    readable(recovery);
    assert!(recovery.contains("🟢 UDP · IPv4: передача восстановлена."));
    m.restart(20000);
    let gap = &m.state.outbox.last().unwrap().text;
    readable(gap);
    assert!(gap.contains("Состояние серверов за это время неизвестно."));
    assert!(!gap.contains("15000"));
    assert!(!gap.contains("20000"));
}
#[test]
fn dns_setup_failure_and_recovery_are_readable() {
    let mut m = common::monitor();
    m.policies[0].families.clear();
    let automatic = vec!["node-01".into()];
    for now in [600, 4200, 7800] {
        m.observe_dns(None, &automatic, now);
    }
    assert_eq!(m.state.outbox.len(), 1);
    readable(&m.state.outbox[0].text);
    assert!(m.state.outbox[0].text.contains("🔴 DNS:"));
    m.observe_dns(
        Some(&Resolution {
            addresses: vec!["127.0.0.1".parse().unwrap()],
            ipv4_error: false,
            ipv6_error: false,
        }),
        &automatic,
        8000,
    );
    assert_eq!(m.policies[0].families, vec![Family::Ipv4]);
    readable(&m.state.outbox[1].text);
    assert!(m.state.outbox[1].text.contains("🟢 DNS:"));
}
