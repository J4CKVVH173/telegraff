#![allow(dead_code)]
use telegraff::application::{Channel, Family, Monitor, Policy, Protocol, State, Transfer};

pub fn policy() -> Policy {
    Policy {
        name: "node-01".into(),
        activation: 0,
        interval: 3600,
        offset: 0,
        grace: 600,
        paused: false,
        families: vec![Family::Ipv4, Family::Ipv6],
        payload_bytes: 153600,
        udp_threshold: 99,
    }
}
pub fn monitor() -> Monitor {
    Monitor {
        state: State::default(),
        policies: vec![policy()],
        reminder: 21600,
        retention: 86400,
    }
}
pub fn transfer(cycle: u64, family: Family, protocol: Protocol, bytes: usize) -> Transfer {
    Transfer {
        agent: "node-01".into(),
        cycle,
        channel: Channel { family, protocol },
        transfer: 0,
        bytes,
        duration_ms: 10,
        invalid: false,
        fingerprint: String::new(),
    }
}
pub fn key_file(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("agent.key");
    std::fs::write(&path, hex::encode([7; 32])).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}
pub fn entry(key_file: std::path::PathBuf) -> telegraff::infrastructure::config::AgentEntry {
    let p = policy();
    telegraff::infrastructure::config::AgentEntry {
        name: p.name,
        key_file,
        activation: 0,
        interval: p.interval,
        offset: p.offset,
        grace: p.grace,
        paused: false,
        families: p.families,
        auto: false,
        payload_bytes: p.payload_bytes,
        udp_threshold: p.udp_threshold,
    }
}
