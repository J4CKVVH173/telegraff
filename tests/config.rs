mod common;
use telegraff::infrastructure::config::{Config, HubConfig};
fn config(key: std::path::PathBuf) -> Config {
    Config::Hub(HubConfig {
        public_port: None,
        database: "state.sqlite".into(),
        target: "127.0.0.1".into(),
        tcp_listen: vec!["127.0.0.1:9477".parse().unwrap()],
        udp_listen: vec!["127.0.0.1:9477".parse().unwrap()],
        retention_days: 30,
        reminder_seconds: 21600,
        max_connections: 64,
        max_assemblies: 256,
        ntfy: None,
        agents: vec![common::entry(key)],
    })
}
#[test]
fn rejects_invalid_registry_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let base = config(common::key_file(dir.path()));
    assert!(base.validate().is_ok());
    for case in 0..5 {
        let Config::Hub(mut c) = base.clone() else {
            unreachable!()
        };
        match case {
            0 => c.agents.push(c.agents[0].clone()),
            1 => c.agents[0].offset = 3600,
            2 => c.agents[0].payload_bytes = 999999,
            3 => c.max_connections = 0,
            _ => c.agents[0].auto = true,
        }
        assert!(Config::Hub(c).validate().is_err());
    }
}
#[test]
fn secrets_require_restricted_permissions_and_parse_errors_do_not_echo_input() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let key = common::key_file(dir.path());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(config(key).validate().is_err());
    let file = dir.path().join("bad.toml");
    std::fs::write(&file, "private_value = 'test-marker'\ninvalid syntax").unwrap();
    let error = Config::load(&file).unwrap_err().to_string();
    assert!(!error.contains("test-marker"));
}
