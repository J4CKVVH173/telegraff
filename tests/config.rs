mod common;
use telegraff::infrastructure::config::{Config, HubConfig};
fn config(key: std::path::PathBuf) -> Config {
    Config::Hub(HubConfig {
        public_port: None,
        public_udp_port: None,
        udp_target: None,
        ingress: Default::default(),
        tls: None,
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

#[test]
fn hub_tls_table_enables_automatic_certbot_paths() {
    let source = include_str!("../examples/hub.toml").replace("# [tls]", "[tls]");
    let Config::Hub(hub) = toml::from_str::<Config>(&source).unwrap() else {
        panic!("hub expected")
    };
    let paths = hub.tls.unwrap().paths(&hub.target).unwrap();
    assert_eq!(
        paths.0,
        std::path::PathBuf::from("/etc/letsencrypt/live/hub.example.net/fullchain.pem")
    );
    assert_eq!(
        paths.1,
        std::path::PathBuf::from("/etc/letsencrypt/live/hub.example.net/privkey.pem")
    );
}

#[test]
fn ingress_and_udp_config_validation() {
    let dir = tempfile::tempdir().unwrap();
    let Config::Hub(base) = config(common::key_file(dir.path())) else {
        unreachable!()
    };
    for case in 0..5 {
        let mut c = base.clone();
        match case {
            0 => c.public_udp_port = Some(0),
            1 => c.udp_target = Some("https://udp.example.net".into()),
            2 => c.ingress.tracked_ips = 0,
            3 => c.ingress.udp_per_second = 0,
            _ => c.ingress.agent_assemblies = 0,
        }
        assert!(Config::Hub(c).validate().is_err());
    }
    let source = include_str!("../examples/hub.toml");
    let Config::Hub(hub) = toml::from_str::<Config>(source).unwrap() else {
        unreachable!()
    };
    assert_eq!(hub.ingress.tcp_per_second, 128);
}
#[test]
fn registration_exports_udp_defaults_and_overrides_and_loads_old_profiles() {
    use telegraff::infrastructure::registration::register_with_udp;
    let dir = tempfile::tempdir().unwrap();
    let Config::Hub(mut hub) = config(common::key_file(dir.path())) else {
        unreachable!()
    };
    hub.database = dir.path().join("hub.sqlite");
    hub.public_port = Some(443);
    hub.public_udp_port = Some(9477);
    hub.udp_target = Some("udp.example.net".into());
    let default = register_with_udp(&hub, "default", None, None, None, 0).unwrap();
    let override_path = register_with_udp(
        &hub,
        "override",
        None,
        Some(10443),
        Some("origin.example.net"),
        0,
    )
    .unwrap();
    for (path, port, host) in [
        (default, 9477, "udp.example.net"),
        (override_path, 10443, "origin.example.net"),
    ] {
        let Config::Agent(agent) = Config::load(&path).unwrap() else {
            unreachable!()
        };
        assert_eq!(agent.port, 443);
        assert_eq!(agent.udp_port, Some(port));
        assert_eq!(agent.udp_hub.as_deref(), Some(host));
    }
    hub.public_udp_port = None;
    hub.udp_target = None;
    let path = register_with_udp(&hub, "legacy", None, None, None, 0).unwrap();
    let Config::Agent(agent) = Config::load(&path).unwrap() else {
        unreachable!()
    };
    assert!(agent.udp_port.is_none() && agent.udp_hub.is_none());
    let original = std::fs::read(&path).unwrap();
    assert!(register_with_udp(&hub, "bad", None, Some(0), None, 0).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
