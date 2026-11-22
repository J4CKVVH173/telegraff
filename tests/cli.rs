use std::{
    process::{Command, Stdio},
    time::Duration,
};
use telegraff::{application::ports::Repository, infrastructure::store::SqliteStore};

const BIN: &str = env!("CARGO_BIN_EXE_telegraff");
struct Hub(std::process::Child);
impl Drop for Hub {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn example_configuration_runs_a_hub_and_agent() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("state.sqlite");
    let hub_file = dir.path().join("hub.toml");
    let agent_file = dir.path().join("agent.toml");
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let offset = telegraff::utils::unix_time() % 3600;
    let source = include_str!("../examples/hub.toml");
    let ntfy_start = source.find("[ntfy]").unwrap();
    let hub = source[..ntfy_start]
        .replace(
            "/var/lib/telegraff/state.sqlite",
            database.to_str().unwrap(),
        )
        .replace("hub.example.net", "127.0.0.1")
        .replace(
            "[\"127.0.0.1:9477\", \"[::1]:9477\"]",
            &format!("[\"127.0.0.1:{port}\"]"),
        );
    std::fs::write(&hub_file, hub).unwrap();
    let register = || {
        Command::new(BIN)
            .current_dir(dir.path())
            .args(["register", "node-01", "--config"])
            .arg(&hub_file)
            .args(["--offset", &offset.to_string()])
            .output()
            .unwrap()
    };
    let first = register();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let profile = database
        .with_added_extension("agents.d")
        .join("node-01.profile");
    std::fs::copy(&profile, &agent_file).unwrap();
    assert!(!register().status.success());
    assert_eq!(
        std::fs::read(&profile).unwrap(),
        std::fs::read(&agent_file).unwrap()
    );
    for config in [&hub_file, &agent_file] {
        assert!(
            Command::new(BIN)
                .args(["config", "check", "--config"])
                .arg(config)
                .stdout(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
    let mut hub = Hub(Command::new(BIN)
        .args(["hub", "--config"])
        .arg(&hub_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    let mut ready = false;
    for _ in 0..100 {
        assert!(
            hub.0.try_wait().unwrap().is_none(),
            "Hub exited during startup"
        );
        if let Ok(state) = SqliteStore::read(&database)
            && state.enrolled.contains_key("node-01")
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ready, "Hub did not enroll literal address");
    let result = Command::new(BIN)
        .args(["agent", "--once", "--json", "--config"])
        .arg(&agent_file)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Agent failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["channels"].as_array().unwrap().len(), 2);
    let state = SqliteStore::open(&database).unwrap().load().unwrap();
    assert_eq!(state.transfers.len(), 6);
    assert!(state.dns.contains_key("agent:node-01"));
    let status = Command::new(BIN)
        .args(["status", "--config"])
        .arg(&hub_file)
        .arg("--json")
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["agents"][0]["channels"].as_array().unwrap().len(), 4);
}
#[test]
fn key_generation_refuses_to_overwrite_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("new.key");
    assert!(
        Command::new(BIN)
            .args(["key", "generate", "--output"])
            .arg(&key)
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let before = std::fs::read(&key).unwrap();
    assert!(
        !Command::new(BIN)
            .args(["key", "generate", "--output"])
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(before, std::fs::read(&key).unwrap());
}

#[test]
fn daemon_lifecycle_and_exported_profile() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("hub.toml");
    let export = dir.path().join("agent.toml");
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    std::fs::write(&config, format!("mode = 'hub'\ndatabase = '{}'\ntarget = '127.0.0.1'\npublic_port = {port}\ntcp_listen = ['127.0.0.1:{port}']\nudp_listen = ['127.0.0.1:{port}']\n", dir.path().join("state.sqlite").display())).unwrap();
    let result = Command::new(BIN)
        .args(["register", "test-agent", "--config"])
        .arg(&config)
        .arg("--output")
        .arg(&export)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(
        std::fs::metadata(&export).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let telegraff::infrastructure::config::Config::Agent(agent) =
        telegraff::infrastructure::config::Config::load(&export).unwrap()
    else {
        panic!("expected agent")
    };
    assert_eq!(agent.port, port);
    assert_eq!(agent.agent.grace, agent.agent.interval);
    let output_text = String::from_utf8(result.stdout).unwrap();
    let profile: toml::Value = toml::from_str(&std::fs::read_to_string(&export).unwrap()).unwrap();
    assert!(!output_text.contains(profile["secret"].as_str().unwrap()));
    let start = || {
        Command::new(BIN)
            .args(["hub", "-dv", "--config"])
            .arg(&config)
            .output()
            .unwrap()
    };
    let started = start();
    assert!(started.status.success());
    let start_text = String::from_utf8(started.stdout).unwrap();
    let log_path = start_text
        .lines()
        .find_map(|line| line.strip_prefix("Log: "))
        .unwrap()
        .to_owned();
    let mut stop = Command::new(BIN);
    stop.args(["down", "--config"]).arg(&config);
    // Always stop the child before asserting the duplicate-start outcome.
    let agent_started = Command::new(BIN)
        .args(["agent", "-d", "--config"])
        .arg(&export)
        .output()
        .unwrap();
    let agent_stopped = Command::new(BIN)
        .args(["down", "--config"])
        .arg(&export)
        .output()
        .unwrap();
    let duplicate = start();
    let stopped = stop.output().unwrap();
    assert!(agent_started.status.success());
    assert!(agent_stopped.status.success());
    assert!(!duplicate.status.success());
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(stop.output().unwrap().status.success());
    let log = std::fs::read_to_string(log_path).unwrap();
    assert!(
        log.contains("Configuration:"),
        "verbose flag was not forwarded to the daemon"
    );
    assert!(!log.contains(profile["secret"].as_str().unwrap()));
}

#[test]
fn status_uses_default_config_and_explains_empty_monitoring() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("state.sqlite");
    let mut store = SqliteStore::open(&database).unwrap();
    store
        .save(&telegraff::application::State::default())
        .unwrap();
    std::fs::write(dir.path().join("telegraff.toml"), format!("mode='hub'\ndatabase='{}'\ntarget='127.0.0.1'\ntcp_listen=['127.0.0.1:9477']\nudp_listen=['127.0.0.1:9477']\n", database.display())).unwrap();
    let output = Command::new(BIN)
        .current_dir(dir.path())
        .arg("status")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Agents: 0"));
    assert!(text.contains("Hub: WAIT"));
    assert!(!text.contains("Last observation:"));
    assert!(!text.contains('\x1b'));
    for args in [["status", "--verbose"], ["-v", "status"], ["status", "-v"]] {
        let verbose = Command::new(BIN)
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(verbose.status.success());
        let detail = String::from_utf8(verbose.stdout).unwrap();
        assert!(detail.contains("Last observation: 0"));
        assert!(detail.contains("Notifications waiting to be sent: 0"));
        assert!(!detail.contains('\x1b'));
    }
    let json = Command::new(BIN)
        .current_dir(dir.path())
        .args(["status", "--json", "--verbose"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(value["agents"].as_array().unwrap().is_empty());
}

#[test]
fn down_handles_atomic_binary_upgrade_but_rejects_other_executable_paths() {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("telegraff");
    std::fs::copy(BIN, &binary).unwrap();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let config = dir.path().join("hub.toml");
    std::fs::write(&config,format!("mode='hub'\ndatabase='{}'\ntarget='127.0.0.1'\ntcp_listen=['127.0.0.1:{port}']\nudp_listen=['127.0.0.1:{port}']\n",dir.path().join("state.sqlite").display())).unwrap();
    assert!(
        Command::new(&binary)
            .args(["hub", "-d", "--config"])
            .arg(&config)
            .output()
            .unwrap()
            .status
            .success()
    );
    let other = Command::new(BIN)
        .args(["down", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let replacement = dir.path().join("telegraff.new");
    std::fs::copy(BIN, &replacement).unwrap();
    std::fs::rename(&replacement, &binary).unwrap();
    let stopped = Command::new(&binary)
        .args(["down", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(!other.status.success());
    assert!(String::from_utf8_lossy(&other.stderr).contains("Process executable differs"));
}

#[test]
fn unregister_revokes_live_access_preserves_other_agents_and_rejects_old_key_after_reregistration()
{
    use std::io::{Read, Write};
    use telegraff::{
        application::{Channel, Family, Protocol},
        infrastructure::{
            config::read_key,
            wire::{DATA, Frame},
        },
    };
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("state.sqlite");
    let config = dir.path().join("telegraff.toml");
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    std::fs::write(&config,format!("mode='hub'\ndatabase='{}'\ntarget='127.0.0.1'\ntcp_listen=['127.0.0.1:{port}']\nudp_listen=['127.0.0.1:{port}']\n",database.display())).unwrap();
    for name in ["removed", "keeper"] {
        assert!(
            Command::new(BIN)
                .current_dir(dir.path())
                .args(["register", name])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    let keeper_path = dir.path().join("keeper.toml");
    let keeper_profile = std::fs::read(&keeper_path).unwrap();
    let old_key = read_key(&dir.path().join("removed.toml")).unwrap();
    let keeper_key = read_key(&keeper_path).unwrap();
    let mut hub = Hub(Command::new(BIN)
        .current_dir(dir.path())
        .arg("hub")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    for _ in 0..100 {
        if SqliteStore::read(&database).is_ok_and(|s| s.enrolled.len() == 2) {
            break;
        }
        assert!(hub.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(SqliteStore::read(&database).unwrap().enrolled.len(), 2);
    let exchange = |name: &str, key: &[u8]| {
        let frame = Frame {
            kind: DATA,
            agent: name.into(),
            cycle: 123456,
            channel: Channel {
                family: Family::Ipv4,
                protocol: Protocol::Tcp,
            },
            transfer: 0,
            total: 153600,
            part: 0,
            parts: 1,
            payload: vec![1; 153600],
        };
        let bytes = frame.encode(key);
        let mut stream =
            std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let written = stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&bytes));
        if written.is_err() {
            return false;
        }
        let mut length = [0; 4];
        if stream.read_exact(&mut length).is_err() {
            return false;
        }
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).unwrap();
        frame.matches_receipt(&Frame::decode(&response, key).unwrap())
    };
    assert!(exchange("removed", &old_key));
    for name in ["unknown", "../keeper"] {
        assert!(
            !Command::new(BIN)
                .current_dir(dir.path())
                .args(["unregister", name])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(
        Command::new(BIN)
            .current_dir(dir.path())
            .args(["unregister", "removed"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!exchange("removed", &old_key));
    assert!(exchange("keeper", &keeper_key));
    for _ in 0..100 {
        if !SqliteStore::read(&database)
            .unwrap()
            .enrolled
            .contains_key("removed")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let state = SqliteStore::read(&database).unwrap();
    assert!(!state.enrolled.contains_key("removed"));
    assert!(state.enrolled.contains_key("keeper"));
    assert!(hub.0.try_wait().unwrap().is_none());
    assert_eq!(keeper_profile, std::fs::read(&keeper_path).unwrap());
    assert!(
        Command::new(BIN)
            .current_dir(dir.path())
            .args(["register", "removed", "--output", "fresh.toml"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!exchange("removed", &old_key));
}
