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
            "[\"0.0.0.0:9477\", \"[::]:9477\"]",
            &format!("[\"127.0.0.1:{port}\"]"),
        );
    std::fs::write(&hub_file, hub).unwrap();
    let register = || {
        Command::new(BIN)
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
        .args(["agent", "--config"])
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
