use anyhow::{Result, ensure};
use std::{
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
fn ask(question: &str, default: &str) -> Result<String> {
    print!("{question} [{default}]: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    ensure!(io::stdin().read_line(&mut answer)? > 0, "Setup input ended");
    let answer = answer.trim();
    Ok(if answer.is_empty() {
        default.to_owned()
    } else {
        answer.to_owned()
    })
}
pub fn run() -> Result<()> {
    ensure!(
        io::stdin().is_terminal(),
        "Interactive setup needs a terminal; use hub/agent --config PATH"
    );
    let role = ask("Role (hub/agent)", "hub")?;
    let destination = PathBuf::from(ask("Configuration file", "telegraff.toml")?);
    ensure!(
        !destination.exists(),
        "Destination already exists; refusing to overwrite"
    );
    if role == "agent" {
        let source = PathBuf::from(ask(
            "Profile file produced by telegraff register on the hub",
            "agent.profile",
        )?);
        ensure!(
            matches!(
                super::config::Config::load(&source)?,
                super::config::Config::Agent(_)
            ),
            "Agent profile required"
        );
        // Profiles contain their own key; legacy configs reference a separate file.
        let contents = std::fs::read(&source)?;
        let value: toml::Value = toml::from_str(std::str::from_utf8(&contents)?)?;
        ensure!(
            value.get("mode").and_then(|v| v.as_str()) == Some("profile"),
            "Setup requires the self-contained profile from register"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination)?;
        file.write_all(&contents)?;
        file.sync_all()?;
    } else {
        ensure!(role == "hub", "Choose hub or agent");
        let host = ask("Public hub DNS name (without scheme)", "hub.example.net")?;
        let listen: u16 = ask("Local TCP/UDP listen port", "9477")?.parse()?;
        let public: u16 = ask(
            "Public TCP/UDP port (after forwarding)",
            &listen.to_string(),
        )?
        .parse()?;
        ensure!(listen > 0 && public > 0, "Ports must be nonzero");
        let database = ask("SQLite database path", "state.sqlite")?;
        let mut table = toml::Table::new();
        for (k, v) in [
            ("mode", "hub"),
            ("target", host.as_str()),
            ("database", database.as_str()),
        ] {
            table.insert(k.into(), toml::Value::String(v.into()));
        }
        table.insert("public_port".into(), toml::Value::Integer(public.into()));
        for k in ["tcp_listen", "udp_listen"] {
            table.insert(
                k.into(),
                toml::Value::Array(vec![
                    toml::Value::String(format!("127.0.0.1:{listen}")),
                    toml::Value::String(format!("[::1]:{listen}")),
                ]),
            );
        }
        let endpoint = ask("ntfy HTTPS endpoint (empty to disable notifications)", "")?;
        if !endpoint.is_empty() {
            let mut ntfy = toml::Table::new();
            ntfy.insert("endpoint".into(), toml::Value::String(endpoint));
            let token = ask("ntfy token file (empty if none)", "")?;
            if !token.is_empty() {
                ntfy.insert("token_file".into(), toml::Value::String(token));
            }
            table.insert("ntfy".into(), toml::Value::Table(ntfy));
        }
        let contents = toml::to_string(&table)?;
        let parsed: super::config::Config = toml::from_str(&contents)
            .map_err(|_| anyhow::anyhow!("Invalid setup configuration"))?;
        parsed.validate()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    println!(
        "Saved {}. Start: telegraff {role} --config {} -d",
        destination.display(),
        destination.display()
    );
    if role == "hub" {
        println!(
            "Next: telegraff register NAME --config {}",
            destination.display()
        );
    }
    Ok(())
}
