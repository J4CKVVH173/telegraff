use anyhow::{Result, ensure};
use std::{
    fs::OpenOptions,
    io::{self, IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
fn ask(question: &str, default: &str) -> Result<String> {
    print!(
        "{} [{default}]: ",
        crate::utils::paint(
            question,
            36,
            crate::utils::color_enabled(io::stdout().is_terminal())
        )
    );
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
    if role == "agent" && destination.exists() {
        ensure!(
            matches!(
                super::config::Config::load(&destination)?,
                super::config::Config::Agent(_)
            ),
            "Destination exists and is not an agent configuration; choose another file. Nothing was overwritten"
        );
        println!(
            "Already configured.\nStart: telegraff agent --config {} -d",
            destination.display()
        );
        return Ok(());
    }
    ensure!(
        !destination.exists(),
        "Destination already exists; refusing to overwrite"
    );
    if role == "agent" {
        println!(
            "On hub: telegraff register NAME\nCopy NAME.toml here (includes address and key)."
        );
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(".")? {
            let path = entry?.path();
            if path == destination
                || !matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("toml" | "profile")
                )
            {
                continue;
            }
            if let Ok(contents) = std::fs::read_to_string(&path)
                && let Ok(value) = toml::from_str::<toml::Value>(&contents)
                && value.get("mode").and_then(|v| v.as_str()) == Some("profile")
            {
                candidates.push(path);
            }
        }
        let default = if candidates.len() == 1 {
            candidates[0].display().to_string()
        } else {
            String::new()
        };
        let contents = loop {
            let source = PathBuf::from(ask(
                "File copied from hub (NAME.toml or its full path)",
                &default,
            )?);
            match profile_contents(&source) {
                Ok(contents) => break contents,
                Err(error) => crate::utils::message(
                    &format!(
                        "Cannot read {}: {error}. Check the path and retry.",
                        source.display()
                    ),
                    31,
                ),
            }
        };
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
        let native_tls = ask(
            "Enable native TLS (yes/no; yes for nginx TLS passthrough)",
            "no",
        )?;
        ensure!(
            matches!(native_tls.as_str(), "yes" | "no"),
            "Choose yes or no for TLS"
        );
        if native_tls == "yes" {
            let certificate = ask(
                "TLS certificate PEM file (empty: automatic certbot path)",
                "",
            )?;
            let key = ask(
                "TLS private key PEM file (empty: automatic certbot path)",
                "",
            )?;
            let tls = super::config::HubTlsConfig {
                certificate_file: (!certificate.is_empty()).then(|| certificate.clone().into()),
                private_key_file: (!key.is_empty()).then(|| key.clone().into()),
            };
            tls.acceptor(&host)?;
            let mut tls = toml::Table::new();
            if !certificate.is_empty() {
                tls.insert("certificate_file".into(), toml::Value::String(certificate));
            }
            if !key.is_empty() {
                tls.insert("private_key_file".into(), toml::Value::String(key));
            }
            table.insert("tls".into(), toml::Value::Table(tls));
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
    crate::utils::message(&format!("Saved {}", destination.display()), 32);
    println!(
        "Start: telegraff {role} --config {} -d",
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

fn profile_contents(path: &std::path::Path) -> Result<Vec<u8>> {
    use anyhow::Context;
    let contents = std::fs::read(path).context("file missing or unreadable")?;
    let text = std::str::from_utf8(&contents).context("profile must be UTF-8 TOML")?;
    let value: toml::Value =
        toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid profile TOML"))?;
    ensure!(
        value.get("mode").and_then(|v| v.as_str()) == Some("profile"),
        "use the NAME.toml exported by register, not a hub or legacy configuration"
    );
    ensure!(
        matches!(
            super::config::Config::load(path)?,
            super::config::Config::Agent(_)
        ),
        "agent profile required"
    );
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_errors_do_not_echo_secret_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.toml");
        std::fs::write(&path, "secret = 'DO_NOT_ECHO'\ninvalid syntax").unwrap();
        let error = profile_contents(&path).unwrap_err().to_string();
        assert!(!error.contains("DO_NOT_ECHO"));
        assert!(
            profile_contents(&dir.path().join("missing.toml"))
                .unwrap_err()
                .to_string()
                .contains("missing or unreadable")
        );
    }
}
