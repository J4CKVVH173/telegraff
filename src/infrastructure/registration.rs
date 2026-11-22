use super::config::{AgentConfig, AgentEntry, HubConfig, check_permissions, validate_name};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{ErrorKind, Write},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Profile,
}

fn continuous_default() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    mode: Mode,
    name: String,
    hub: String,
    port: u16,
    offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_file: Option<PathBuf>,
    #[serde(default = "continuous_default")]
    continuous: bool,
    pub(super) secret: String,
}

impl Profile {
    pub(super) fn agent(&self, path: &Path) -> AgentConfig {
        let mut config = AgentConfig::registered(
            self.name.clone(),
            path.to_owned(),
            self.hub.clone(),
            self.port,
            self.offset,
        );
        config.tls = self.tls;
        config.ca_file = self.ca_file.clone();
        if self.continuous {
            config.agent.grace = config.agent.interval;
        }
        config
    }
}

fn directory(hub: &HubConfig) -> PathBuf {
    hub.database.with_added_extension("agents.d")
}

pub(super) fn load_registry(hub: &mut HubConfig) -> Result<()> {
    let files = match fs::read_dir(directory(hub)) {
        Ok(files) => files,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("Cannot read agent registry"),
    };
    for file in files {
        let path = file?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("profile") {
            continue;
        }
        check_permissions(&path)?;
        let profile: Profile = toml::from_str(&fs::read_to_string(&path)?)
            .map_err(|_| anyhow::anyhow!("Invalid registered profile"))?;
        ensure!(
            path.file_stem().and_then(|n| n.to_str()) == Some(&profile.name),
            "Profile name differs from registry entry"
        );
        let entry: AgentEntry = profile.agent(&path).agent;
        hub.agents.push(entry);
    }
    Ok(())
}

pub fn register(hub: &HubConfig, name: &str, port: Option<u16>, offset: u64) -> Result<PathBuf> {
    validate_name(name)?;
    ensure!(
        !hub.agents.iter().any(|a| a.name == name),
        "Agent already registered"
    );
    let port = port.or(hub.public_port).unwrap_or(hub.tcp_listen[0].port());
    ensure!(port > 0 && offset < 3600, "Invalid port or hourly offset");
    let dir = directory(hub);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let path = dir.join(format!("{name}.profile"));
    let profile = Profile {
        mode: Mode::Profile,
        name: name.to_owned(),
        hub: hub.target.clone(),
        port,
        offset,
        continuous: true,
        tls: None,
        ca_file: None,
        secret: hex::encode(rand::random::<[u8; 32]>()),
    };
    let mut file = tempfile::NamedTempFile::new_in(&dir)?;
    file.write_all(toml::to_string(&profile)?.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&path)
        .context("Cannot create profile. The agent name must be unused")?;
    fs::File::open(dir)?.sync_all()?;
    Ok(path)
}
