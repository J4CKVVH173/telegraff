use crate::application::{Family, Policy};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

fn interval() -> u64 {
    3600
}
fn grace() -> u64 {
    600
}
fn payload() -> usize {
    153600
}
fn threshold() -> u8 {
    99
}
fn cycle_timeout() -> u64 {
    120
}
fn rate() -> u64 {
    131072
}
fn retention() -> u64 {
    30
}
fn reminder() -> u64 {
    21600
}
fn connections() -> usize {
    64
}
fn assemblies() -> usize {
    256
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEntry {
    pub name: String,
    pub key_file: PathBuf,
    pub activation: u64,
    #[serde(default = "interval")]
    pub interval: u64,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "grace")]
    pub grace: u64,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub families: Vec<Family>,
    #[serde(default)]
    pub auto: bool,
    #[serde(default = "payload")]
    pub payload_bytes: usize,
    #[serde(default = "threshold")]
    pub udp_threshold: u8,
}
impl AgentEntry {
    pub fn policy(&self) -> Policy {
        Policy {
            name: self.name.clone(),
            activation: self.activation,
            interval: self.interval,
            offset: self.offset,
            grace: self.grace,
            paused: self.paused,
            families: self.families.clone(),
            payload_bytes: self.payload_bytes,
            udp_threshold: self.udp_threshold,
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 32
                && self
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
            "Agent names must contain 1..32 ASCII letters, digits, hyphens or underscores"
        );
        ensure!(
            self.activation <= 253402300799,
            "Activation timestamp is out of range"
        );
        ensure!(
            self.interval >= 180 && self.interval <= 86400 && self.offset < self.interval,
            "Invalid interval or offset"
        );
        ensure!(
            self.grace >= 120 && self.grace < self.interval,
            "Grace must be at least 120 seconds and less than interval"
        );
        ensure!(
            (102400..=204800).contains(&self.payload_bytes),
            "Payload must be 100..200 KiB"
        );
        ensure!(
            (1..=100).contains(&self.udp_threshold),
            "UDP threshold must be 1..100"
        );
        let unique: HashSet<_> = self.families.iter().collect();
        ensure!(
            unique.len() == self.families.len(),
            "Duplicate address family"
        );
        ensure!(
            self.auto == self.families.is_empty(),
            "Set either auto=true or explicit families"
        );
        read_key(&self.key_file)?;
        Ok(())
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    pub endpoint: String,
    pub token_file: PathBuf,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    pub database: PathBuf,
    pub target: String,
    pub tcp_listen: Vec<SocketAddr>,
    pub udp_listen: Vec<SocketAddr>,
    #[serde(default = "retention")]
    pub retention_days: u64,
    #[serde(default = "reminder")]
    pub reminder_seconds: u64,
    #[serde(default = "connections")]
    pub max_connections: usize,
    #[serde(default = "assemblies")]
    pub max_assemblies: usize,
    pub ntfy: Option<NtfyConfig>,
    pub agents: Vec<AgentEntry>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub hub: String,
    pub port: u16,
    #[serde(default = "cycle_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "rate")]
    pub udp_bytes_per_second: u64,
    pub agent: AgentEntry,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum Config {
    Hub(HubConfig),
    Agent(AgentConfig),
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).context("Cannot read configuration file")?;
        // Parser diagnostics can quote input lines, including credentials.
        let config: Self = toml::from_str(&text)
            .map_err(|_| anyhow::anyhow!("Invalid TOML configuration or unknown field"))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Hub(c) => {
                ensure!(
                    !c.target.is_empty() && !c.agents.is_empty(),
                    "Hub target and agent registry are required"
                );
                ensure!(
                    !c.tcp_listen.is_empty() && !c.udp_listen.is_empty(),
                    "TCP and UDP listeners are required"
                );
                ensure!(
                    c.max_connections > 0
                        && c.max_connections <= 4096
                        && c.max_assemblies > 0
                        && c.max_assemblies <= 65536,
                    "Invalid resource limits"
                );
                ensure!((1..=3650).contains(&c.retention_days), "Invalid retention");
                let mut names = HashSet::new();
                for a in &c.agents {
                    a.validate()?;
                    ensure!(names.insert(&a.name), "Duplicate agent name");
                }
                if let Some(n) = &c.ntfy {
                    let url = reqwest::Url::parse(&n.endpoint).context("Invalid ntfy endpoint")?;
                    ensure!(
                        url.scheme() == "https"
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.query().is_none()
                            && url.fragment().is_none(),
                        "ntfy requires HTTPS without URL credentials or query"
                    );
                    read_token(&n.token_file)?;
                }
            }
            Self::Agent(c) => {
                c.agent.validate()?;
                ensure!(
                    !c.hub.is_empty() && c.port > 0,
                    "Hub address and port are required"
                );
                ensure!(
                    (1..=120).contains(&c.timeout_seconds),
                    "Cycle timeout must be 1..120 seconds"
                );
                ensure!(
                    (16384..=1048576).contains(&c.udp_bytes_per_second),
                    "Invalid UDP payload rate"
                );
            }
        }
        Ok(())
    }
}
pub fn read_key(path: &Path) -> Result<Vec<u8>> {
    check_permissions(path)?;
    let text = fs::read_to_string(path).context("Cannot read key file")?;
    let key = hex::decode(text.trim()).context("Key must be hexadecimal")?;
    ensure!(key.len() == 32, "Key must contain 32 bytes");
    Ok(key)
}
pub fn read_token(path: &Path) -> Result<String> {
    check_permissions(path)?;
    let token = fs::read_to_string(path).context("Cannot read ntfy token file")?;
    ensure!(
        !token.trim().is_empty() && !token.trim().contains(['\r', '\n']),
        "Invalid ntfy token"
    );
    Ok(token.trim().into())
}
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).context("Cannot inspect secret file")?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "Secret file must be a regular file with mode 0600 or stricter"
    );
    Ok(())
}
