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
pub(super) fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 32
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
        "Agent names must contain 1..32 ASCII letters, digits, hyphens or underscores"
    );
    Ok(())
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
        validate_name(&self.name)?;
        ensure!(
            self.activation <= 253402300799,
            "Activation timestamp is out of range"
        );
        ensure!(
            self.interval >= 180 && self.interval <= 86400 && self.offset < self.interval,
            "Invalid interval or offset"
        );
        ensure!(
            self.grace >= 120 && self.grace <= self.interval,
            "Grace must be at least 120 seconds and at most interval"
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
    pub token_file: Option<PathBuf>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubTlsConfig {
    pub certificate_file: Option<PathBuf>,
    pub private_key_file: Option<PathBuf>,
}
impl HubTlsConfig {
    pub fn paths(&self, target: &str) -> Result<(PathBuf, PathBuf)> {
        let automatic = self.certificate_file.is_none() || self.private_key_file.is_none();
        if automatic {
            ensure!(
                target.contains('.')
                    && target
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
                    && !target.contains("..")
                    && target.parse::<std::net::IpAddr>().is_err(),
                "Automatic certbot paths require a DNS target; set certificate_file and private_key_file explicitly for IP targets"
            );
        }
        let directory = Path::new("/etc/letsencrypt/live").join(target);
        let certificate_file = self
            .certificate_file
            .clone()
            .unwrap_or_else(|| directory.join("fullchain.pem"));
        let private_key_file = self
            .private_key_file
            .clone()
            .unwrap_or_else(|| directory.join("privkey.pem"));
        Ok((certificate_file, private_key_file))
    }
    pub fn acceptor(&self, target: &str) -> Result<tokio_rustls::TlsAcceptor> {
        use tokio_rustls::rustls::{
            self,
            pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        };
        let (certificate_file, private_key_file) = self.paths(target)?;
        let certificates = CertificateDer::pem_file_iter(&certificate_file)
            .with_context(|| format!("Cannot read TLS certificate file {}; issue the certificate with certbot or set tls.certificate_file", certificate_file.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Invalid TLS certificate PEM")?;
        ensure!(
            !certificates.is_empty(),
            "TLS certificate file contains no certificates"
        );
        let key = PrivateKeyDer::from_pem_file(&private_key_file)
            .with_context(|| format!("Cannot read TLS private key PEM {}; check permissions and use an unencrypted PEM key", private_key_file.display()))?;
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .context("Invalid TLS certificate chain or mismatched private key")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    pub tls: Option<HubTlsConfig>,
    pub database: PathBuf,
    pub target: String,
    #[serde(default)]
    pub public_port: Option<u16>,
    pub public_udp_port: Option<u16>,
    pub udp_target: Option<String>,
    #[serde(default)]
    pub ingress: super::ingress::Limits,
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
    #[serde(default)]
    pub agents: Vec<AgentEntry>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Defaults to HTTPS for DNS names and raw TCP for IP literals.
    pub tls: Option<bool>,
    pub ca_file: Option<PathBuf>,
    pub hub: String,
    pub port: u16,
    pub udp_port: Option<u16>,
    pub udp_hub: Option<String>,
    #[serde(default = "cycle_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "rate")]
    pub udp_bytes_per_second: u64,
    pub agent: AgentEntry,
}
impl AgentConfig {
    pub(super) fn registered(
        name: String,
        key_file: PathBuf,
        hub: String,
        port: u16,
        offset: u64,
    ) -> Self {
        Self {
            hub,
            port,
            udp_port: None,
            udp_hub: None,
            tls: None,
            ca_file: None,
            timeout_seconds: cycle_timeout(),
            udp_bytes_per_second: rate(),
            agent: AgentEntry {
                name,
                key_file,
                activation: 0,
                interval: interval(),
                offset,
                grace: grace(),
                paused: false,
                families: Vec::new(),
                auto: true,
                payload_bytes: payload(),
                udp_threshold: threshold(),
            },
        }
    }
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
        let mut config: Self = match toml::from_str(&text) {
            Ok(config) => config,
            Err(_) => {
                let profile: super::registration::Profile = toml::from_str(&text)
                    .map_err(|_| anyhow::anyhow!("Invalid TOML configuration or unknown field"))?;
                check_permissions(path)?;
                Config::Agent(profile.agent(path))
            }
        };
        if let Self::Hub(hub) = &mut config {
            super::registration::load_registry(hub)?;
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Hub(c) => {
                ensure!(!c.target.is_empty(), "Hub target is required");
                ensure!(
                    c.public_port != Some(0) && c.public_udp_port != Some(0),
                    "Public ports must be nonzero"
                );
                c.ingress.validate()?;
                if let Some(host) = &c.udp_target {
                    validate_host(host)?;
                }
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
                    if let Some(path) = &n.token_file {
                        read_token(path)?;
                    }
                }
            }
            Self::Agent(c) => {
                c.agent.validate()?;
                ensure!(c.udp_port != Some(0), "UDP port must be nonzero");
                if let Some(host) = &c.udp_hub {
                    validate_host(host)?;
                }
                super::agent::SocketTransport::for_hub(
                    vec![0; 32],
                    c.udp_bytes_per_second,
                    &c.hub,
                    c.tls,
                    c.ca_file.as_deref(),
                )?;
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
    let secret = if text.trim().len() == 64 {
        text.trim()
    } else {
        let profile: super::registration::Profile =
            toml::from_str(&text).map_err(|_| anyhow::anyhow!("Invalid credential file"))?;
        return decode_key(&profile.secret);
    };
    decode_key(secret)
}
fn decode_key(secret: &str) -> Result<Vec<u8>> {
    let key = hex::decode(secret).context("Key must be hexadecimal")?;
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
pub(super) fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).context("Cannot inspect secret file")?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "Secret file must be a regular file with mode 0600 or stricter"
    );
    Ok(())
}

pub(super) fn validate_host(host: &str) -> Result<()> {
    ensure!(
        !host.trim().is_empty() && host == host.trim() && !host.contains(['/', '@', '?', '#']),
        "UDP host must be a DNS name or IP literal"
    );
    if host.parse::<std::net::IpAddr>().is_err() {
        ensure!(
            host.len() <= 253
                && host.trim_end_matches('.').split('.').all(|s| !s.is_empty()
                    && s.len() <= 63
                    && !s.starts_with('-')
                    && !s.ends_with('-')
                    && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')),
            "Invalid UDP hostname"
        );
    }
    Ok(())
}
