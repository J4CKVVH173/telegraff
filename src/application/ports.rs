use super::{Family, State};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;

pub trait Repository {
    fn load(&self) -> Result<State>;
    fn save(&mut self, state: &State) -> Result<()>;
}
pub trait Clock {
    fn now(&self) -> u64;
}
#[derive(Debug, Clone)]
pub struct Resolution {
    pub addresses: Vec<IpAddr>,
    pub ipv4_error: bool,
    pub ipv6_error: bool,
}
impl Resolution {
    pub fn families(&self) -> Vec<Family> {
        let mut result = Vec::new();
        if self.addresses.iter().any(IpAddr::is_ipv4) {
            result.push(Family::Ipv4);
        }
        if self.addresses.iter().any(IpAddr::is_ipv6) {
            result.push(Family::Ipv6);
        }
        result
    }
    pub fn summary(&self) -> String {
        self.observation().summary()
    }
}
#[async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Resolution>;
}
#[async_trait]
pub trait Notifier {
    async fn publish(&self, text: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub agent: String,
    pub cycle: u64,
    pub channel: super::Channel,
    pub transfer: u8,
    pub total: usize,
}
#[async_trait]
pub trait Transport: Send {
    async fn identify(&mut self, _request: IdentityRequest) -> Option<Vec<Family>> {
        None
    }

    async fn send(
        &mut self,
        address: std::net::SocketAddr,
        request: TransferRequest,
        budget: std::time::Duration,
    ) -> Result<super::confirmation::Confirmation>;
}

pub struct IdentityRequest {
    pub addresses: Vec<std::net::SocketAddr>,
    pub agent: String,
    pub cycle: u64,
    pub total: usize,
    pub observation: DnsObservation,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsObservation {
    pub signature: String,
    pub ipv4_records: usize,
    pub ipv6_records: usize,
    pub ipv4_error: bool,
    pub ipv6_error: bool,
}
impl Resolution {
    pub fn observation(&self) -> DnsObservation {
        use sha2::{Digest, Sha256};
        let mut addresses = self.addresses.clone();
        addresses.sort();
        addresses.dedup();
        let mut hash = Sha256::new();
        for address in addresses {
            match address {
                std::net::IpAddr::V4(ip) => {
                    hash.update([4]);
                    hash.update(ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    hash.update([6]);
                    hash.update(ip.octets());
                }
            }
        }
        DnsObservation {
            signature: hex::encode(hash.finalize()),
            ipv4_records: self.addresses.iter().filter(|ip| ip.is_ipv4()).count(),
            ipv6_records: self.addresses.iter().filter(|ip| ip.is_ipv6()).count(),
            ipv4_error: self.ipv4_error,
            ipv6_error: self.ipv6_error,
        }
    }
}
impl DnsObservation {
    pub fn summary(&self) -> String {
        format!(
            "ipv4_records={} ipv6_records={} ipv4_error={} ipv6_error={} dns_set={}",
            self.ipv4_records, self.ipv6_records, self.ipv4_error, self.ipv6_error, self.signature
        )
    }
}
