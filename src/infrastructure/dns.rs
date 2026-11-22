use crate::application::ports::{Resolution, Resolver};
use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_resolver::{TokioResolver, proto::rr::RecordType};
use std::net::IpAddr;

pub struct Dns {
    resolver: TokioResolver,
}
impl Dns {
    pub fn new() -> Result<Self> {
        Ok(Self {
            resolver: TokioResolver::builder_tokio()
                .context("Cannot load DNS configuration")?
                .build(),
        })
    }
}
#[async_trait]
impl Resolver for Dns {
    async fn resolve(&self, host: &str) -> Result<Resolution> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Resolution {
                addresses: vec![normalize(ip)],
                ipv4_error: false,
                ipv6_error: false,
            });
        }
        let (a, aaaa) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                self.resolver.lookup(host, RecordType::A),
                self.resolver.lookup(host, RecordType::AAAA)
            )
        })
        .await
        .map_err(|_| anyhow::anyhow!("DNS lookup timed out"))?;
        let mut result = Resolution {
            addresses: Vec::new(),
            ipv4_error: false,
            ipv6_error: false,
        };
        for (lookup, error) in [(a, &mut result.ipv4_error), (aaaa, &mut result.ipv6_error)] {
            match lookup {
                Ok(records) => {
                    for record in records.iter() {
                        match record {
                            hickory_resolver::proto::rr::RData::A(ip) => {
                                result.addresses.push(IpAddr::V4(ip.0))
                            }
                            hickory_resolver::proto::rr::RData::AAAA(ip) => {
                                result.addresses.push(IpAddr::V6(ip.0))
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    *error = !e.is_no_records_found();
                }
            }
        }
        result
            .addresses
            .iter_mut()
            .for_each(|ip| *ip = normalize(*ip));
        result.addresses.sort();
        result.addresses.dedup();
        Ok(result)
    }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
