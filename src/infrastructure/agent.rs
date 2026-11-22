use super::{
    receiver::{read_frame, write_frame},
    wire::{DATA, Frame, PART},
};
use crate::application::{
    Protocol,
    ports::{IdentityRequest, TransferRequest, Transport},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::{Instant, sleep_until, timeout},
};

pub struct SocketTransport {
    key: Vec<u8>,
    rate: u64,
    next_send: Instant,
    https: Option<Https>,
}
impl SocketTransport {
    pub fn new(key: Vec<u8>, rate: u64) -> Self {
        Self {
            key,
            rate,
            next_send: Instant::now(),
            https: None,
        }
    }
    pub fn for_hub(
        key: Vec<u8>,
        rate: u64,
        hub: &str,
        tls: Option<bool>,
        ca_file: Option<&std::path::Path>,
    ) -> Result<Self> {
        ensure!(
            !hub.trim().is_empty() && !hub.contains(['/', '@', '?', '#']),
            "Hub must be a DNS name or IP literal without a scheme or path"
        );
        let mut transport = Self::new(key, rate);
        if tls.unwrap_or_else(|| hub.parse::<std::net::IpAddr>().is_err()) {
            let mut url = reqwest::Url::parse("https://localhost/telegraff")?;
            url.set_host(Some(hub)).context("Invalid hub hostname")?;
            let certificates = if let Some(path) = ca_file {
                let pem = std::fs::read(path).context("Cannot read TLS CA file")?;
                let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                    .context("Invalid TLS CA PEM bundle")?;
                ensure!(
                    !certificates.is_empty(),
                    "TLS CA file contains no certificates"
                );
                certificates
            } else {
                Vec::new()
            };
            transport.https = Some(Https {
                host: url.host_str().context("Hub hostname required")?.to_owned(),
                certificates,
            });
        } else {
            ensure!(ca_file.is_none(), "ca_file requires TLS");
        }
        Ok(transport)
    }
    async fn exchange(&self, address: SocketAddr, frame: &Frame) -> Result<Vec<u8>> {
        if let Some(https) = &self.https {
            https.exchange(address, &frame.encode(&self.key)).await
        } else {
            let mut socket = TcpStream::connect(address).await?;
            write_frame(&mut socket, &frame.encode(&self.key)).await?;
            read_frame(&mut socket).await
        }
    }
}
struct Https {
    host: String,
    certificates: Vec<reqwest::Certificate>,
}
impl Https {
    async fn exchange(&self, address: SocketAddr, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut url = reqwest::Url::parse("https://localhost/telegraff")?;
        url.set_host(Some(&self.host))
            .context("Invalid hub hostname")?;
        url.set_port(Some(address.port()))
            .map_err(|_| anyhow::anyhow!("Invalid HTTPS port"))?;
        // Pin the exact family/address selected by the monitoring application;
        // retain the DNS hostname in the URL for Host, SNI and certificate checks.
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&self.host, &[address])
            .timeout(Duration::from_secs(10));
        for certificate in &self.certificates {
            builder = builder.add_root_certificate(certificate.clone());
        }
        let mut response = builder
            .build()?
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "HTTPS connection or certificate verification failed: {}",
                    error_chain(&e)
                )
            })?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "Unexpected HTTPS status: {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= super::wire::MAX_FRAME,
                "HTTPS receipt too large"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    messages.join(": ")
}
#[async_trait]
impl Transport for SocketTransport {
    async fn identify(
        &mut self,
        request: IdentityRequest,
    ) -> Option<Vec<crate::application::Family>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        for address in request.addresses {
            let frame = Frame {
                kind: super::wire::IDENTITY,
                agent: request.agent.clone(),
                cycle: request.cycle,
                channel: crate::application::Channel {
                    family: super::receiver::family(address.ip()),
                    protocol: Protocol::Tcp,
                },
                transfer: 0,
                total: request.total as u32,
                part: 0,
                parts: 1,
                payload: serde_json::to_vec(&request.observation).ok()?,
            };
            let result = timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(2)),
                async {
                    let response =
                        Frame::decode(&self.exchange(address, &frame).await?, &self.key)?;
                    ensure!(frame.matches_receipt(&response), "Invalid identity receipt");
                    let families = response
                        .payload
                        .iter()
                        .map(|b| match b {
                            4 => Ok(crate::application::Family::Ipv4),
                            6 => Ok(crate::application::Family::Ipv6),
                            _ => Err(anyhow::anyhow!("Invalid family")),
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok::<_, anyhow::Error>(families)
                },
            )
            .await;
            if let Ok(Ok(families)) = result {
                return Some(families);
            }
        }
        None
    }

    async fn send(
        &mut self,
        address: SocketAddr,
        request: TransferRequest,
        budget: Duration,
    ) -> Result<usize> {
        let mut frame = Frame {
            kind: DATA,
            agent: request.agent,
            cycle: request.cycle,
            channel: request.channel,
            transfer: request.transfer,
            total: request.total as u32,
            part: 0,
            parts: 1,
            payload: vec![0; request.total],
        };
        use hmac::{Hmac, Mac};
        use rand::{RngCore, SeedableRng};
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(frame.agent.as_bytes());
        mac.update(&frame.cycle.to_be_bytes());
        mac.update(frame.channel.label().as_bytes());
        mac.update(&[frame.transfer]);
        let seed: [u8; 32] = mac.finalize().into_bytes().into();
        rand::rngs::StdRng::from_seed(seed).fill_bytes(&mut frame.payload);
        let cap = match frame.channel.protocol {
            Protocol::Tcp => 3,
            Protocol::Udp => 5,
        };
        timeout(budget.min(Duration::from_secs(cap)), async {
            match frame.channel.protocol {
                Protocol::Tcp => {
                    let receipt = Frame::decode(&self.exchange(address, &frame).await?, &self.key)?;
                    ensure!(frame.matches_receipt(&receipt), "Invalid TCP receipt");
                    Ok(receipt.total as usize)
                }
                Protocol::Udp => {
                    udp(address, &frame, &self.key, self.rate, &mut self.next_send).await
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Transfer timed out"))?
    }
}
async fn udp(
    address: SocketAddr,
    template: &Frame,
    key: &[u8],
    rate: u64,
    next: &mut Instant,
) -> Result<usize> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(address).await?;
    let parts = template.payload.len().div_ceil(PART) as u16;
    for (part, payload) in template.payload.chunks(PART).enumerate() {
        sleep_until(*next).await;
        let frame = Frame {
            part: part as u16,
            parts,
            payload: payload.to_vec(),
            ..template.clone()
        };
        socket.send(&frame.encode(key)).await?;
        *next = Instant::now() + Duration::from_secs_f64(payload.len() as f64 / rate as f64);
    }
    let mut bytes = [0; 1232];
    let n = timeout(Duration::from_secs(1), socket.recv(&mut bytes)).await??;
    let receipt = Frame::decode(&bytes[..n], key)?;
    ensure!(template.matches_receipt(&receipt), "Invalid UDP receipt");
    Ok(receipt.total as usize)
}
