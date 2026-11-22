use super::{
    receiver::{read_frame, write_frame},
    wire::{DATA, Frame, PART},
};
use crate::application::{
    Protocol,
    ports::{IdentityRequest, TransferRequest, Transport},
};
use anyhow::{Result, ensure};
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
}
impl SocketTransport {
    pub fn new(key: Vec<u8>, rate: u64) -> Self {
        Self {
            key,
            rate,
            next_send: Instant::now(),
        }
    }
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
                    let mut socket = TcpStream::connect(address).await?;
                    write_frame(&mut socket, &frame.encode(&self.key)).await?;
                    let response = Frame::decode(&read_frame(&mut socket).await?, &self.key)?;
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
                Protocol::Tcp => tcp(address, &frame, &self.key).await,
                Protocol::Udp => {
                    udp(address, &frame, &self.key, self.rate, &mut self.next_send).await
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Transfer timed out"))?
    }
}
async fn tcp(address: SocketAddr, frame: &Frame, key: &[u8]) -> Result<usize> {
    let mut socket = TcpStream::connect(address).await?;
    write_frame(&mut socket, &frame.encode(key)).await?;
    let bytes = read_frame(&mut socket).await?;
    let receipt = Frame::decode(&bytes, key)?;
    ensure!(frame.matches_receipt(&receipt), "Invalid TCP receipt");
    Ok(receipt.total as usize)
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
