use crate::application::{Channel, Family, Protocol};
use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const PART: usize = 1100;
pub const HEADER: usize = 62;
pub const TAG: usize = 32;
pub const MAX_FRAME: usize = 204800 + HEADER + TAG;
pub const RECEIPT: u8 = 2;
pub const DATA: u8 = 1;
pub const IDENTITY: u8 = 3;

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: u8,
    pub agent: String,
    pub cycle: u64,
    pub channel: Channel,
    pub transfer: u8,
    pub total: u32,
    pub part: u16,
    pub parts: u16,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn encode(&self, key: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER + TAG + self.payload.len());
        bytes.extend_from_slice(b"TLGF");
        bytes.push(1);
        bytes.push(self.kind);
        bytes.push(if self.channel.family == Family::Ipv4 {
            4
        } else {
            6
        });
        bytes.push(if self.channel.protocol == Protocol::Tcp {
            1
        } else {
            2
        });
        let mut name = [0; 32];
        name[..self.agent.len()].copy_from_slice(self.agent.as_bytes());
        bytes.extend_from_slice(&name);
        bytes.extend_from_slice(&self.cycle.to_be_bytes());
        bytes.push(self.transfer);
        bytes.push(0);
        bytes.extend_from_slice(&self.total.to_be_bytes());
        bytes.extend_from_slice(&self.part.to_be_bytes());
        bytes.extend_from_slice(&self.parts.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        bytes
    }
    pub fn identity(bytes: &[u8]) -> Result<&str> {
        ensure!(
            bytes.len() >= HEADER + TAG && bytes.len() <= MAX_FRAME,
            "Invalid frame size"
        );
        ensure!(
            &bytes[..4] == b"TLGF" && bytes[4] == 1,
            "Unsupported wire version"
        );
        let end = bytes[8..40].iter().position(|b| *b == 0).unwrap_or(32);
        ensure!(
            bytes[8 + end..40].iter().all(|b| *b == 0),
            "Invalid identity padding"
        );
        Ok(std::str::from_utf8(&bytes[8..8 + end])?)
    }
    pub fn decode(bytes: &[u8], key: &[u8]) -> Result<Self> {
        let agent = Self::identity(bytes)?.to_string();
        let split = bytes.len() - TAG;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&bytes[..split]);
        mac.verify_slice(&bytes[split..])
            .map_err(|_| anyhow::anyhow!("Invalid authentication"))?;
        ensure!(
            bytes[5] == DATA || bytes[5] == RECEIPT || bytes[5] == IDENTITY,
            "Invalid frame kind"
        );
        ensure!(bytes[49] == 0 && bytes[48] < 3, "Invalid transfer");
        let family = match bytes[6] {
            4 => Family::Ipv4,
            6 => Family::Ipv6,
            _ => anyhow::bail!("Invalid family"),
        };
        let protocol = match bytes[7] {
            1 => Protocol::Tcp,
            2 => Protocol::Udp,
            _ => anyhow::bail!("Invalid protocol"),
        };
        let total = u32::from_be_bytes(bytes[50..54].try_into()?);
        let part = u16::from_be_bytes(bytes[54..56].try_into()?);
        let parts = u16::from_be_bytes(bytes[56..58].try_into()?);
        let len = u32::from_be_bytes(bytes[58..62].try_into()?) as usize;
        ensure!(len == split - HEADER, "Invalid payload length");
        Ok(Self {
            kind: bytes[5],
            agent,
            cycle: u64::from_be_bytes(bytes[40..48].try_into()?),
            channel: Channel { family, protocol },
            transfer: bytes[48],
            total,
            part,
            parts,
            payload: bytes[HEADER..split].to_vec(),
        })
    }
    pub fn receipt(&self, bytes: usize) -> Self {
        Self {
            kind: RECEIPT,
            total: bytes as u32,
            payload: Vec::new(),
            part: 0,
            parts: 0,
            ..self.clone()
        }
    }
    pub fn matches_receipt(&self, receipt: &Self) -> bool {
        receipt.kind == RECEIPT
            && receipt.agent == self.agent
            && receipt.cycle == self.cycle
            && receipt.channel == self.channel
            && receipt.transfer == self.transfer
    }
}
