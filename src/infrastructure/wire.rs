use crate::application::{Channel, Family, Protocol};
use anyhow::{Result, ensure};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::AeadInPlace};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const PART: usize = 1100;
const ROUTING: usize = 37;
const ENVELOPE: usize = ROUTING + 24;
const FIELDS: usize = 20;
const TOKEN: usize = 32;
pub const HEADER: usize = ENVELOPE + FIELDS + TOKEN;
pub const TAG: usize = 16;

fn derive(secret: &[u8], purpose: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(purpose);
    mac
}
fn cipher(secret: &[u8]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(
        &derive(secret, b"telegraff/v2/encryption")
            .finalize()
            .into_bytes(),
    )
}
fn token(secret: &[u8]) -> Hmac<Sha256> {
    derive(secret, b"telegraff/v2/agent-token")
}

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
        bytes.push(2);
        let mut name = [0; 32];
        name[..self.agent.len()].copy_from_slice(self.agent.as_bytes());
        bytes.extend_from_slice(&name);
        let nonce: [u8; 24] = rand::random();
        bytes.extend_from_slice(&nonce);
        let mut body = Vec::with_capacity(FIELDS + TOKEN + self.payload.len() + TAG);
        body.push(self.kind);
        body.push(if self.channel.family == Family::Ipv4 {
            4
        } else {
            6
        });
        body.push(if self.channel.protocol == Protocol::Tcp {
            1
        } else {
            2
        });
        body.extend_from_slice(&self.cycle.to_be_bytes());
        body.push(self.transfer);
        body.extend_from_slice(&self.total.to_be_bytes());
        body.extend_from_slice(&self.part.to_be_bytes());
        body.extend_from_slice(&self.parts.to_be_bytes());
        body.extend_from_slice(&token(key).finalize().into_bytes());
        body.extend_from_slice(&self.payload);
        cipher(key)
            .encrypt_in_place((&nonce).into(), &bytes, &mut body)
            .expect("bounded frame");
        bytes.extend_from_slice(&body);
        bytes
    }

    pub fn identity(bytes: &[u8]) -> Result<&str> {
        ensure!(
            (HEADER + TAG..=MAX_FRAME).contains(&bytes.len()),
            "Invalid frame size"
        );
        ensure!(&bytes[..5] == b"TLGF\x02", "Unsupported wire version");
        let name = &bytes[5..ROUTING];
        let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        ensure!(
            end > 0 && name[end..].iter().all(|b| *b == 0),
            "Invalid agent identity"
        );
        Ok(std::str::from_utf8(&name[..end])?)
    }

    pub fn decode(bytes: &[u8], key: &[u8]) -> Result<Self> {
        let agent = Self::identity(bytes)?.to_owned();
        let mut body = bytes[ENVELOPE..].to_vec();
        cipher(key)
            .decrypt_in_place(
                bytes[ROUTING..ENVELOPE].into(),
                &bytes[..ENVELOPE],
                &mut body,
            )
            .map_err(|_| anyhow::anyhow!("Invalid authentication"))?;
        token(key)
            .verify_slice(&body[FIELDS..FIELDS + TOKEN])
            .map_err(|_| anyhow::anyhow!("Invalid agent token"))?;
        ensure!(
            matches!(body[0], DATA | RECEIPT | IDENTITY) && body[11] < 3,
            "Invalid transfer"
        );
        let family = match body[1] {
            4 => Family::Ipv4,
            6 => Family::Ipv6,
            _ => anyhow::bail!("Invalid family"),
        };
        let protocol = match body[2] {
            1 => Protocol::Tcp,
            2 => Protocol::Udp,
            _ => anyhow::bail!("Invalid protocol"),
        };
        Ok(Self {
            kind: body[0],
            agent,
            channel: Channel { family, protocol },
            cycle: u64::from_be_bytes(body[3..11].try_into()?),
            transfer: body[11],
            total: u32::from_be_bytes(body[12..16].try_into()?),
            part: u16::from_be_bytes(body[16..18].try_into()?),
            parts: u16::from_be_bytes(body[18..20].try_into()?),
            payload: body.split_off(FIELDS + TOKEN),
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
    pub fn into_confirmation(self) -> Result<crate::application::confirmation::Confirmation> {
        ensure!(
            self.kind == RECEIPT && self.part == 0 && self.parts == 0 && self.payload.is_empty(),
            "Invalid transfer confirmation envelope"
        );
        Ok(crate::application::confirmation::Confirmation {
            agent: self.agent,
            cycle: self.cycle,
            channel: self.channel,
            transfer: self.transfer,
            bytes: self.total as usize,
        })
    }
    pub fn from_confirmation(c: crate::application::confirmation::Confirmation) -> Self {
        Self {
            kind: RECEIPT,
            agent: c.agent,
            cycle: c.cycle,
            channel: c.channel,
            transfer: c.transfer,
            total: c.bytes as u32,
            part: 0,
            parts: 0,
            payload: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_request_requires_correct_token() {
        let key = [3; 32];
        let payload = b"diagnostic payload marker".to_vec();
        let frame = Frame {
            kind: DATA,
            agent: "node".into(),
            cycle: 12,
            channel: Channel {
                family: Family::Ipv4,
                protocol: Protocol::Udp,
            },
            transfer: 1,
            total: payload.len() as u32,
            part: 0,
            parts: 1,
            payload,
        };
        let mut wire = frame.encode(&key);
        assert_ne!(wire, frame.encode(&key));
        assert!(
            !wire
                .windows(frame.payload.len())
                .any(|s| s == frame.payload)
        );
        let token = token(&key).finalize().into_bytes();
        assert!(!wire.windows(TOKEN).any(|s| s == token.as_slice()));
        let mut body = wire.split_off(ENVELOPE);
        let nonce: &[u8; 24] = wire[ROUTING..].try_into().unwrap();
        cipher(&key)
            .decrypt_in_place(nonce.into(), &wire, &mut body)
            .unwrap();
        body[FIELDS] ^= 1;
        cipher(&key)
            .encrypt_in_place(nonce.into(), &wire, &mut body)
            .unwrap();
        wire.extend(body);
        assert_eq!(
            Frame::decode(&wire, &key).unwrap_err().to_string(),
            "Invalid agent token"
        );
        wire[4] = 1;
        assert!(Frame::identity(&wire).is_err());
    }
}
