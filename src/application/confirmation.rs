//! Shared transfer confirmation rules. Socket framing and encryption stay in infrastructure.
use super::{Channel, Protocol, Transfer, ports::TransferRequest};
use anyhow::{Result, ensure};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pub agent: String,
    pub cycle: u64,
    pub channel: Channel,
    pub transfer: u8,
    pub bytes: usize,
}
impl Confirmation {
    /// Called only after the application has accepted and persisted the transfer.
    pub fn accepted(transfer: &Transfer) -> Self {
        Self {
            agent: transfer.agent.clone(),
            cycle: transfer.cycle,
            channel: transfer.channel,
            transfer: transfer.transfer,
            bytes: transfer.bytes,
        }
    }
    pub fn validate(&self, request: &TransferRequest) -> Result<usize> {
        ensure!(
            self.agent == request.agent
                && self.cycle == request.cycle
                && self.channel == request.channel
                && self.transfer == request.transfer,
            "Confirmation does not match transfer"
        );
        ensure!(
            self.bytes <= request.total,
            "Confirmation exceeds transfer size"
        );
        Ok(self.bytes)
    }
}

pub fn passes(protocol: Protocol, bytes: usize, total: usize, udp_threshold: u8) -> bool {
    bytes <= total
        && total > 0
        && match protocol {
            Protocol::Tcp => bytes == total,
            Protocol::Udp => bytes as u128 * 100 >= total as u128 * u128::from(udp_threshold),
        }
}
