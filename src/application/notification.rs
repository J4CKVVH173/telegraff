//! Notification text is presentation, independent of the delivery service.
use super::{Channel, Family, Protocol};
use crate::utils::timestamp;

pub fn message(subject: &str, now: u64, details: &[String]) -> String {
    format!("📡 {subject}\n{}\n\n{}", timestamp(now), details.join("\n"))
}
pub fn channel(channel: Channel) -> String {
    format!(
        "{} · {}",
        match channel.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        },
        match channel.family {
            Family::Ipv4 => "IPv4",
            Family::Ipv6 => "IPv6",
        }
    )
}
pub fn failure(channel: Channel, last_success: Option<u64>) -> String {
    let last = last_success
        .map(timestamp)
        .unwrap_or_else(|| "ещё не было".into());
    format!(
        "🔴 {}: нет успешной передачи 3 проверки подряд.\nПоследний успех: {last}.",
        self::channel(channel)
    )
}
