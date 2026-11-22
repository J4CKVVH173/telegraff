mod common;
use anyhow::Result;
use async_trait::async_trait;
use common::*;
use std::{net::IpAddr, sync::Arc};
use telegraff::{
    application::{
        Family,
        agent::{self, AgentSettings},
        ports::{Resolution, Resolver},
    },
    infrastructure::{
        agent::SocketTransport,
        receiver::{self, Intake},
    },
};
use tokio::sync::{Semaphore, mpsc};
struct Loopback(IpAddr);
#[async_trait]
impl Resolver for Loopback {
    async fn resolve(&self, _: &str) -> Result<Resolution> {
        Ok(Resolution {
            addresses: vec![self.0],
            ipv4_error: false,
            ipv6_error: false,
        })
    }
}

async fn check(ip: IpAddr) {
    let dir = tempfile::tempdir().unwrap();
    let mut entry = entry(key_file(dir.path()));
    let f = if ip.is_ipv4() {
        Family::Ipv4
    } else {
        Family::Ipv6
    };
    entry.families = vec![f];
    let now = telegraff::utils::unix_time();
    entry.offset = now % 3600;
    let tcp = receiver::bind_tcp((ip, 0).into()).expect("Loopback TCP must be available");
    let port = tcp.local_addr().unwrap().port();
    let udp = receiver::bind_udp((ip, port).into()).expect("Loopback UDP must be available");
    let registry = receiver::registry(&[entry.clone()]).unwrap();
    let (tx, mut rx) = mpsc::channel::<Intake>(32);
    let tcp_task = tokio::spawn(receiver::tcp_loop(
        tcp,
        registry.clone(),
        tx.clone(),
        Arc::new(Semaphore::new(8)),
    ));
    let udp_task = tokio::spawn(receiver::udp_loop(udp, registry, tx, 8));
    let intake = tokio::spawn(async move {
        let mut results = Vec::new();
        while let Some(i) = rx.recv().await {
            results.push(i.event);
            let _ = i.accepted.send(receiver::IntakeReply {
                accepted: true,
                families: Vec::new(),
            });
        }
        results
    });
    let settings = AgentSettings {
        policy: entry.policy(),
        hub: "loopback.invalid".into(),
        port,
        timeout_seconds: 30,
        auto: false,
    };
    let mut transport = SocketTransport::new(vec![7; 32], 1048576);
    let report = agent::run(
        &settings,
        &Loopback(ip),
        &mut transport,
        &telegraff::infrastructure::SystemClock,
    )
    .await
    .unwrap();
    assert!(report.successful(), "{report:?}");
    assert_eq!(report.channels.len(), 2);
    assert!(
        report
            .channels
            .iter()
            .all(|c| c.transfers.len() == 3 && c.accepted_bytes == 153600)
    );
    tcp_task.abort();
    udp_task.abort();
    intake.abort();
}
#[tokio::test]
async fn ipv4_tcp_and_udp_transfer_full_payload() {
    check("127.0.0.1".parse().unwrap()).await;
}
#[tokio::test]
async fn ipv6_tcp_and_udp_transfer_full_payload() {
    check("::1".parse().unwrap()).await;
}
