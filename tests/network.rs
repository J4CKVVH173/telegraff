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

async fn check(ip: IpAddr, split: bool) {
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
    let udp = receiver::bind_udp((ip, if split { 0 } else { port }).into())
        .expect("Loopback UDP must be available");
    let udp_port = udp.local_addr().unwrap().port();
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
        udp_port: split.then_some(udp_port),
        udp_hub: None,
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
    check("127.0.0.1".parse().unwrap(), false).await;
}
#[tokio::test]
async fn ipv6_tcp_and_udp_transfer_full_payload() {
    check("::1".parse().unwrap(), false).await;
}

#[tokio::test]
async fn ipv4_split_tcp_udp_ports_transfer_full_payload() {
    check("127.0.0.1".parse().unwrap(), true).await;
}
#[tokio::test]
async fn ipv6_split_tcp_udp_ports_transfer_full_payload() {
    check("::1".parse().unwrap(), true).await;
}

#[tokio::test]
async fn tcp_ip_connection_limit_closes_before_authentication() {
    use telegraff::infrastructure::ingress::{Guard, Limits};
    use tokio::{
        io::AsyncReadExt,
        time::{Duration, timeout},
    };
    let guard = Guard::new(
        Limits {
            tcp_connections_per_ip: 1,
            ..Limits::default()
        },
        8,
    );
    let reservation = guard.tcp("127.0.0.1".parse().unwrap()).unwrap();
    let listener = receiver::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let task = tokio::spawn(receiver::tcp_loop_guarded(
        listener,
        receiver::registry(&[]).unwrap(),
        tx,
        Arc::new(Semaphore::new(8)),
        None,
        guard.clone(),
    ));
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), stream.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(guard.take_rejections(), vec![("connections", 1)]);
    drop(reservation);
    task.abort();
}

#[tokio::test]
async fn udp_flood_is_limited_before_frame_authentication() {
    use telegraff::infrastructure::ingress::{Guard, Limits};
    use tokio::time::{Duration, sleep, timeout};
    let guard = Guard::new(
        Limits {
            udp_per_ip_per_second: 1,
            ..Limits::default()
        },
        8,
    );
    let socket = receiver::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = socket.local_addr().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let task = tokio::spawn(receiver::udp_loop_guarded(
        socket,
        receiver::registry(&[]).unwrap(),
        tx,
        8,
        guard.clone(),
    ));
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..10 {
        sender.send_to(b"invalid", address).await.unwrap();
    }
    let mut auth = 0;
    let mut limited = 0;
    timeout(Duration::from_secs(2), async {
        loop {
            for (reason, n) in guard.take_rejections() {
                match reason {
                    "authentication_or_frame" => auth += n,
                    "ip_rate" => limited += n,
                    _ => panic!("Unexpected rejection"),
                }
            }
            if auth + limited == 10 {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!((auth, limited), (2, 8));
    task.abort();
}
