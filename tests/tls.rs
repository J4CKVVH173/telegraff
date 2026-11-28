mod common;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use telegraff::{
    application::{
        Channel, Family, Protocol,
        ports::{IdentityRequest, Resolution, TransferRequest, Transport},
    },
    infrastructure::{
        agent::SocketTransport,
        receiver::{self, Intake},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};

struct Fixture {
    _dir: tempfile::TempDir,
    ca: PathBuf,
    address: SocketAddr,
    backend: SocketAddr,
    sni: mpsc::Receiver<String>,
    intake: mpsc::Receiver<Intake>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Fixture {
    async fn new(ip: IpAddr) -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["hub.test".into()]).unwrap();
        Self::with_certificate(ip, certificate).await
    }
    async fn with_certificate(ip: IpAddr, certificate: rcgen::CertifiedKey) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("test-ca.pem");
        std::fs::write(&ca, certificate.cert.pem()).unwrap();
        let key = PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], key.into())
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        // Model nginx forwarding either public address family to an IPv4 backend.
        let listener_backend = receiver::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let backend = listener_backend.local_addr().unwrap();
        let mut entry = common::entry(common::key_file(dir.path()));
        entry.grace = entry.interval;
        let registry = receiver::registry(&[entry]).unwrap();
        let (tx, intake) = mpsc::channel(32);
        let hub = tokio::spawn(async move {
            receiver::tcp_loop(listener_backend, registry, tx, Arc::new(Semaphore::new(8)))
                .await
                .unwrap();
        });
        let (sni_tx, sni) = mpsc::channel(32);
        let proxy = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                // Tests use sequential requests; no detached per-request tasks remain.
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    sni_tx
                        .send(tls.get_ref().1.server_name().unwrap_or("").to_owned())
                        .await
                        .unwrap();
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        assert!(headers.len() < 8192);
                        headers.push(tls.read_u8().await.unwrap());
                    }
                    let text = std::str::from_utf8(&headers).unwrap().to_ascii_lowercase();
                    assert!(text.starts_with("post /telegraff http/1.1\r\n"));
                    assert!(text.contains(&format!("\r\nhost: hub.test:{}\r\n", address.port())));
                    let mut upstream = TcpStream::connect(backend).await.unwrap();
                    upstream.write_all(&headers).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                }
            }
        });
        Self {
            _dir: dir,
            ca,
            address,
            backend,
            sni,
            intake,
            tasks: vec![hub, proxy],
        }
    }
    fn transport(&self, host: &str, trusted: bool) -> SocketTransport {
        SocketTransport::for_hub(
            vec![7; 32],
            1048576,
            host,
            None,
            if trusted {
                Some(self.ca.as_path())
            } else {
                None
            },
        )
        .unwrap()
    }
    fn request(&self) -> TransferRequest {
        TransferRequest {
            agent: "node-01".into(),
            cycle: 123456,
            channel: Channel {
                family: if self.address.is_ipv4() {
                    Family::Ipv4
                } else {
                    Family::Ipv6
                },
                protocol: Protocol::Tcp,
            },
            transfer: 0,
            total: 153600,
        }
    }
}
async fn check_https(ip: IpAddr) {
    let mut fixture = Fixture::new(ip).await;
    let mut transport = fixture.transport("hub.test", true);
    let address = fixture.address;
    let request = fixture.request();
    let family = request.channel.family;
    let resolution = Resolution {
        addresses: vec![ip],
        ipv4_error: false,
        ipv6_error: false,
    };
    let identify = transport.identify(IdentityRequest {
        addresses: vec![address],
        agent: "node-01".into(),
        cycle: 123456,
        total: 153600,
        observation: resolution.observation(),
    });
    let respond = async {
        let event = fixture.intake.recv().await.unwrap();
        assert!(matches!(event.event, receiver::Incoming::Dns(_, _)));
        event
            .accepted
            .send(receiver::IntakeReply {
                accepted: true,
                families: vec![family],
            })
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(identify, respond)
    })
    .await
    .unwrap();
    assert_eq!(result, Some(vec![family]));
    let send = transport.send(address, request, Duration::from_secs(5));
    let respond = async {
        let event = fixture.intake.recv().await.unwrap();
        let receiver::Incoming::Transfer(transfer) = event.event else {
            panic!("transfer expected")
        };
        assert_eq!(transfer.channel.family, family);
        assert_eq!(transfer.bytes, 153600);
        event
            .accepted
            .send(receiver::IntakeReply {
                accepted: true,
                families: vec![family],
            })
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(send, respond)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap().bytes, 153600);
    for _ in 0..2 {
        assert_eq!(fixture.sni.recv().await.unwrap(), "hub.test");
    }
}
#[tokio::test]
async fn https_sni_and_receipts_over_ipv4() {
    check_https("127.0.0.1".parse().unwrap()).await;
}
#[tokio::test]
async fn https_ipv6_frontend_with_ipv4_backend() {
    check_https("::1".parse().unwrap()).await;
}
#[tokio::test]
async fn rejects_untrusted_certificate_without_plaintext_fallback() {
    let mut fixture = Fixture::new("127.0.0.1".parse().unwrap()).await;
    let mut transport = fixture.transport("hub.test", false);
    let error = transport
        .send(fixture.address, fixture.request(), Duration::from_secs(5))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("UnknownIssuer"), "{error}");
    assert!(fixture.intake.try_recv().is_err());
}
#[tokio::test]
async fn rejects_wrong_hostname_even_with_trusted_certificate() {
    let mut fixture = Fixture::new("127.0.0.1".parse().unwrap()).await;
    let mut transport = fixture.transport("wrong.test", true);
    let error = transport
        .send(fixture.address, fixture.request(), Duration::from_secs(5))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("certificate not valid for name"), "{error}");
    assert!(fixture.intake.try_recv().is_err());
}
#[tokio::test]
async fn explicit_plain_tcp_preserves_legacy_domain_connections() {
    let mut fixture = Fixture::new("127.0.0.1".parse().unwrap()).await;
    let mut transport =
        SocketTransport::for_hub(vec![7; 32], 1048576, "hub.test", Some(false), None).unwrap();
    let send = transport.send(fixture.backend, fixture.request(), Duration::from_secs(5));
    let respond = async {
        let event = fixture.intake.recv().await.unwrap();
        event
            .accepted
            .send(receiver::IntakeReply {
                accepted: true,
                families: vec![Family::Ipv4],
            })
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(send, respond)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap().bytes, 153600);
}
#[test]
fn rejects_invalid_ca_or_host_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let empty_ca = dir.path().join("empty.pem");
    std::fs::write(&empty_ca, "").unwrap();
    assert!(
        SocketTransport::for_hub(vec![7; 32], 1048576, "hub.test", None, Some(&empty_ca)).is_err()
    );
    assert!(
        SocketTransport::for_hub(
            vec![7; 32],
            1048576,
            "hub.test",
            Some(false),
            Some(&empty_ca)
        )
        .is_err()
    );
    assert!(
        SocketTransport::for_hub(vec![7; 32], 1048576, "https://hub.test/path", None, None)
            .is_err()
    );
}

#[tokio::test]
async fn rejects_expired_certificate_even_when_explicitly_trusted() {
    let mut params = rcgen::CertificateParams::new(vec!["hub.test".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let mut fixture = Fixture::with_certificate(
        "127.0.0.1".parse().unwrap(),
        rcgen::CertifiedKey { cert, key_pair },
    )
    .await;
    let mut transport = fixture.transport("hub.test", true);
    let error = transport
        .send(fixture.address, fixture.request(), Duration::from_secs(5))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("certificate expired"), "{error}");
    assert!(fixture.intake.try_recv().is_err());
}

async fn check_native_tls(ip: IpAddr) {
    use telegraff::infrastructure::config::HubTlsConfig;
    let dir = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["hub.test".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, certificate.cert.pem()).unwrap();
    std::fs::write(&key, certificate.key_pair.serialize_pem()).unwrap();
    let acceptor = HubTlsConfig {
        certificate_file: Some(cert.clone()),
        private_key_file: Some(key),
    }
    .acceptor("hub.test")
    .unwrap();
    let listener = receiver::bind_tcp((ip, 0).into()).unwrap();
    let address = listener.local_addr().unwrap();
    let mut entry = common::entry(common::key_file(dir.path()));
    entry.grace = entry.interval;
    let registry = receiver::registry(&[entry]).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(receiver::tcp_loop_with_tls(
        listener,
        registry,
        tx,
        Arc::new(Semaphore::new(8)),
        Some(acceptor),
    ));
    // A bad TLS peer must not stop the listener or reach authenticated intake.
    let mut untrusted =
        SocketTransport::for_hub(vec![7; 32], 1048576, "hub.test", None, None).unwrap();
    let request = TransferRequest {
        agent: "node-01".into(),
        cycle: 123456,
        channel: Channel {
            family: receiver::family(ip),
            protocol: Protocol::Tcp,
        },
        transfer: 0,
        total: 153600,
    };
    assert!(
        untrusted
            .send(
                address,
                TransferRequest {
                    agent: "node-01".into(),
                    cycle: 123456,
                    channel: request.channel,
                    transfer: 0,
                    total: 153600
                },
                Duration::from_secs(5)
            )
            .await
            .is_err()
    );
    assert!(rx.try_recv().is_err());
    let mut transport =
        SocketTransport::for_hub(vec![7; 32], 1048576, "hub.test", None, Some(&cert)).unwrap();
    let family = request.channel.family;
    let identify = transport.identify(IdentityRequest {
        addresses: vec![address],
        agent: "node-01".into(),
        cycle: 123456,
        total: 153600,
        observation: Resolution {
            addresses: vec![ip],
            ipv4_error: false,
            ipv6_error: false,
        }
        .observation(),
    });
    let respond = async {
        let event = rx.recv().await.unwrap();
        assert!(matches!(event.event, receiver::Incoming::Dns(_, _)));
        event
            .accepted
            .send(receiver::IntakeReply {
                accepted: true,
                families: vec![family],
            })
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(identify, respond)
    })
    .await
    .unwrap();
    assert_eq!(result, Some(vec![family]));
    let send = transport.send(address, request, Duration::from_secs(5));
    let respond = async {
        let event = rx.recv().await.unwrap();
        let receiver::Incoming::Transfer(transfer) = event.event else {
            panic!("transfer expected")
        };
        assert_eq!(transfer.bytes, 153600);
        assert_eq!(transfer.channel.family, family);
        event
            .accepted
            .send(receiver::IntakeReply {
                accepted: true,
                families: vec![family],
            })
            .unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(10), async {
        tokio::join!(send, respond)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap().bytes, 153600);
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn native_tls_ipv4_receipts_and_enrollment() {
    check_native_tls("127.0.0.1".parse().unwrap()).await;
}
#[tokio::test]
async fn native_tls_ipv6_receipts_and_enrollment() {
    check_native_tls("::1".parse().unwrap()).await;
}
#[test]
fn native_tls_configuration_rejects_bad_credentials() {
    use telegraff::infrastructure::config::HubTlsConfig;
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let config = HubTlsConfig {
        certificate_file: Some(cert.clone()),
        private_key_file: Some(key.clone()),
    };
    assert!(config.acceptor("hub.test").is_err());
    std::fs::write(&cert, "invalid PEM").unwrap();
    std::fs::write(&key, "invalid PEM").unwrap();
    assert!(config.acceptor("hub.test").is_err());
    let a = rcgen::generate_simple_self_signed(vec!["hub.test".into()]).unwrap();
    let b = rcgen::generate_simple_self_signed(vec!["hub.test".into()]).unwrap();
    std::fs::write(&cert, a.cert.pem()).unwrap();
    assert!(config.acceptor("hub.test").is_err());
    std::fs::write(&key, b.key_pair.serialize_pem()).unwrap();
    assert!(config.acceptor("hub.test").is_err());
    std::fs::write(&key, a.key_pair.serialize_pem()).unwrap();
    assert!(config.acceptor("hub.test").is_ok());
}

#[test]
fn native_tls_automatic_certbot_paths_and_overrides() {
    use telegraff::infrastructure::config::HubTlsConfig;
    let automatic: HubTlsConfig = toml::from_str("").unwrap();
    assert_eq!(
        automatic.paths("hub.example.net").unwrap(),
        (
            PathBuf::from("/etc/letsencrypt/live/hub.example.net/fullchain.pem"),
            PathBuf::from("/etc/letsencrypt/live/hub.example.net/privkey.pem")
        )
    );
    for target in [
        "127.0.0.1",
        "::1",
        "../bad",
        "/tmp/example.net",
        "https://example.net",
    ] {
        assert!(automatic.paths(target).is_err());
    }
    let explicit = HubTlsConfig {
        certificate_file: Some("custom-cert.pem".into()),
        private_key_file: Some("custom-key.pem".into()),
    };
    assert_eq!(
        explicit.paths("127.0.0.1").unwrap(),
        (
            PathBuf::from("custom-cert.pem"),
            PathBuf::from("custom-key.pem")
        )
    );
    let partial = HubTlsConfig {
        certificate_file: Some("custom.pem".into()),
        private_key_file: None,
    };
    assert_eq!(
        partial.paths("hub.example.net").unwrap().1,
        PathBuf::from("/etc/letsencrypt/live/hub.example.net/privkey.pem")
    );
}

#[tokio::test]
async fn full_agent_cycle_uses_https_proxy_and_direct_udp_on_another_port() {
    use async_trait::async_trait;
    use telegraff::application::{
        agent::{self, AgentSettings},
        ports::Resolver,
    };
    struct Endpoints(IpAddr);
    #[async_trait]
    impl Resolver for Endpoints {
        async fn resolve(&self, host: &str) -> anyhow::Result<Resolution> {
            assert!(matches!(host, "hub.test" | "origin.test"));
            Ok(Resolution {
                addresses: vec![self.0],
                ipv4_error: false,
                ipv6_error: false,
            })
        }
    }
    for ip in [
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        "::1".parse().unwrap(),
    ] {
        let mut fixture = Fixture::new(ip).await;
        let mut entry = common::entry(common::key_file(fixture._dir.path()));
        entry.grace = entry.interval;
        let family = receiver::family(ip);
        entry.families = vec![family];
        let udp = receiver::bind_udp((ip, 0).into()).unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        assert_ne!(udp_port, fixture.address.port());
        let (tx, mut rx) = mpsc::channel::<Intake>(32);
        let registry = receiver::registry(&[entry.clone()]).unwrap();
        fixture.tasks.push(tokio::spawn(async move {
            receiver::udp_loop(udp, registry, tx, 8).await.unwrap();
        }));
        let config = AgentSettings {
            policy: entry.policy(),
            hub: "hub.test".into(),
            port: fixture.address.port(),
            udp_port: Some(udp_port),
            udp_hub: Some("origin.test".into()),
            timeout_seconds: 30,
            auto: true,
        };
        let mut transport = fixture.transport("hub.test", true);
        let endpoints = Endpoints(ip);
        let run = agent::run(
            &config,
            &endpoints,
            &mut transport,
            &telegraff::infrastructure::SystemClock,
        );
        let respond = async {
            loop {
                let event = tokio::select! { event=fixture.intake.recv()=>event.unwrap(), event=rx.recv()=>event.unwrap() };
                event
                    .accepted
                    .send(receiver::IntakeReply {
                        accepted: true,
                        families: vec![family],
                    })
                    .unwrap();
            }
        };
        let report = tokio::select! { result=run=>result.unwrap(), ()=respond=>unreachable!() };
        assert!(report.successful(), "{report:?}");
        assert_eq!(report.channels.len(), 2);
        assert!(
            report
                .channels
                .iter()
                .all(|c| c.accepted_bytes == 153600 && c.transfers.len() == 3)
        );
        for _ in 0..4 {
            assert_eq!(fixture.sni.recv().await.unwrap(), "hub.test");
        }
    }
}
