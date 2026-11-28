use super::*;

pub async fn tcp_loop(
    listener: TcpListener,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    tcp_loop_with_tls(listener, registry, tx, permits, None).await
}
trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}
pub async fn tcp_loop_with_tls(
    listener: TcpListener,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    permits: Arc<Semaphore>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    tcp_loop_guarded(
        listener,
        registry,
        tx,
        permits,
        tls,
        Guard::new(Limits::default(), 256),
    )
    .await
}
pub async fn tcp_loop_guarded(
    listener: TcpListener,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    permits: Arc<Semaphore>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    guard: Arc<Guard>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(connection) = guard.tcp(peer.ip()) else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            guard.reject(Rejection::Connections);
            continue;
        };
        let registry = registry.clone();
        let tx = tx.clone();
        let tls = tls.clone();
        let guard = guard.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _connection = connection;
            let result = timeout(Duration::from_secs(10), async {
                let start = Instant::now();
                // Handshake shares the bounded request deadline and connection permit.
                let mut stream: Box<dyn Connection> = if let Some(tls) = tls {
                    Box::new(tls.accept(stream).await?)
                } else {
                    Box::new(stream)
                };
                let (bytes, http) = crate::infrastructure::http::read_request(&mut stream).await?;
                let (frame, c) = authenticate(&bytes, &registry, peer, Protocol::Tcp, http)?;
                let _agent_connection = c
                    .connections
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| anyhow::anyhow!(AgentLimit))?;
                if frame.kind == crate::infrastructure::wire::IDENTITY {
                    ensure!(frame.payload.len() <= 512, "Invalid identity report");
                    let observation: crate::application::ports::DnsObservation =
                        serde_json::from_slice(&frame.payload)?;
                    ensure!(
                        observation.signature.len() == 64
                            && observation.signature.bytes().all(|b| b.is_ascii_hexdigit())
                            && observation.ipv4_records <= 1024
                            && observation.ipv6_records <= 1024,
                        "Invalid DNS observation"
                    );
                    let (accepted, response) = oneshot::channel();
                    tx.try_send(Intake {
                        event: Incoming::Dns(frame.agent.clone(), observation),
                        accepted,
                    })
                    .map_err(|_| anyhow::anyhow!(QueueFull))?;
                    let reply = response.await?;
                    if reply.accepted {
                        let mut receipt = frame.receipt(0);
                        receipt.payload = reply
                            .families
                            .iter()
                            .map(|f| if *f == Family::Ipv4 { 4 } else { 6 })
                            .collect();
                        crate::infrastructure::http::write_response(
                            &mut stream,
                            &receipt.encode(&c.key),
                            http,
                        )
                        .await?;
                    }
                    return Ok::<_, anyhow::Error>(());
                }
                ensure!(
                    frame.part == 0
                        && frame.parts == 1
                        && frame.payload.len() == c.entry.payload_bytes,
                    "Incomplete TCP transfer"
                );
                if let Some(confirmation) = submit(
                    &tx,
                    &guard,
                    &frame,
                    frame.payload.len(),
                    start.elapsed(),
                    false,
                    hex::encode(Sha256::digest(&frame.payload)),
                )
                .await
                {
                    crate::infrastructure::http::write_response(
                        &mut stream,
                        &Frame::from_confirmation(confirmation).encode(&c.key),
                        http,
                    )
                    .await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
            match result {
                Ok(Err(error)) => rejected(&guard, &error),
                Err(_) => guard.reject(Rejection::Timeout),
                _ => {}
            }
        });
    }
}
