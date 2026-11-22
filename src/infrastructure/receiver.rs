use super::{
    config::{AgentEntry, read_key},
    wire::{DATA, Frame, MAX_FRAME, PART},
};
use crate::{
    application::{Family, Protocol, Transfer},
    utils::unix_time,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, oneshot},
    time::timeout,
};

pub enum Incoming {
    Transfer(Transfer),
    Dns(String, crate::application::ports::DnsObservation),
}
pub struct Intake {
    pub event: Incoming,
    pub accepted: oneshot::Sender<IntakeReply>,
}
#[derive(Default)]
pub struct IntakeReply {
    pub accepted: bool,
    pub families: Vec<Family>,
}
#[derive(Clone)]
pub struct Credential {
    pub entry: AgentEntry,
    pub key: Vec<u8>,
    quota: Arc<Mutex<(u64, usize)>>,
}
pub type Registry = Arc<HashMap<String, Credential>>;
pub fn registry(entries: &[AgentEntry]) -> Result<Registry> {
    Ok(Arc::new(
        entries
            .iter()
            .map(|e| {
                Ok((
                    e.name.clone(),
                    Credential {
                        entry: e.clone(),
                        key: read_key(&e.key_file)?,
                        quota: Arc::new(Mutex::new((0, 0))),
                    },
                ))
            })
            .collect::<Result<_>>()?,
    ))
}
pub fn family(ip: IpAddr) -> Family {
    match ip {
        IpAddr::V4(_) => Family::Ipv4,
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => Family::Ipv4,
        _ => Family::Ipv6,
    }
}
pub fn bind_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from_std(socket.into())?)
}
pub fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}
pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    ensure!(
        (super::wire::HEADER + super::wire::TAG..=MAX_FRAME).contains(&len),
        "Invalid frame size"
    );
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
fn authenticate(
    bytes: &[u8],
    registry: &Registry,
    peer: SocketAddr,
    protocol: Protocol,
) -> Result<(Frame, Credential)> {
    let name = Frame::identity(bytes)?;
    let credential = registry
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Unknown agent"))?;
    let frame = Frame::decode(bytes, &credential.key)?;
    ensure!(
        (frame.kind == DATA || (frame.kind == super::wire::IDENTITY && protocol == Protocol::Tcp))
            && frame.channel.family == family(peer.ip())
            && frame.channel.protocol == protocol,
        "Invalid channel"
    );
    ensure!(
        frame.total as usize == credential.entry.payload_bytes
            && !credential.entry.paused
            && (credential.entry.grace == credential.entry.interval
                || credential.entry.policy().accepts(frame.cycle, unix_time())),
        "Invalid cycle or total"
    );
    {
        let mut quota = credential
            .quota
            .lock()
            .map_err(|_| anyhow::anyhow!("Rate limiter unavailable"))?;
        let quota_cycle = unix_time() / credential.entry.interval;
        if quota.0 != quota_cycle {
            *quota = (quota_cycle, 0);
        }
        quota.1 = quota.1.saturating_add(bytes.len());
        ensure!(
            quota.1 <= credential.entry.payload_bytes * 48,
            "Agent rate limit reached"
        );
    }
    Ok((frame, credential.clone()))
}
async fn submit(
    tx: &mpsc::Sender<Intake>,
    frame: &Frame,
    bytes: usize,
    elapsed: Duration,
    invalid: bool,
    fingerprint: String,
) -> bool {
    let (accepted, result) = oneshot::channel();
    let result_data = Transfer {
        agent: frame.agent.clone(),
        cycle: frame.cycle,
        channel: frame.channel,
        transfer: frame.transfer,
        bytes,
        duration_ms: elapsed.as_millis() as u64,
        invalid,
        fingerprint,
    };
    if tx
        .send(Intake {
            event: Incoming::Transfer(result_data),
            accepted,
        })
        .await
        .is_err()
    {
        return false;
    }
    result.await.unwrap_or_default().accepted
}
pub async fn tcp_loop(
    listener: TcpListener,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let registry = registry.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = timeout(Duration::from_secs(10), async {
                let start = Instant::now();
                let bytes = read_frame(&mut stream).await?;
                let (frame, c) = authenticate(&bytes, &registry, peer, Protocol::Tcp)?;
                if frame.kind == super::wire::IDENTITY {
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
                    tx.send(Intake {
                        event: Incoming::Dns(frame.agent.clone(), observation),
                        accepted,
                    })
                    .await?;
                    let reply = response.await?;
                    if reply.accepted {
                        let mut receipt = frame.receipt(0);
                        receipt.payload = reply
                            .families
                            .iter()
                            .map(|f| if *f == Family::Ipv4 { 4 } else { 6 })
                            .collect();
                        write_frame(&mut stream, &receipt.encode(&c.key)).await?;
                    }
                    return Ok::<_, anyhow::Error>(());
                }
                ensure!(
                    frame.part == 0
                        && frame.parts == 1
                        && frame.payload.len() == c.entry.payload_bytes,
                    "Incomplete TCP transfer"
                );
                if submit(
                    &tx,
                    &frame,
                    frame.payload.len(),
                    start.elapsed(),
                    false,
                    hex::encode(Sha256::digest(&frame.payload)),
                )
                .await
                {
                    write_frame(
                        &mut stream,
                        &frame.receipt(frame.payload.len()).encode(&c.key),
                    )
                    .await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
        });
    }
}

pub struct Assembly {
    pub frame: Frame,
    pub started: Instant,
    hashes: BTreeMap<u16, [u8; 32]>,
    pub bytes: usize,
    pub invalid: bool,
}
impl Assembly {
    pub fn new(frame: &Frame) -> Self {
        Self {
            frame: Frame {
                payload: Vec::new(),
                ..frame.clone()
            },
            started: Instant::now(),
            hashes: BTreeMap::new(),
            bytes: 0,
            invalid: false,
        }
    }
    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        for (part, digest) in &self.hashes {
            hash.update(part.to_be_bytes());
            hash.update(digest);
        }
        hex::encode(hash.finalize())
    }
    pub fn expired(&self) -> bool {
        self.started.elapsed() >= Duration::from_secs(120)
    }
    pub fn add(&mut self, f: &Frame) -> Result<bool> {
        ensure!(!self.expired(), "UDP assembly expired");
        let total = f.total as usize;
        let parts = total.div_ceil(PART);
        ensure!(
            parts == f.parts as usize && (f.part as usize) < parts && parts > 0,
            "Invalid UDP part"
        );
        let expected = (total - f.part as usize * PART).min(PART);
        ensure!(f.payload.len() == expected, "Invalid UDP part size");
        ensure!(
            f.total == self.frame.total && f.parts == self.frame.parts,
            "Conflicting transfer metadata"
        );
        let hash: [u8; 32] = Sha256::digest(&f.payload).into();
        if let Some(old) = self.hashes.get(&f.part) {
            if *old != hash {
                self.invalid = true;
            }
            return Ok(false);
        }
        self.hashes.insert(f.part, hash);
        self.bytes += f.payload.len();
        Ok(true)
    }
}

pub async fn udp_loop(
    socket: UdpSocket,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    max_assemblies: usize,
) -> Result<()> {
    let mut assemblies: HashMap<(String, u64, Family, u8), Assembly> = HashMap::new();
    let mut buffer = [0; 1233];
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    let mut quota: HashMap<String, (u64, usize)> = HashMap::new();
    let mut packet_window = (Instant::now(), 0usize);
    loop {
        tokio::select! {
            incoming = socket.recv_from(&mut buffer) => {
                let (n,peer) = incoming?;
                if packet_window.0.elapsed() >= Duration::from_secs(1) { packet_window = (Instant::now(),0); }
                packet_window.1 += 1;
                if n > 1232 || packet_window.1 > 50000 { continue; }
                let Ok((frame,c)) = authenticate(&buffer[..n],&registry,peer,Protocol::Udp) else { continue; };
                let quota_cycle = unix_time() / c.entry.interval;
                let q = quota.entry(frame.agent.clone()).or_insert((quota_cycle,0));
                if q.0 != quota_cycle { *q = (quota_cycle,0); }
                q.1 += n;
                if q.1 > c.entry.payload_bytes * 24 { continue; }
                let id = (frame.agent.clone(),frame.cycle,frame.channel.family,frame.transfer);
                if !assemblies.contains_key(&id) && assemblies.len() >= max_assemblies { continue; }
                let a = assemblies.entry(id).or_insert_with(|| Assembly::new(&frame));
                if a.expired() || a.add(&frame).is_err() { continue; }
                if a.invalid {
                    let _=submit(&tx,&frame,a.bytes,a.started.elapsed(),true,a.fingerprint()).await;
                    continue;
                }
                let passes = a.bytes * 100 >= c.entry.payload_bytes * usize::from(c.entry.udp_threshold);
                if passes || frame.part + 1 == frame.parts {
                    let accepted = submit(&tx,&frame,a.bytes,a.started.elapsed(),false,a.fingerprint()).await;
                    // Each valid new part can update intake, but only the last part solicits a receipt.
                    if accepted && frame.part + 1 == frame.parts {
                        let reply = frame.receipt(a.bytes).encode(&c.key);
                        let _ = socket.send_to(&reply,peer).await;
                    }
                }
            }
            _ = cleanup.tick() => {
                let now = unix_time();
                let expired: Vec<_> = assemblies.iter().filter(|(_,a)| a.expired() || registry.get(&a.frame.agent).is_none_or(|c| c.entry.paused || (c.entry.grace != c.entry.interval && !c.entry.policy().accepts(a.frame.cycle,now)))).map(|(k,_)| k.clone()).collect();
                for id in expired {
                    if let Some(a) = assemblies.remove(&id) && !a.invalid { let _ = submit(&tx,&a.frame,a.bytes,a.started.elapsed(),false,a.fingerprint()).await; }
                }
            }
        }
    }
}
