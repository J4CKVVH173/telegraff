use super::*;

pub async fn udp_loop(
    socket: UdpSocket,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    max_assemblies: usize,
) -> Result<()> {
    udp_loop_guarded(
        socket,
        registry,
        tx,
        max_assemblies,
        Guard::new(Limits::default(), max_assemblies),
    )
    .await
}
pub async fn udp_loop_guarded(
    socket: UdpSocket,
    registry: Registry,
    tx: mpsc::Sender<Intake>,
    max_assemblies: usize,
    guard: Arc<Guard>,
) -> Result<()> {
    let mut assemblies: HashMap<(String, u64, Family, u8), Assembly> = HashMap::new();
    let mut buffer = [0; 1233];
    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    let mut quota: HashMap<String, (u64, usize)> = HashMap::new();

    loop {
        tokio::select! {
            incoming = socket.recv_from(&mut buffer) => {
                let (n,peer) = incoming?;
                if !guard.udp(peer.ip()) { continue; }
                if n > 1232 { guard.reject(Rejection::Oversize); continue; }
                let (frame,c) = match authenticate(&buffer[..n],&registry,peer,Protocol::Udp,false) {
                    Ok(result) => result,
                    Err(error) => { rejected(&guard, &error); continue; }
                };
                let quota_cycle = unix_time() / c.entry.interval;
                let q = quota.entry(frame.agent.clone()).or_insert((quota_cycle,0));
                if q.0 != quota_cycle { *q = (quota_cycle,0); }
                q.1 += n;
                if q.1 > c.entry.payload_bytes * 24 { guard.reject(Rejection::AgentQuota); continue; }
                let id = (frame.agent.clone(),frame.cycle,frame.channel.family,frame.transfer);
                if !assemblies.contains_key(&id) {
                    if assemblies.len() >= max_assemblies { guard.reject(Rejection::Assemblies); continue; }
                    let Ok(global) = guard.assemblies.clone().try_acquire_owned() else { guard.reject(Rejection::Assemblies); continue; };
                    let Ok(agent) = c.assemblies.clone().try_acquire_owned() else { guard.reject(Rejection::AgentQuota); continue; };
                    let mut assembly = Assembly::new(&frame);
                    assembly.permits = Some((global, agent));
                    assemblies.insert(id.clone(), assembly);
                }
                let a = assemblies.get_mut(&id).unwrap();
                if a.expired() || a.add(&frame).is_err() { guard.reject(Rejection::Authentication); continue; }
                if a.invalid {
                    let _=submit(&tx,&guard,&frame,a.bytes,a.started.elapsed(),true,a.fingerprint()).await;
                    continue;
                }
                let passes = crate::application::confirmation::passes(Protocol::Udp, a.bytes, c.entry.payload_bytes, c.entry.udp_threshold);
                if passes || frame.part + 1 == frame.parts {
                    let accepted = submit(&tx,&guard,&frame,a.bytes,a.started.elapsed(),false,a.fingerprint()).await;
                    // Each valid new part can update intake, but only the last part solicits a receipt.
                    if let Some(confirmation) = accepted && frame.part + 1 == frame.parts {
                        let reply = Frame::from_confirmation(confirmation).encode(&c.key);
                        let _ = socket.send_to(&reply,peer).await;
                    }
                }
            }
            _ = cleanup.tick() => {
                let now = unix_time();
                let expired: Vec<_> = assemblies.iter().filter(|(_,a)| a.expired() || registry.get(&a.frame.agent).is_none_or(|c| c.entry.paused || (c.entry.grace != c.entry.interval && !c.entry.policy().accepts(a.frame.cycle,now)))).map(|(k,_)| k.clone()).collect();
                for id in expired {
                    if let Some(a) = assemblies.remove(&id) && !a.invalid { let _ = submit(&tx,&guard,&a.frame,a.bytes,a.started.elapsed(),false,a.fingerprint()).await; }
                }
            }
        }
    }
}
