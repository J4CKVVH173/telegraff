use super::*;

pub(super) async fn udp(
    address: SocketAddr,
    template: &Frame,
    key: &[u8],
    rate: u64,
    next: &mut Instant,
) -> Result<crate::application::confirmation::Confirmation> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(address).await?;
    let parts = template.payload.len().div_ceil(PART) as u16;
    for (part, payload) in template.payload.chunks(PART).enumerate() {
        sleep_until(*next).await;
        let frame = Frame {
            part: part as u16,
            parts,
            payload: payload.to_vec(),
            ..template.clone()
        };
        socket.send(&frame.encode(key)).await?;
        *next = Instant::now() + Duration::from_secs_f64(payload.len() as f64 / rate as f64);
    }
    let mut bytes = [0; 1232];
    let n = timeout(Duration::from_secs(1), socket.recv(&mut bytes)).await??;
    Frame::decode(&bytes[..n], key)?.into_confirmation()
}
