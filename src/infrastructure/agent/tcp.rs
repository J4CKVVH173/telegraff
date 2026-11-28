use super::*;

impl SocketTransport {
    pub(super) async fn exchange(&self, address: SocketAddr, frame: &Frame) -> Result<Vec<u8>> {
        if let Some(https) = &self.https {
            https.exchange(address, &frame.encode(&self.key)).await
        } else {
            let mut socket = TcpStream::connect(address).await?;
            write_frame(&mut socket, &frame.encode(&self.key)).await?;
            read_frame(&mut socket).await
        }
    }
}
pub(super) struct Https {
    pub(super) host: String,
    pub(super) certificates: Vec<reqwest::Certificate>,
}
impl Https {
    async fn exchange(&self, address: SocketAddr, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut url = reqwest::Url::parse("https://localhost/telegraff")?;
        url.set_host(Some(&self.host))
            .context("Invalid hub hostname")?;
        url.set_port(Some(address.port()))
            .map_err(|_| anyhow::anyhow!("Invalid HTTPS port"))?;
        // Pin the exact family/address selected by the monitoring application;
        // retain the DNS hostname in the URL for Host, SNI and certificate checks.
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&self.host, &[address])
            .timeout(Duration::from_secs(10));
        for certificate in &self.certificates {
            builder = builder.add_root_certificate(certificate.clone());
        }
        let mut response = builder
            .build()?
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "HTTPS connection or certificate verification failed: {}",
                    error_chain(&e)
                )
            })?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "Unexpected HTTPS status: {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= crate::infrastructure::wire::MAX_FRAME,
                "HTTPS receipt too large"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
