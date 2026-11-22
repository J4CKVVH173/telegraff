use super::config::{NtfyConfig, read_token};
use crate::application::ports::Notifier;
use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::time::Duration;

pub struct Ntfy {
    client: reqwest::Client,
    endpoint: String,
    token: Option<String>,
}
impl Ntfy {
    pub fn new(config: &NtfyConfig) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            endpoint: config.endpoint.clone(),
            token: config.token_file.as_deref().map(read_token).transpose()?,
        })
    }
}
#[async_trait]
impl Notifier for Ntfy {
    async fn publish(&self, text: &str) -> Result<()> {
        let mut request = self.client.post(&self.endpoint);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let result = request
            .header("Title", "telegraff")
            .body(text.to_owned())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("ntfy request failed"))?;
        ensure!(result.status().is_success(), "ntfy rejected notification");
        Ok(())
    }
}
