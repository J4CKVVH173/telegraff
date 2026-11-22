use super::config::{NtfyConfig, read_token};
use crate::application::ports::Notifier;
use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::time::Duration;

pub struct Ntfy {
    client: reqwest::Client,
    endpoint: String,
    token: String,
}
impl Ntfy {
    pub fn new(config: &NtfyConfig) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            endpoint: config.endpoint.clone(),
            token: read_token(&config.token_file)?,
        })
    }
}
#[async_trait]
impl Notifier for Ntfy {
    async fn publish(&self, text: &str) -> Result<()> {
        let result = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .header("Title", "telegraff")
            .body(text.to_owned())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("ntfy request failed"))?;
        ensure!(result.status().is_success(), "ntfy rejected notification");
        Ok(())
    }
}
