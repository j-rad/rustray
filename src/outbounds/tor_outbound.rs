// src/outbounds/tor_outbound.rs
use super::Outbound;
use crate::config::{LevelPolicy, TorOutboundSettings};
use crate::error::Result;
use crate::transport::BoxedStream;
use arti_client::DataStream;
use arti_client::{TorClient, TorClientConfig};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tracing::{info, warn};

pub struct TorOutbound {
    #[allow(dead_code)]
    settings: TorOutboundSettings,
    client: Option<TorClient<tor_rtcompat::PreferredRuntime>>,
}

impl TorOutbound {
    pub fn new(settings: TorOutboundSettings) -> Self {
        // Initialize Tor Client
        // Note: Bootstrapping Tor takes time. Ideally this is done in a background task
        // and we wait for it, or we lazily connect.
        // Here we setup the builder but don't block `new`.

        let _config = TorClientConfig::default();
        let client = match TorClient::builder().create_unbootstrapped() {
            Ok(c) => Some(c),
            Err(e) => {
                // This blocks! In real app, do this async.
                // For now, we just log the error and will fail on handle.
                warn!(
                    "Tor: Failed to create client (will retry on connection): {}",
                    e
                );
                None
            }
        };

        Self { settings, client }
    }
}

#[async_trait]
impl Outbound for TorOutbound {
    async fn handle(
        &self,
        mut stream: BoxedStream,
        host: String,
        port: u16,
        policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        info!("Tor: Routing connection to {}:{}", host, port);

        // 1. Get or Create Client
        // Since `create_bootstrapped` is blocking/heavy, we assume it succeeded in `new`
        // or we would need an async mutex to init it here.
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Tor client not initialized"))?;

        // 2. Connect through Tor
        let target = format!("{}:{}", host, port);
        let mut tor_stream: DataStream = client
            .connect((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("Tor connect failed: {}", e))?;

        info!("Tor: Circuit established to {}", target);

        // 3. Pipe Data
        let operation = io::copy_bidirectional(&mut stream, &mut tor_stream);
        let idle_timeout = Duration::from_secs(policy.conn_idle.unwrap_or(300) as u64);

        match tokio::time::timeout(idle_timeout, operation).await {
            Ok(Ok((up, down))) => {
                info!("Tor: Connection closed. Up: {}, Down: {}", up, down);
                Ok(())
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Idle timeout")),
        }
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Tor client not initialized"))?;
        let tor_stream = client
            .connect((host.as_str(), port))
            .await
            .map_err(|e| anyhow::anyhow!("Tor connect failed: {}", e))?;
        Ok(Box::new(tor_stream) as BoxedStream)
    }
}
