// src/outbounds/blackhole.rs
use super::Outbound;
use crate::config::BlackholeSettings;
use crate::error::Result;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tracing::info;

/// Implements the "blackhole" outbound protocol.
pub struct Blackhole {
    _settings: BlackholeSettings,
}

impl Blackhole {
    pub fn new(settings: BlackholeSettings) -> Self {
        Self {
            _settings: settings,
        }
    }
}

#[async_trait]
impl Outbound for Blackhole {
    async fn handle(
        &self,
        mut stream: BoxedStream,
        host: String,
        port: u16,
        _policy: std::sync::Arc<crate::config::LevelPolicy>,
    ) -> Result<()> {
        info!("Blackhole: Blocking connection to {}:{}", host, port);
        let mut buf = [0; 32];
        let _ = stream.read(&mut buf).await;
        Ok(())
    }

    async fn dial(&self, _host: String, _port: u16) -> Result<BoxedStream> {
        Err(anyhow::anyhow!("Blackhole: Dialing is not supported"))
    }
}
