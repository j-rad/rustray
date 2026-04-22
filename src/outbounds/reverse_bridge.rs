// src/outbounds/reverse_bridge.rs
use super::Outbound;
use crate::app::reverse::ReverseManager;
use crate::config::{LevelPolicy, ReverseBridgeSettings};
use crate::error::Result;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use std::sync::Arc;

pub struct ReverseBridge {
    settings: ReverseBridgeSettings,
    reverse_manager: Arc<ReverseManager>,
}

impl ReverseBridge {
    pub fn new(settings: ReverseBridgeSettings, reverse_manager: Arc<ReverseManager>) -> Self {
        Self {
            settings,
            reverse_manager,
        }
    }
}

#[async_trait]
impl Outbound for ReverseBridge {
    async fn handle(
        &self,
        mut stream: BoxedStream,
        _host: String,
        _port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut portal_stream = self
            .reverse_manager
            .send_to_portal(
                &self.settings.tag,
                Box::new(tokio::io::empty()) as BoxedStream,
            )
            .await?;
        crate::transport::copy_bidirectional(&mut stream, &mut portal_stream).await?;
        Ok(())
    }
    async fn dial(&self, _host: String, _port: u16) -> Result<BoxedStream> {
        Err(anyhow::anyhow!("ReverseBridge: Dialing is not supported"))
    }
}
