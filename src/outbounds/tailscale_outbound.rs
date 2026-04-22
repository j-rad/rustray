// src/outbounds/tailscale_outbound.rs
use super::Outbound;
use crate::config::{LevelPolicy, TailscaleSettings};
use crate::error::Result;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{info, warn};
use wgctrl::{Backend, Device};

pub struct TailscaleOutbound {
    #[allow(dead_code)]
    settings: TailscaleSettings,
}

impl TailscaleOutbound {
    pub fn new(settings: TailscaleSettings) -> Self {
        Self { settings }
    }
}

#[async_trait]
impl Outbound for TailscaleOutbound {
    async fn handle(
        &self,
        mut stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        // Tailscale routing relies on the OS routing table for the "tailscale0" interface.
        // Usually, if Tailscale is up, we just connect() to the MagicDNS name or IP.

        info!("Tailscale: Routing to {}", host);

        // 1. Check if Tailscale interface exists (using wgctrl as a proxy for checking status)
        // This is a lightweight check.
        #[cfg(target_os = "linux")]
        match Device::get(&"tailscale0".parse().unwrap(), Backend::Kernel) {
            Ok(_) => {}
            Err(e) => warn!("Tailscale: Could not find 'tailscale0' interface: {}", e),
        };

        // 2. Connect directly
        // If the host is a MagicDNS name (e.g., "monitoring"), the OS DNS resolver
        // (which Tailscale manages) should resolve it to a 100.x.y.z IP.
        // The OS routing table then routes it via tailscale0.

        let addr = format!("{}:{}", host, port);
        let mut out_stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| anyhow::anyhow!("Tailscale connect failed: {}", e))?;

        info!("Tailscale: Connected to {}", addr);

        // 3. Pipe
        tokio::io::copy_bidirectional(&mut stream, &mut out_stream).await?;
        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let addr = format!("{}:{}", host, port);
        let out_stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| anyhow::anyhow!("Tailscale connect failed: {}", e))?;
        Ok(Box::new(out_stream) as BoxedStream)
    }
}
