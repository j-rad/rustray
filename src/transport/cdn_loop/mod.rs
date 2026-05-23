// src/transport/cdn_loop/mod.rs
//! CDN-Loop Adapter (Method 4)
//!
//! Exploits Iran-domestic CDN providers (ArvanCloud, Parspack) whose NIN-priority
//! routing treats traffic to their edge as first-class domestic bandwidth.
//!
//! Architecture:
//!   Client  ──▶  Iran Entry VPS  ──(TLS 1.3 + WS upgrade)──▶  CDN Edge  ──▶  Germany VPS
//!
//! The CDN edge sees a legitimate cached WebSocket connection to a hosted domain.
//! The Germany VPS runs REALITY V2 to mirror a whitelisted global site (samsung.com),
//! so even if the CDN inspects the onward connection, it looks like a cache-fill.
//!
//! `spawn_chaff_requests()` injects non-functional HTTP GETs at Gaussian-random
//! intervals (30–120s) to break the 1:1 upload/download symmetry fingerprint.

use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TransportStats, TrinityTransport};
use bytes::{BufMut, BytesMut};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use rand_distr::{Distribution, Normal};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};

// ─── Configuration ────────────────────────────────────────────────────────────

/// CDN-Loop adapter configuration, parsed from JSON `streamSettings`.
#[derive(Debug, Clone)]
pub struct CdnLoopConfig {
    /// Iran-based entry VPS address (e.g. "185.x.x.x:443").
    pub entry_addr: String,
    /// Domain hosted on ArvanCloud/Parspack CDN for fronting.
    pub cdn_domain: String,
    /// WebSocket upgrade path.
    pub ws_path: String,
    /// Optional: SNI for the TLS handshake (defaults to cdn_domain).
    pub sni: Option<String>,
    /// Enable chaff requests (statistical noise generator).
    pub chaff_enabled: bool,
    /// Chaff mean interval in seconds (default 75).
    pub chaff_mean_interval_secs: f64,
    /// Chaff stddev in seconds (default 20).
    pub chaff_stddev_secs: f64,
    /// Fake resource paths for chaff (e.g. ["/assets/bg.png", "/css/main.css"]).
    pub chaff_paths: Vec<String>,
}

impl Default for CdnLoopConfig {
    fn default() -> Self {
        Self {
            entry_addr: String::new(),
            cdn_domain: String::new(),
            ws_path: "/ws".to_string(),
            sni: None,
            chaff_enabled: true,
            chaff_mean_interval_secs: 75.0,
            chaff_stddev_secs: 20.0,
            chaff_paths: vec![
                "/assets/hero-bg.png".to_string(),
                "/css/bootstrap.min.css".to_string(),
                "/js/analytics.js".to_string(),
                "/images/logo-2x.webp".to_string(),
                "/fonts/vazir-regular.woff2".to_string(),
            ],
        }
    }
}

// ─── CDN-Loop Adapter ─────────────────────────────────────────────────────────

/// A TAL-compatible transport that wraps VLESS traffic inside a CDN WebSocket.
///
/// After construction, the adapter has completed the HTTP Upgrade handshake
/// and the inner stream is a raw bidirectional byte pipe through the CDN.
pub struct CdnLoopAdapter {
    /// The established WebSocket stream through the CDN.
    inner: BoxedTrinityTransport,
    /// Configuration snapshot for chaff and reconnection.
    config: CdnLoopConfig,
    /// Tracks total bytes for statistics.
    bytes_sent: u64,
    bytes_received: u64,
    /// Flag to signal chaff shutdown.
    chaff_running: Arc<AtomicBool>,
}

impl CdnLoopAdapter {
    /// Dial through the CDN loop.
    ///
    /// 1. TCP connect to `entry_addr`.
    /// 2. TLS 1.3 handshake with SNI = `cdn_domain`.
    /// 3. WebSocket HTTP Upgrade through the CDN edge.
    /// 4. Optionally spawn chaff request generator.
    pub async fn connect(config: CdnLoopConfig) -> Result<Self> {
        debug!(
            "CDN-Loop: connecting to entry={} via cdn={}",
            config.entry_addr, config.cdn_domain
        );

        // Step 1: TCP connect to the Iran entry VPS.
        let tcp_stream = TcpStream::connect(&config.entry_addr).await?;

        // Step 2: TLS 1.3 handshake with CDN domain as SNI.
        let sni = config.sni.as_deref().unwrap_or(&config.cdn_domain);
        let tls_stream = crate::transport::tls::wrap_tls_client_simple(
            Box::new(tcp_stream) as BoxedTrinityTransport,
            sni,
        )
        .await?;

        // Step 3: WebSocket HTTP Upgrade handshake.
        let ws_stream = Self::do_ws_upgrade(tls_stream, &config).await?;

        debug!("CDN-Loop: WebSocket tunnel established");

        let chaff_running = Arc::new(AtomicBool::new(false));

        let mut adapter = Self {
            inner: ws_stream,
            config: config.clone(),
            bytes_sent: 0,
            bytes_received: 0,
            chaff_running: chaff_running.clone(),
        };

        // Step 4: Spawn chaff if enabled.
        if config.chaff_enabled {
            adapter.chaff_running.store(true, Ordering::Release);
            spawn_chaff_requests(config, chaff_running);
        }

        Ok(adapter)
    }

    /// Perform the WebSocket HTTP Upgrade handshake over the TLS stream.
    async fn do_ws_upgrade(
        mut stream: BoxedTrinityTransport,
        config: &CdnLoopConfig,
    ) -> Result<BoxedTrinityTransport> {
        // Generate a random WebSocket key (RFC 6455).
        let ws_key = {
            let mut key_bytes = [0u8; 16];
            SmallRng::from_entropy().fill(&mut key_bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_bytes)
        };

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Origin: https://{}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             \r\n",
            config.ws_path, config.cdn_domain, ws_key, config.cdn_domain,
        );

        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        // Read the HTTP response.
        let mut response_buf = BytesMut::with_capacity(2048);
        let mut temp = [0u8; 512];

        loop {
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut temp).await?;
            if n == 0 {
                return Err(anyhow::anyhow!(
                    "CDN-Loop: connection closed during WS upgrade"
                ));
            }
            response_buf.extend_from_slice(&temp[..n]);

            if response_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if response_buf.len() > 8192 {
                return Err(anyhow::anyhow!(
                    "CDN-Loop: WS upgrade response too large"
                ));
            }
        }

        let response_str = String::from_utf8_lossy(&response_buf);
        if response_str.contains("101") {
            debug!("CDN-Loop: WS upgrade succeeded (101 Switching Protocols)");
            Ok(stream)
        } else {
            Err(anyhow::anyhow!(
                "CDN-Loop: WS upgrade failed: {}",
                response_str.lines().next().unwrap_or("empty response")
            ))
        }
    }
}

impl Drop for CdnLoopAdapter {
    fn drop(&mut self) {
        // Signal chaff task to stop.
        self.chaff_running.store(false, Ordering::Release);
    }
}

// ─── TrinityTransport impl ───────────────────────────────────────────────────

impl TrinityTransport for CdnLoopAdapter {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner = new_carrier;
        debug!("CDN-Loop: carrier hot-swapped");
        Ok(())
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn handover(mut self, new_carrier: BoxedTrinityTransport) -> Result<Self> {
        self.inner = new_carrier;
        Ok(self)
    }

    fn get_transport_info(&self) -> TransportStats {
        TransportStats {
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            ..Default::default()
        }
    }
}

impl AsyncRead for CdnLoopAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = (buf.filled().len() - before) as u64;
            self.bytes_received = self.bytes_received.wrapping_add(read);
        }
        result
    }
}

impl AsyncWrite for CdnLoopAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.bytes_sent = self.bytes_sent.wrapping_add(*n as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// ─── Statistical Noise Generator ──────────────────────────────────────────────

/// Spawn a background task that performs non-functional HTTP GET requests at
/// Gaussian-random intervals (mean=75s, σ=20s, clamped to 30–120s).
///
/// These chaff requests are for `.png`, `.css`, `.js` resources that don't exist
/// on the CDN. The CDN returns a small 404, but the ISP's Asymmetric Volume
/// Analysis AI sees outbound requests without matching inbound downloads,
/// classifying the flow as "Human Browsing" rather than a steady proxy stream.
pub fn spawn_chaff_requests(config: CdnLoopConfig, running: Arc<AtomicBool>) {
    tokio::spawn(async move {
        debug!("CDN-Loop: chaff generator started");

        // Gaussian distribution: mean=75s, sigma=20s, clamped to [30, 120].
        let normal = Normal::new(
            config.chaff_mean_interval_secs,
            config.chaff_stddev_secs,
        )
        .unwrap_or_else(|_| Normal::new(75.0, 20.0).unwrap());

        let mut rng = SmallRng::from_entropy();

        while running.load(Ordering::Acquire) {
            // Sample next interval from Gaussian, clamp to [30, 120].
            let raw_interval: f64 = normal.sample(&mut rng);
            let interval_secs = raw_interval.clamp(30.0, 120.0);

            tokio::time::sleep(tokio::time::Duration::from_secs_f64(interval_secs)).await;

            if !running.load(Ordering::Acquire) {
                break;
            }

            // Pick a random chaff path.
            let path_idx = rng.r#gen_range(0..config.chaff_paths.len().max(1));
            let path = config
                .chaff_paths
                .get(path_idx)
                .cloned()
                .unwrap_or_else(|| "/assets/placeholder.png".to_string());

            // Fire and forget: connect, send GET, ignore response.
            let addr = config.entry_addr.clone();
            let host = config.cdn_domain.clone();
            tokio::spawn(async move {
                match TcpStream::connect(&addr).await {
                    Ok(mut tcp) => {
                        let req = format!(
                            "GET {} HTTP/1.1\r\n\
                             Host: {}\r\n\
                             Accept: */*\r\n\
                             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
                             Connection: close\r\n\
                             \r\n",
                            path, host
                        );
                        let _ = tcp.write_all(req.as_bytes()).await;
                        let _ = tcp.flush().await;
                        // Read a bit of the response to make it look realistic,
                        // but don't care about the content.
                        let mut discard = [0u8; 512];
                        let _ = tokio::io::AsyncReadExt::read(&mut tcp, &mut discard).await;
                        trace!(
                            "CDN-Loop: chaff GET {} complete (interval={:.1}s)",
                            path,
                            0.0f64  // we don't track this here
                        );
                    }
                    Err(e) => {
                        warn!("CDN-Loop: chaff request failed to connect: {}", e);
                    }
                }
            });
        }

        debug!("CDN-Loop: chaff generator stopped");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdn_loop_config_defaults() {
        let config = CdnLoopConfig::default();
        assert!(config.chaff_enabled);
        assert!(!config.chaff_paths.is_empty());
        assert_eq!(config.ws_path, "/ws");
    }
}
