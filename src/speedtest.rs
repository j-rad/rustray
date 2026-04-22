use crate::app::dns::DnsServer;
use crate::config::{RealityClientConfig, StreamSettings, TlsSettings, WebSocketConfig};
use crate::error::Result;
use crate::transport;
use crate::types::ServerConfig;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpeedTestResults {
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub download_speed_mbps: f64,
}

pub struct SpeedTestEngine {
    dns: Arc<DnsServer>,
}

impl SpeedTestEngine {
    pub fn new(dns: Arc<DnsServer>) -> Self {
        Self { dns }
    }

    pub async fn run_comprehensive_test(&self, server: &ServerConfig) -> Result<SpeedTestResults> {
        let stream_settings = server_config_to_stream_settings(server);

        // 1. Latency & Jitter Test
        let (latency, jitter) = self
            .measure_latency_and_jitter(&stream_settings, server)
            .await?;

        // 2. Burst Throughput Test
        // Only run if latency check succeeded
        let download_speed = self
            .measure_burst_throughput(&stream_settings, server)
            .await
            .unwrap_or(0.0);

        Ok(SpeedTestResults {
            latency_ms: latency,
            jitter_ms: jitter,
            download_speed_mbps: download_speed,
        })
    }

    async fn measure_latency_and_jitter(
        &self,
        settings: &StreamSettings,
        server: &ServerConfig,
    ) -> Result<(f64, f64)> {
        let mut samples = Vec::with_capacity(5);

        // Take 5 samples
        for _ in 0..5 {
            let start = Instant::now();
            let mut stream =
                transport::connect(settings, self.dns.clone(), &server.address, server.port)
                    .await?;

            // Simple ping: write 1 byte and flush
            stream.write_all(&[0u8]).await?;
            stream.flush().await?;

            // For full RTT, we'd ideally read back, but many proxies don't echo.
            // Handshake time is the most critical metric for "responsiveness" in censorship contexts.
            // So we measure connection + handshake time.

            let rtt = start.elapsed().as_secs_f64() * 1000.0;
            samples.push(rtt);

            // Small sleep between samples
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let sum: f64 = samples.iter().sum();
        let avg = sum / samples.len() as f64;

        // Calculate Jitter (Standard Deviation)
        let variance = samples
            .iter()
            .map(|value| {
                let diff = avg - *value;
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;

        let jitter = variance.sqrt();

        Ok((avg, jitter))
    }

    async fn measure_burst_throughput(
        &self,
        settings: &StreamSettings,
        server: &ServerConfig,
    ) -> Result<f64> {
        // Implement a 1MB "burst" download or time-limited test
        // Connect and request a large file (or just read stream if it was a real internet test)
        // Since we are testing Proxy connectivity, we need a target.
        // Usually speedtests connect to the proxy, then request a URL through it.

        let _target_url = "http://speedtest.google.com/Generate_204"; // Lightweight target
        // For actual throughput, we might need a larger payload.
        // Let's assume we request a small dummy file from a CDN if possible,
        // or just measure read speed of "garbage" if talking to a specialized server.

        // LIMITATION: Without a known large file URL, strictly measuring throughput is hard
        // unless we use the proxy to fetch something.
        // Let's assume we fetch a 1MB test file from a common CDN.
        let _test_file_url = "http://speed.cloudflare.com/__down?bytes=1000000";

        let start = Instant::now();

        // We need to construct a HTTP request over the transport stream manually
        // because our transport returns `AsyncRead + AsyncWrite`, not a reqwest client directly.
        // A minimal HTTP 1.1 GET request is easy to construct.

        let mut stream =
            transport::connect(settings, self.dns.clone(), &server.address, server.port).await?;

        let request = "GET /__down?bytes=1000000 HTTP/1.1\r\n\
             Host: speed.cloudflare.com\r\n\
             User-Agent: RustRay-SpeedTest\r\n\
             Connection: close\r\n\
             \r\n".to_string();

        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut total_bytes = 0;
        let mut buf = [0u8; 8192];
        let mut first_chunk = true;

        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            total_bytes += n;

            // Check speed after first chunk or small intervals to auto-terminate
            if first_chunk {
                // If extremely slow to get first byte (TTFB), we could abort.
                first_chunk = false;
            }

            // Safety timeout 5s
            if start.elapsed().as_secs() > 5 {
                break;
            }

            // Auto termination check: < 32KB downloaded after 2 seconds (~128kbps)
            if start.elapsed().as_secs() >= 2 && total_bytes < 32_000 {
                return Ok(0.0); // Too slow, treat as 0
            }
        }

        let duration = start.elapsed().as_secs_f64();
        if duration == 0.0 {
            return Ok(0.0);
        }

        let bits = total_bytes as f64 * 8.0;
        let mbps = (bits / duration) / 1_000_000.0;

        Ok(mbps)
    }
}

/// Helper for standalone simple tests (legacy support)
pub async fn run_speed_test(server: &ServerConfig) -> Result<f64> {
    let dns_config = crate::config::DnsConfig {
        servers: Some(vec!["8.8.8.8".to_string()]),
        auto_detect_system_dns: None,
        fakedns: None,
        hosts: None,
    };
    let dns = Arc::new(DnsServer::new(dns_config)?);
    let engine = SpeedTestEngine::new(dns);

    let res = engine.run_comprehensive_test(server).await?;
    Ok(res.latency_ms)
}

/// Convert ServerConfig to internal StreamSettings
fn server_config_to_stream_settings(server: &ServerConfig) -> StreamSettings {
    let mut settings = StreamSettings::default();

    // Network type (tcp, ws, grpc, kcp, etc.)
    if let Some(network) = &server.network {
        settings.network = network.clone();
    }

    // Security (tls, reality, none)
    if let Some(security) = &server.security {
        settings.security = security.clone();

        match security.as_str() {
            "tls" => {
                let mut tls = TlsSettings::default();
                tls.server_name = server.sni.clone();
                tls.fingerprint = server.fingerprint.clone();
                tls.allow_insecure = server.allow_insecure;
                settings.tls_settings = Some(tls);
            }
            "reality" => {
                if let (Some(sni), Some(pbk), Some(sid)) = (&server.sni, &server.pbk, &server.sid) {
                    let reality = RealityClientConfig {
                        show: true,
                        fingerprint: server
                            .fingerprint
                            .clone()
                            .unwrap_or_else(|| "chrome".to_string()),
                        server_name: sni.clone(),
                        public_key: pbk.clone(),
                        short_id: sid.clone(),
                        spider_x: None,
                    };
                    settings.reality_settings = Some(reality);
                }
            }
            _ => {}
        }
    }

    // WebSocket settings
    if settings.network == "ws" {
        let mut ws = WebSocketConfig::default();
        ws.path = server.path.clone().unwrap_or_else(|| "/".to_string());
        ws.host = server.host.clone();
        settings.ws_settings = Some(ws);
    }

    // Config mappings for other transports (grpc, etc) needed if testing them directly
    // Assuming defaults or mapped similarly for now

    settings
}
