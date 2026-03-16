// src/protocols/http_proxy.rs
use crate::app::dns::DnsServer;
use crate::app::stats::StatsManager;
use crate::config::LevelPolicy;
use crate::config::{HttpProxyOutboundSettings, HttpProxySettings};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

// --- INBOUND ---
pub async fn listen_stream(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    mut stream: BoxedStream,
    _settings: HttpProxySettings,
    source: String,
) -> Result<()> {
    // 1. Peek at the stream to read the HTTP Method
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?; // Note: This consumes bytes, we need to be careful if we fail

    // Simple parser for "CONNECT host:port HTTP/1.1"
    let request_str = String::from_utf8_lossy(&buf[..n]);

    if request_str.starts_with("CONNECT ") {
        let parts: Vec<&str> = request_str.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow::anyhow!("Invalid HTTP CONNECT request"));
        }
        let target = parts[1]; // "host:port"

        let (host, port_str) = target
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid target format"))?;
        let port: u16 = port_str.parse()?;

        // 2. Send 200 OK
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;

        // 3. Route
        let policy = state.policy_manager.get_policy(0); // Default policy
        debug!("HTTP Proxy: Routing to {}:{}", host, port);

        // Note: `stream` has already been read from. If the client sent data *with* the CONNECT,
        // it's in `buf`. In a robust impl, we'd need to chain `buf[header_len..n]` back onto the stream.
        // For standard HTTP proxy clients, they wait for 200 OK before sending data.

        router
            .route_stream(stream, host.to_string(), port, source, policy)
            .await
    } else {
        // Handle standard HTTP proxying (GET http://...)
        // For now, we only support CONNECT (HTTPS tunneling)
        Err(anyhow::anyhow!("Only CONNECT method is supported"))
    }
}

// --- OUTBOUND ---
pub struct HttpOutbound {
    settings: HttpProxyOutboundSettings,
    dns: Arc<DnsServer>,
    #[allow(dead_code)]
    stats: Arc<StatsManager>,
    #[allow(dead_code)]
    tag: String,
}

impl HttpOutbound {
    pub fn new(
        settings: HttpProxyOutboundSettings,
        dns: Arc<DnsServer>,
        stats: Arc<StatsManager>,
        tag: String,
    ) -> Self {
        Self {
            settings,
            dns,
            stats,
            tag,
        }
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;

        // 4. Bridge
        let operation = tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream);
        match tokio::time::timeout(
            Duration::from_secs(policy.conn_idle.unwrap_or(300) as u64),
            operation,
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Idle timeout")),
        }
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let proxy_addr = format!("{}:{}", self.settings.address, self.settings.port);
        debug!(
            "HTTP Proxy: Connecting to proxy at {} for {}:{}",
            proxy_addr, host, port
        );

        // 1. Connect to the Proxy Server
        let addrs = self.dns.resolve_ip(&self.settings.address).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("Proxy IP not found"));
        }
        let remote_addr = std::net::SocketAddr::new(addrs[0], self.settings.port);

        let mut out_stream = tokio::net::TcpStream::connect(remote_addr).await?;

        // 2. Send CONNECT Request
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            host, port, host, port
        );
        out_stream.write_all(connect_req.as_bytes()).await?;

        // 3. Read Response
        let mut buf = [0u8; 1024];
        let n = out_stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if response.contains("200 OK") {
            debug!("HTTP Proxy: Tunnel established to {}:{}", host, port);
            Ok(Box::new(out_stream) as BoxedStream)
        } else {
            Err(anyhow::anyhow!("Proxy rejected connection: {}", response))
        }
    }
}
