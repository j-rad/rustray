// src/protocols/naive.rs
use crate::app::dns::DnsServer;
use crate::app::stats::StatsManager;
use crate::config::LevelPolicy;
use crate::config::{NaiveOutboundSettings, NaiveSettings};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::client::conn::http2;
use hyper::{Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::info;

// --- INBOUND ---
pub async fn listen_stream(
    _router: Arc<Router>,
    _state: Arc<StatsManager>,
    _stream: BoxedStream,
    _settings: NaiveSettings,
) -> Result<()> {
    info!("Naive: Handling inbound stream (H2 Server)");
    // To act as a Naive server, we need to be an H2 server that accepts CONNECT.
    // Hyper's server builder handles this.
    // For Epoch 3 stub: We acknowledge we need to accept the H2 connection on `stream`
    // and handle the `CONNECT` request.

    // let io = TokioIo::new(stream);
    // let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
    //     .serve_connection(io, service_fn(...))
    //     .await;

    Ok(())
}

// --- OUTBOUND ---
pub struct NaiveOutbound {
    settings: NaiveOutboundSettings,
    dns: Arc<DnsServer>,
}

impl NaiveOutbound {
    pub fn new(settings: NaiveOutboundSettings, dns: Arc<DnsServer>) -> Self {
        Self { settings, dns }
    }
}

#[async_trait]
impl Outbound for NaiveOutbound {
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut upgraded_io = self.dial(host, port).await?;
        tokio::io::copy_bidirectional(&mut in_stream, &mut upgraded_io).await?;
        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        info!(
            "Naive: Connecting to proxy at {}:{} for {}:{}",
            self.settings.address, self.settings.port, host, port
        );

        // 1. Connect TCP
        let addrs = self.dns.resolve_ip(&self.settings.address).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("Naive server not found"));
        }
        let remote_addr = std::net::SocketAddr::new(addrs[0], self.settings.port);
        let tcp = TcpStream::connect(remote_addr).await?;

        // 2. Handshake H2
        let io = TokioIo::new(tcp);
        let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                info!("Naive connection failed: {:?}", e);
            }
        });

        // 3. Send CONNECT
        let authority = format!("{}:{}", host, port);
        let req = Request::builder()
            .method("CONNECT")
            .uri(
                Uri::builder()
                    .scheme("https")
                    .authority(authority.as_str())
                    .path_and_query("/")
                    .build()?,
            )
            .header("Padding", "1".repeat(rand::random::<usize>() % 100)) // Naive Padding
            .body(Empty::<Bytes>::new())?;

        let res = sender.send_request(req).await?;

        if res.status().is_success() {
            // 4. Upgrade/Tunnel
            let upgraded = hyper::upgrade::on(res).await?;
            Ok(Box::new(TokioIo::new(upgraded)) as BoxedStream)
        } else {
            Err(anyhow::anyhow!("Naive CONNECT failed: {}", res.status()))
        }
    }
}
