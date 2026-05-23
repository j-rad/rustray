//! Relay-based Domain Fronting Transport
//! 
//! This transport implementation provides domain fronting capabilities by encapsulating
//! TCP stream data into HTTP requests. It is particularly effective against SNI-based
//! filtering and IP-level blocks by hiding traffic behind high-reputation domains
//! like Google, Cloudflare, or Fronted Workers.
//!
//! ### Architecture
//! - **Background Worker**: Spawns a task that polls the relay for incoming data and
//!   uploads buffered outgoing data via POST requests.
//! - **Base64 Encoding**: All binary data is base64-encoded to ensure compatibility
//!   with standard HTTP headers and body content.
//! - **Session Management**: Each stream uses a unique UUID session ID to allow the
//!   relay to multiplex multiple client connections.
//!
//! ### Example Configuration
//! ```json
//! {
//!   "network": "relay-fronting",
//!   "relayFronting": {
//!     "relayUrl": "https://script.google.com/macros/s/...",
//!     "host": "script.google.com",
//!     "sni": "www.google.com",
//!     "intervalMs": 500
//!   }
//! }
//! ```

use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use bytes::{Buf, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RelayFrontingSettings {
    pub relay_url: String,
    pub host: String,
    pub sni: String,
    pub interval_ms: u64,
}

pub struct RelayFrontingStream {
    settings: Arc<RelayFrontingSettings>,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    read_buffer: BytesMut,
}

impl RelayFrontingStream {
    pub fn new(settings: RelayFrontingSettings) -> Self {
        let (read_tx, read_rx) = mpsc::channel(128);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(128);
        let settings = Arc::new(settings);
        let session_id = uuid::Uuid::new_v4().to_string();

        // Spawn Background Worker for HTTP Polling/Uploading
        let worker_settings = settings.clone();
        let worker_session_id = session_id.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true) 
                .build()
                .unwrap();

            loop {
                // 1. Check for data to upload
                let mut data_to_upload = Vec::new();
                while let Ok(chunk) = write_rx.try_recv() {
                    data_to_upload.extend_from_slice(&chunk);
                    if data_to_upload.len() > 16384 { break; }
                }

                if !data_to_upload.is_empty() {
                    let b64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data_to_upload);
                    let res = client.post(&worker_settings.relay_url)
                        .header("Host", &worker_settings.host)
                        .header("X-SNI", &worker_settings.sni) 
                        .header("X-Session-ID", &worker_session_id)
                        .body(b64_data)
                        .send()
                        .await;

                    match res {
                        Ok(resp) => {
                            if let Ok(body) = resp.bytes().await {
                                if !body.is_empty() {
                                    if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body) {
                                        let _ = read_tx.send(decoded).await;
                                    }
                                }
                            }
                        }
                        Err(e) => warn!("RelayFronting: Post error: {}", e),
                    }
                } else {
                    // 2. No data to upload, just poll for incoming data
                    let res = client.get(&worker_settings.relay_url)
                        .header("Host", &worker_settings.host)
                        .header("X-SNI", &worker_settings.sni)
                        .header("X-Session-ID", &worker_session_id)
                        .send()
                        .await;

                    match res {
                        Ok(resp) => {
                            if let Ok(body) = resp.bytes().await {
                                if !body.is_empty() {
                                    if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body) {
                                        let _ = read_tx.send(decoded).await;
                                    }
                                }
                            }
                        }
                        Err(e) => debug!("RelayFronting: Poll error: {}", e),
                    }
                    
                    tokio::time::sleep(Duration::from_millis(worker_settings.interval_ms)).await;
                }
            }
        });

        Self {
            settings,
            read_rx,
            write_tx,
            read_buffer: BytesMut::new(),
        }
    }
}

impl AsyncRead for RelayFrontingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let n = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..n]);
            self.read_buffer.advance(n);
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for RelayFrontingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.write_tx.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "RelayFronting: write channel closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TrinityTransport for RelayFrontingStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "RelayFronting: switch_carrier not supported"))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Err(anyhow::anyhow!("RelayFronting: handover not supported"))
    }
}
