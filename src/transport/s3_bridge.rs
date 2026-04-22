// src/transport/s3_bridge.rs
use crate::error::Result;
use crate::transport::AsyncStream;
use crate::transport::s3_codec::S3Codec;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use rand::Rng;
use reqwest::Client;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio_util::sync::PollSender;
use tracing::{debug, warn};
use uuid::Uuid;

// ============================================================================
// ASYNC S3 TRANSPORT
// ============================================================================

pub struct S3TransportSettings {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    // Add path style, etc. as needed for ArvanCloud/MizbanCloud
}

pub struct S3Bridge {
    client: Client,
    settings: Arc<S3TransportSettings>,
    session_id: String,
    codec: Mutex<S3Codec>,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl S3Bridge {
    pub async fn connect(settings: Arc<S3TransportSettings>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
            
        let session_id = Uuid::new_v4().to_string();
        
        // Note: For true S3 compatibility, we ideally should sign requests.
        // For domestic drop-buckets, we often use pre-shared API keys in headers 
        // or URLs if using a simple object storage wrapper, to reduce binary bloat.
        // Implementation here assumes a simplified REST interface over `reqwest`.
        
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        
        // Spawn polling loop
        let client_clone = client.clone();
        let settings_clone = settings.clone();
        let session_clone = session_id.clone();
        
        tokio::spawn(async move {
            Self::polling_loop(client_clone, settings_clone, session_clone, tx).await;
        });

        debug!("Flow-J S3: Bridge initialized for session {}", session_id);
        
        Ok(Self {
            client,
            settings,
            session_id,
            codec: Mutex::new(S3Codec::new()),
            rx,
        })
    }
    
    async fn polling_loop(
        client: Client,
        settings: Arc<S3TransportSettings>,
        session_id: String,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        let mut sequence = 0;
        loop {
            // Randomized polling interval (300ms–800ms) to evade anomaly detection
            let jitter = rand::thread_rng().gen_range(300..=800);
            tokio::time::sleep(Duration::from_millis(jitter)).await;

            // Inbound object path convention: s3://bucket/session/inbound_{seq}
            let object_key = format!("{}/inbound_{}", session_id, sequence);
            let url = format!("{}/{}/{}", settings.endpoint, settings.bucket, object_key);
            
            // Perform GET
            let req = client.get(&url)
                // .header("Authorization", format!("Bearer {}", settings.access_key))
                .send()
                .await;
                
            match req {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(bytes) = resp.bytes().await {
                        let mut codec = S3Codec::new();
                        if let Ok(decoded) = codec.decode_blob(&bytes) {
                            if tx.send(decoded).await.is_err() {
                                break; // Receiver dropped
                            }
                        }
                    }
                    
                    // Fire-and-forget DELETE so we don't build up infinite garbage
                    let del_url = url.clone();
                    let del_client = client.clone();
                    // .header("Authorization", ...)
                    tokio::spawn(async move {
                        let _ = del_client.delete(&del_url).send().await;
                    });
                    
                    sequence += 1;
                }
                Ok(resp) if resp.status() == 404 => {
                    // Normal, waiting for peer
                }
                Ok(resp) => {
                    warn!("S3 GET non-success: {}", resp.status());
                }
                Err(e) => {
                    debug!("S3 GET error: {}", e);
                }
            }
        }
    }
    
    pub async fn send(&self, data: &[u8], sequence_out: u64) -> Result<()> {
        let mut codec = self.codec.lock().await;
        let blob = codec.encode_blob(data);
        
        // Outbound object path convention: s3://bucket/session/outbound_{seq}
        let object_key = format!("{}/outbound_{}", self.session_id, sequence_out);
        let url = format!("{}/{}/{}", self.settings.endpoint, self.settings.bucket, object_key);
        
        let resp = self.client.put(&url)
            // .header("Authorization", format!("Bearer {}", self.settings.access_key))
            .body(blob)
            .send()
            .await?;
            
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Failed to PUT S3 blob: {}", resp.status()));
        }
        
        Ok(())
    }
}

pub struct S3BridgeStream {
    bridge: Arc<S3Bridge>,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    read_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    write_tx: PollSender<Vec<u8>>,
    sequence_out: Arc<Mutex<u64>>,
}

impl S3BridgeStream {
    pub fn new(mut bridge: S3Bridge) -> Self {
        let read_rx = std::mem::replace(&mut bridge.rx, tokio::sync::mpsc::channel(1).1); // Dummy replace
        let bridge = Arc::new(bridge);
        
        let (write_tx_inner, mut write_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
        let sequence_out = Arc::new(Mutex::new(0));

        let write_bridge = bridge.clone();
        let write_seq = sequence_out.clone();
        
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                let mut seq = write_seq.lock().await;
                if let Err(e) = write_bridge.send(&data, *seq).await {
                    warn!("Flow-J S3: Write error: {}", e);
                    break;
                }
                *seq += 1;
            }
        });

        Self {
            bridge,
            read_buffer: BytesMut::with_capacity(crate::transport::s3_codec::S3_BLOB_SIZE),
            write_buffer: BytesMut::new(),
            read_rx,
            write_tx: PollSender::new(write_tx_inner),
            sequence_out,
        }
    }
}

impl AsyncRead for S3BridgeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let len = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..len]);
            
            // Advance buffer
            // For BytesMut, split_to is fine or advance but BytesMut::advance takes ownership of part, so we copy
            let remaining = self.read_buffer.split_off(len);
            self.read_buffer = remaining;
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.len() <= buf.remaining() {
                    buf.put_slice(&data);
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&data[..len]);
                    self.read_buffer.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for S3BridgeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = std::task::ready!(self.write_tx.poll_ready_unpin(cx)) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }

        let data = buf.to_vec();
        if let Err(e) = self.write_tx.start_send_unpin(data) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_flush_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_close_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }
}
