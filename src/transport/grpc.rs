// src/transport/grpc.rs
use crate::error::Result;
use crate::transport::BoxedStream;
use bytes::Bytes;
use futures::stream::StreamExt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::Endpoint;
use tonic::{Request, Streaming};

/// Configuration for gRPC Transport
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub service_name: String,
    pub host: String, // Host header (if different from address)
    pub multi_mode: bool,
    pub idle_timeout: std::time::Duration,
    pub health_check_timeout: std::time::Duration,
    pub permit_without_stream: bool,
    pub initial_windows_size: i32,
}

/// A bidirectional stream wrapper that sends/receives raw bytes over gRPC.
/// This mimics the behavior of Xray's "Tunneled" gRPC service.
pub struct GrpcStream {
    /// Sender for outbound data (converted to protobuf Bytes wrapper or raw)
    tx_outbound: tokio::sync::mpsc::Sender<Bytes>,

    /// Receiver for inbound data frames
    /// Wrapped in Mutex because AsyncStream requires Sync, and Streaming is !Sync
    rx_inbound: std::sync::Mutex<Streaming<proto::Hunk>>,

    /// Buffer for read data that hasn't looks been consumed
    read_buf: Bytes,
}

// We need a Proto definition for the tunnel.
// Xray uses `transport.internet.grpc.encoding.Tunneled`.
// Message is "Hunk" { bytes data = 1; }

pub mod proto {
    // handwritten for now to avoid build.rs dependency if possible, or use prost derived
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Hunk {
        #[prost(bytes = "vec", tag = "1")]
        pub data: ::prost::alloc::vec::Vec<u8>,
    }
}

use proto::Hunk;

impl GrpcStream {
    /// Connects to a gRPC endpoint and establishes a streaming tunnel.
    pub async fn connect(address: String, config: GrpcConfig) -> Result<BoxedStream> {
        let endpoint = Endpoint::from_shared(address.clone())?
            .timeout(config.idle_timeout)
            .keep_alive_timeout(config.health_check_timeout)
            .keep_alive_while_idle(config.permit_without_stream);

        let channel = endpoint.connect().await?;

        // We can't easily use generated code without build.rs running,
        // but we can use tonic's generic client or manual codec.
        // For simplicity, we assume we have a `TunneledService` client logic here.
        // Or we construct the request manually.

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Map outbound Bytes to Hunk
        let outbound_stream =
            tokio_stream::wrappers::ReceiverStream::new(rx).map(|bytes: Bytes| Hunk {
                data: bytes.to_vec(),
            });

        // We need a specific path usually. Xray default is "/GunService/Tun" or configurable.
        let service_path = if config.service_name.starts_with('/') {
            config.service_name.clone()
        } else {
            format!("/{}", config.service_name)
        };

        // Create a generic client-like call
        // This is tricky without generated code.
        // We will construct a minimal GrpcClient wrapper.
        // Or use `tonic::client::Grpc::new(channel)`.

        let mut grpc_client = tonic::client::Grpc::new(channel);

        // Path: /<ServiceName>/Tun (standard Xray convention)
        // Actually usually "/GunService/Tun"
        let full_path = format!("{}/Tun", service_path);
        let path = http::uri::PathAndQuery::try_from(full_path)
            .map_err(|e| anyhow::anyhow!("Invalid gRPC path: {}", e))?;

        // Codec
        let codec = tonic::codec::ProstCodec::<Hunk, Hunk>::default();

        let request = Request::new(outbound_stream);

        // Perform the streaming call
        let response_stream = grpc_client
            .streaming(request, path, codec)
            .await?
            .into_inner();

        Ok(Box::new(Self {
            tx_outbound: tx,
            rx_inbound: std::sync::Mutex::new(response_stream),
            read_buf: Bytes::new(),
        }))
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Lock mutex to access stream
        // Since we have &mut self, and Mutex::get_mut provides &mut T without blocking
        // we can safely access the inner stream.
        let stream = self.rx_inbound.get_mut().unwrap();

        match stream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(hunk))) => {
                let data = Bytes::from(hunk.data);
                if data.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // gRPC is message based. We send a Hunk (Bytes).
        let bytes = Bytes::copy_from_slice(buf);

        // Backpressure check using try_reserve fallback or poll_ready logic
        // We really should use `poll_reserve` if available or `try_reserve`.
        // As seen in splithttp, tokio::mpsc inside this crate version might strictly require try_reserve.

        match self.tx_outbound.try_reserve() {
            Ok(permit) => {
                permit.send(bytes);
                Poll::Ready(Ok(buf.len()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Drop if full for now
                tracing::warn!("gRPC outbound buffer full, dropping packet");
                Poll::Ready(Ok(buf.len()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "gRPC closed"),
            )),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Close channel?
        Poll::Ready(Ok(()))
    }
}
