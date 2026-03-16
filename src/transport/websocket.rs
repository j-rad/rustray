// src/transport/websocket.rs
use crate::config::WebSocketConfig;
use crate::error::Result;
use crate::transport::BoxedStream;
use bytes::Bytes;
use futures::prelude::*;
use http::HeaderValue;
use std::io::{self};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{WebSocketStream, client_async};
use tracing::{debug, warn};

/// Wraps an underlying `BoxedStream` with a client-side WebSocket handshake.
pub async fn wrap_ws_client(
    stream: BoxedStream,
    host: &str,
    settings: &WebSocketConfig,
) -> Result<BoxedStream> {
    debug!(
        "WebSocket: Starting client handshake to path '{}'",
        settings.path
    );

    let uri_host = settings.host.as_deref().unwrap_or(host);
    let path = if settings.path.starts_with('/') {
        settings.path.clone()
    } else {
        format!("/{}", settings.path)
    };

    let uri = format!("ws://{}{}", uri_host, path);
    let mut request = uri.into_client_request()?;

    // Set the Host header explicitly if configured or implied
    request
        .headers_mut()
        .insert("Host", HeaderValue::from_str(uri_host)?);

    let (ws_stream, response) = client_async(request, stream)
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket client handshake failed: {}", e))?;

    debug!(
        "WebSocket: Client handshake successful: {:?}",
        response.status()
    );

    Ok(Box::new(WsStreamAdapter::new(ws_stream)))
}

/// Wraps an underlying `BoxedStream` with a server-side WebSocket handshake.
pub async fn wrap_ws_server(
    stream: BoxedStream,
    settings: &WebSocketConfig,
) -> Result<BoxedStream> {
    debug!(
        "WebSocket: Accepting server handshake for path '{}'",
        settings.path
    );

    let expected_path = if settings.path.starts_with('/') {
        settings.path.clone()
    } else {
        format!("/{}", settings.path)
    };

    let callback = |req: &http::Request<()>, resp: http::Response<()>| {
        if req.uri().path() == expected_path {
            Ok(resp)
        } else {
            warn!(
                "WebSocket: Handshake rejected, invalid path: {}",
                req.uri().path()
            );
            Err(http::Response::builder()
                .status(404)
                .body(Some("Not Found".to_string()))
                .unwrap())
        }
    };

    let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback)
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket server handshake failed: {}", e))?;

    debug!("WebSocket: Server handshake successful.");

    Ok(Box::new(WsStreamAdapter::new(ws_stream)))
}

/// Adapter to make `WebSocketStream` (Message-based) compatible
/// with `BoxedStream` (AsyncRead/AsyncWrite byte-based).
///
/// Optimization: Uses `Bytes` for zero-copy buffer management instead of `Vec<u8>`.
struct WsStreamAdapter<S> {
    inner: WebSocketStream<S>,
    /// Buffer for read data that hasn't been consumed by `poll_read` yet.
    /// Uses `Bytes` which is basically ref-counted slice, efficient for slicing.
    read_buf: Bytes,
}

impl<S> WsStreamAdapter<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStreamAdapter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. Return buffered data if any
            if !this.read_buf.is_empty() {
                let n = std::cmp::min(this.read_buf.len(), buf.remaining());

                // Bytes::split_to is efficient O(1) pointer manip
                let chunk = this.read_buf.split_to(n);
                buf.put_slice(&chunk);

                return Poll::Ready(Ok(()));
            }

            // 2. Buffer is empty, poll underlying stream for next message
            match this.inner.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    match msg {
                        Message::Binary(data) => {
                            // Tungstenite returns Vec<u8> or Bytes depending on config/version.
                            // Assuming Vec<u8>, Bytes::from(vec) takes ownership (zero copy relative to vec).
                            this.read_buf = Bytes::from(data);
                            // Loop back to step 1 to return data
                        }
                        Message::Close(_) => return Poll::Ready(Ok(())), // EOF
                        Message::Ping(_) | Message::Pong(_) => {
                            // Tungstenite handles pongs automatically, just continue polling
                            continue;
                        }
                        _ => continue, // Ignore Text frames for proxying
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStreamAdapter<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // WebSocket is message-based. We wrap the bytes in a Binary message.
        // Zero-copy optimization: If `buf` was `Bytes`, we could pass it.
        // But `poll_write` takes `&[u8]`. We must copy to create a Message unless
        // we change the abstraction or assume caller holds it.
        // Message::Binary takes Vec<u8> or Bytes.

        // We create a Bytes object to potentially avoid some internal copies if Message supports it efficiently.
        // Actually, Vec<u8> from slice is a copy. Bytes::copy_from_slice is a copy.
        // `poll_write` contract implies copy anyway.

        let msg = Message::Binary(buf.to_vec().into());

        // We must use start_send_unpin (Sink interface)
        match this.inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => match this.inner.start_send_unpin(msg) {
                Ok(_) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .inner
            .poll_flush_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .inner
            .poll_close_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
