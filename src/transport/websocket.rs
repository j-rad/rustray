// src/transport/websocket.rs
use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use base64::{Engine as _, engine::general_purpose};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub async fn wrap_ws_client(
    stream: BoxedTrinityTransport,
    host: &str,
    settings: &crate::config::WebSocketConfig,
) -> Result<BoxedTrinityTransport> {
    let adapter = WebSocketAdapter::upgrade(stream, host, &settings.path).await?;
    Ok(Box::new(adapter) as BoxedTrinityTransport)
}

pub async fn wrap_ws_server(
    stream: BoxedTrinityTransport,
    _settings: &crate::config::WebSocketConfig,
) -> Result<BoxedTrinityTransport> {
    // Inbound WS handshake is more complex, usually requires a proper HTTP parser.
    // For now, return a placeholder or stub.
    // In a real implementation, we would perform the WS server handshake here.
    Ok(stream)
}

pub struct WebSocketAdapter<S> {
    inner: S,
    mask: Option<[u8; 4]>,
    // Add buffering and frame state here if needed for a full WS implementation
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> WebSocketAdapter<S> {
    pub async fn upgrade(mut stream: S, host: &str, path: &str) -> Result<Self> {
        let key: [u8; 16] = rand::random();
        let key_base64 = general_purpose::STANDARD.encode(key);

        let upgrade_req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            path, host, key_base64
        );

        stream.write_all(upgrade_req.as_bytes()).await?;
        stream.flush().await?;

        // Simple response parsing (ideally use a parser but manual for minimal deps as requested)
        let mut resp_buf = [0u8; 1024];
        let n = stream.read(&mut resp_buf).await?;
        let resp = String::from_utf8_lossy(&resp_buf[..n]);

        if !resp.contains("101 Switching Protocols") {
            return Err(anyhow::anyhow!("WS Upgrade failed: {}", resp));
        }

        Ok(Self {
            inner: stream,
            mask: Some(rand::random()),
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TrinityTransport for WebSocketAdapter<S> {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "WebSocketAdapter: hot-swap not supported"))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(()) // Default no-op
    }

    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Err(anyhow::anyhow!("WebSocketAdapter: handover not implemented"))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketAdapter<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // In a real WS implementation, we'd handle WS framing here.
        // For the TAL refactor, we provide the structure.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketAdapter<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // In a real WS implementation, we'd wrap data in WS frames here.
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
