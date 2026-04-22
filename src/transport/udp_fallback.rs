// src/transport/udp_fallback.rs
//! UDP-over-TCP Fallback Multiplexer
//!
//! Encapsulates UDP datagrams inside a TCP stream using length-prefix framing.
//! Used when direct UDP is blocked but TCP is available.
//! Wire format per frame: [Length: 2 bytes BE] [Payload: N bytes]

use bytes::{Buf, BufMut, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

/// Maximum UDP datagram size that can be encapsulated
const MAX_DATAGRAM_SIZE: usize = 65535;
/// Length prefix size (2 bytes)
const LENGTH_PREFIX_SIZE: usize = 2;

/// Configuration for UDP-over-TCP fallback.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpFallbackConfig {
    /// TCP server address to tunnel UDP through
    pub address: String,
    /// Read buffer size
    #[serde(default = "default_read_buf_size")]
    pub read_buf_size: usize,
}

fn default_read_buf_size() -> usize {
    8192
}

impl Default for UdpFallbackConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            read_buf_size: default_read_buf_size(),
        }
    }
}

/// UDP-over-TCP stream with length-prefix framing.
pub struct UdpOverTcpStream {
    inner: TcpStream,
    /// Read buffer for reassembling frames
    read_buf: BytesMut,
    /// Partially read frame state
    pending_frame_len: Option<u16>,
}

impl UdpOverTcpStream {
    pub fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            read_buf: BytesMut::with_capacity(default_read_buf_size()),
            pending_frame_len: None,
        }
    }

    pub async fn connect(config: &UdpFallbackConfig) -> io::Result<Self> {
        let stream = TcpStream::connect(&config.address).await?;
        debug!("UDP-over-TCP: connected to {}", config.address);
        Ok(Self::new(stream))
    }

    /// Send a UDP datagram over the TCP stream.
    pub async fn send_datagram(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_DATAGRAM_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Datagram too large",
            ));
        }

        // Write length prefix + payload
        let len = data.len() as u16;
        self.inner.write_all(&len.to_be_bytes()).await?;
        self.inner.write_all(data).await?;
        self.inner.flush().await?;

        Ok(())
    }

    /// Receive a UDP datagram from the TCP stream.
    pub async fn recv_datagram(&mut self) -> io::Result<Vec<u8>> {
        // Read length prefix
        let len = self.inner.read_u16().await? as usize;

        if len > MAX_DATAGRAM_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame too large: {} bytes", len),
            ));
        }

        // Read payload
        let mut payload = vec![0u8; len];
        self.inner.read_exact(&mut payload).await?;

        Ok(payload)
    }
}

/// AsyncRead implementation that deframes UDP-over-TCP.
impl AsyncRead for UdpOverTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try to read more data from the inner stream
        let mut tmp_buf = [0u8; 4096];
        let mut tmp_read = ReadBuf::new(&mut tmp_buf);

        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_read) {
            Poll::Ready(Ok(())) => {
                let filled = tmp_read.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
                this.read_buf.extend_from_slice(filled);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.read_buf.is_empty() {
                    return Poll::Pending;
                }
            }
        }

        // Try to extract a frame
        loop {
            if let Some(frame_len) = this.pending_frame_len {
                let needed = frame_len as usize;
                if this.read_buf.len() >= needed {
                    let payload = this.read_buf.split_to(needed);
                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);
                    this.pending_frame_len = None;
                    return Poll::Ready(Ok(()));
                } else {
                    // Need more data
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }

            // Read length prefix
            if this.read_buf.len() >= LENGTH_PREFIX_SIZE {
                let len = u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]);
                this.read_buf.advance(LENGTH_PREFIX_SIZE);
                this.pending_frame_len = Some(len);
                continue;
            }

            // Not enough data for length prefix
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
    }
}

/// AsyncWrite implementation that frames writes as UDP-over-TCP.
impl AsyncWrite for UdpOverTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Frame the write: prepend length prefix
        let len = buf.len().min(MAX_DATAGRAM_SIZE);
        let mut frame = BytesMut::with_capacity(LENGTH_PREFIX_SIZE + len);
        frame.put_u16(len as u16);
        frame.put_slice(&buf[..len]);

        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                if n >= LENGTH_PREFIX_SIZE {
                    Poll::Ready(Ok(n - LENGTH_PREFIX_SIZE))
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
