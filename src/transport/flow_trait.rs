// src/transport/flow_trait.rs
use crate::error::Result;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub rtt_ms: u64,
    /// Inter-packet jitter in milliseconds.
    pub jitter_ms: u64,
    pub buffer_usage_bytes: usize,
    pub isp_asn: Option<u32>,
}

/// TrinityTransport: The Virtual Transport Matrix (VTM) Abstraction.
/// 
/// Decouples protocol payloads (VLESS, Trojan) from physical carriers (WS, TCP, MQTT).
pub trait TrinityTransport: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    /// Atomically swap the underlying carrier mid-session.
    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Carrier switching not supported by this transport"))
    }

    /// Arm 1-byte fragmentation for the next TLS handshake write.
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(()) // Default no-op
    }

    /// Returns current RTT, buffer usage, and ISP ASN.
    fn get_transport_info(&self) -> TransportStats {
        TransportStats::default() // Default no-op implementation
    }

    /// Logic to migrate an active protocol state to a new TAL object.
    fn handover(self, _new_carrier: BoxedTrinityTransport) -> Result<Self>
    where
        Self: Sized;
}

pub type BoxedTrinityTransport = Box<dyn TrinityTransport>;

// --- Wrapper for hot-swappable streams ---
pub struct TrinityStream {
    inner: BoxedTrinityTransport,
}

impl TrinityStream {
    pub fn new(inner: BoxedTrinityTransport) -> Self {
        Self { inner }
    }
}

impl TrinityTransport for TrinityStream {
    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner = new_carrier;
        Ok(())
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn get_transport_info(&self) -> TransportStats {
        self.inner.get_transport_info()
    }

    fn handover(mut self, new_carrier: BoxedTrinityTransport) -> Result<Self> {
        self.inner = new_carrier;
        Ok(self)
    }
}

impl AsyncRead for TrinityStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrinityStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
