// src/protocols/flow_trait.rs
//! Flow Protocol and Virtual Transport Matrix (VTM) Abstraction
//!
//! This module defines the TAL (Transport Abstraction Layer) used throughout RustRay.
//!
//! Key types:
//! - `TrinityTransport` — the "Virtual Network Card"; any stream that can be hot-swapped.
//! - `TrinityStream`    — a boxed carrier that supports mid-session hot-swap.
//! - `FragmentedStream` — wraps any stream and performs 1-byte ClientHello splitting.
//! - `Flow` / `FlowJ`   — per-packet obfuscation/deobfuscation hooks.
//! - `FlowStream`       — applies a `Flow` on top of any async stream.

use crate::error::Result;
use crate::transport::BoxedStream;
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_kcp::KcpStream;
use tracing::debug;

#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency: Duration,
    pub rtt_ms: u64,
    /// Inter-packet jitter in milliseconds, used for flow symmetry evasion.
    pub jitter_ms: u64,
    pub buffer_usage_bytes: usize,
    /// Detected ISP Autonomous System Number (e.g. 44244 for MCI).
    pub isp_asn: Option<u32>,
}

// ─── TrinityTransport ─────────────────────────────────────────────────────────

/// The Virtual Network Card.
///
/// Every carrier (Reality, MQTT, WebRTC, DNS-tunnel, WS+CDN) that can carry proxy
/// traffic must implement this trait.  The two extra methods beyond `AsyncRead +
/// AsyncWrite` enable the VTM's two core powers:
///
/// 1. **Hot-swap** (`switch_carrier`): swap the physical bearer mid-session without
///    resetting the outer protocol (VLESS, Trojan, Hysteria-2).
/// 2. **Fragmentation** (`apply_fragmentation`): arm the 1-byte ClientHello split
///    that defeats ServerHello timing / JA3 fingerprinting at the GFW.
pub trait TrinityTransport: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    /// Return a reference to the underlying type as Any for downcasting.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Return a mutable reference to the underlying type as Any for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;

    /// Atomically swap the underlying carrier.
    ///
    /// After this call the stream continues operating over `new_carrier`.
    /// The semantics are *best-effort*: any in-flight bytes on the old carrier
    /// that have not yet been acknowledged by the DTN layer may be lost; the DTN
    /// `reconcile_session` handshake handles recovery.
    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()>;

    /// Arm 1-byte fragmentation on the next write.
    ///
    /// When armed, the first `poll_write` call will send exactly **one** byte,
    /// forcing the TLS stack to emit a ClientHello split across two TCP segments.
    /// This defeats GFW ServerHello timing analysis and JA3/JA4 fingerprinting.
    fn apply_fragmentation(&mut self) -> io::Result<()>;

    /// Move the internal protocol state from one carrier to another mid-session.
    fn handover(self, new_tal: BoxedTrinityTransport) -> Result<Self>
    where
        Self: Sized;

    /// Get current transport statistics and health info.
    fn get_transport_info(&self) -> TransportStats {
        TransportStats::default()
    }
}

/// Type alias for an owned, heap-allocated `TrinityTransport`.
pub type BoxedTrinityTransport = Box<dyn TrinityTransport>;

impl TrinityTransport for BoxedTrinityTransport {
    fn as_any(&self) -> &dyn std::any::Any {
        (**self).as_any()
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        (**self).as_any_mut()
    }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        (**self).switch_carrier(new_carrier)
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        (**self).apply_fragmentation()
    }

    fn handover(self, new_tal: BoxedTrinityTransport) -> Result<Self> {
        // This is tricky because we can't easily unbox and rebox if it's dynamic.
        // But since it's already boxed, we can just return it or wrap?
        // Actually, handover usually moves the state.
        // For BoxedTrinityTransport, we can't easily call handover(self, ...) on the inner.
        // So we might need to change the trait to return BoxedTrinityTransport?
        // Let's stick to the current signature and return an error for now if not supported.
        Err(anyhow::anyhow!(
            "BoxedTrinityTransport: handover not supported directly"
        ))
    }

    fn get_transport_info(&self) -> TransportStats {
        (**self).get_transport_info()
    }
}

// ─── Blanket impl for BoxedStream sources ─────────────────────────────────────

/// `TrinityStream` is the primary VTM carrier wrapper.
///
/// It boxes any `TrinityTransport` and adds:
/// - Carrier hot-swap (`switch_carrier` delegates to inner, then replaces inner).
/// - Fragmentation arm forwarded to the current inner carrier.
pub struct TrinityStream {
    /// The active physical carrier.
    pub inner: BoxedTrinityTransport,
}

impl TrinityStream {
    pub fn new(inner: BoxedTrinityTransport) -> Self {
        Self { inner }
    }

    /// Wrap an existing `BoxedStream` by giving it no-op VTM methods.
    pub fn from_boxed(stream: BoxedStream) -> Self {
        Self {
            inner: Box::new(VtmAdaptor { inner: stream }),
        }
    }
}

impl TrinityTransport for TrinityStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        // Replace the inner carrier atomically (single pointer store on 64-bit).
        self.inner = new_carrier;
        debug!("VTM: carrier hot-swap completed");
        Ok(())
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn handover(mut self, new_tal: BoxedTrinityTransport) -> Result<Self> {
        self.inner = new_tal;
        Ok(self)
    }

    fn get_transport_info(&self) -> TransportStats {
        self.inner.get_transport_info()
    }
}

impl AsyncRead for TrinityStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrinityStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

// ─── VtmAdaptor ───────────────────────────────────────────────────────────────

/// Adapts any `BoxedStream` (plain `AsyncRead + AsyncWrite`) into a
/// `TrinityTransport` with no-op VTM methods.
///
/// Used when legacy code produces a `BoxedStream` that we want to wrap inside
/// a `TrinityStream` without refactoring the producer.
struct VtmAdaptor {
    inner: BoxedStream,
}

impl TrinityTransport for VtmAdaptor {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VtmAdaptor: hot-swap requires wrapping in TrinityStream first",
        ))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        // VtmAdaptor cannot fragment by itself; callers should wrap in FragmentedStream.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VtmAdaptor: wrap in FragmentedStream to enable fragmentation",
        ))
    }

    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Err(anyhow::anyhow!("VtmAdaptor: handover not supported"))
    }

    fn get_transport_info(&self) -> TransportStats {
        TransportStats::default()
    }
}

impl AsyncRead for VtmAdaptor {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VtmAdaptor {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl TrinityTransport for tokio::net::TcpStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TcpStream: switch_carrier not supported",
        ))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Err(anyhow::anyhow!("TcpStream: handover not supported"))
    }

    fn get_transport_info(&self) -> TransportStats {
        TransportStats::default()
    }
}

// ─── FragmentedStream ─────────────────────────────────────────────────────────

/// Wraps any `TrinityTransport` and implements the 1-byte ClientHello split.
///
/// When `apply_fragmentation()` is called, the very next `poll_write` will send
/// exactly **one** byte.  Subsequent writes are passed through unmodified.
/// This forces the TLS stack to split the ClientHello across two TCP segments,
/// defeating ServerHello timing analysis and JA3/JA4 fingerprinting.
pub struct FragmentedStream<S> {
    inner: S,
    /// True when fragmentation has been armed but the first byte not yet sent.
    armed: bool,
    /// Scratch buffer holding the first byte while we wait for it to flush.
    first_byte_buf: Option<u8>,
}

impl<S> FragmentedStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            armed: false,
            first_byte_buf: None,
        }
    }
}

impl<S: TrinityTransport + Unpin + Send + 'static> TrinityTransport for FragmentedStream<S> {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FragmentedStream: wrap the inner carrier inside TrinityStream to hot-swap",
        ))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.armed = true;
        Ok(())
    }

    fn handover(mut self, new_tal: BoxedTrinityTransport) -> Result<Self> {
        // Here we'd typically want to re-wrap the new carrier in a FragmentedStream
        // but the trait signature returns Self. If we want to support this,
        // we might need a more flexible design. For now, we'll try to swap the inner if possible,
        // but FragmentedStream<S> usually has a specific S.
        // If S is TrinityStream, we can swap.
        // For now, let's just error or try to swap if S is TrinityStream.
        Err(anyhow::anyhow!(
            "FragmentedStream: handover not supported directly. Wrap in TrinityStream."
        ))
    }

    fn get_transport_info(&self) -> TransportStats {
        self.inner.get_transport_info()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.armed && buf.len() > 1 {
            // Send exactly 1 byte to force segment boundary in the TLS record.
            match Pin::new(&mut self.inner).poll_write(cx, &buf[..1]) {
                Poll::Ready(Ok(n)) if n == 1 => {
                    self.armed = false; // disarm after one use
                    // Report that exactly 1 byte was consumed; caller retries the rest.
                    return Poll::Ready(Ok(1));
                }
                other => return other,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ─── Flow Trait ───────────────────────────────────────────────────────────────

/// Per-packet obfuscation/deobfuscation hook.
///
/// Flow protocols operate *on top of* a carrier and manipulate TLS record
/// boundaries, padding, or encryption.  Examples: Vision, H2.
pub trait Flow: Send {
    /// Process data being read from the remote server.
    fn process_read(&mut self, data: &mut [u8]) -> Result<usize> {
        Ok(data.len())
    }

    /// Process data being written to the remote server.
    fn process_write(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    /// Human-readable name of the flow protocol.
    fn name(&self) -> &str;

    /// True while the flow is actively modifying data (e.g. during TLS handshake).
    fn is_active(&self) -> bool {
        true
    }
}

/// Flow-J compatible protocols (CDN, FEC, MQTT).
pub trait FlowJ: Flow {
    /// Operational mode string (e.g. "reality", "cdn", "mqtt").
    fn mode(&self) -> &str;
}

// ─── FlowFactory ──────────────────────────────────────────────────────────────

pub struct FlowFactory;

impl FlowFactory {
    /// Create a flow instance by name.
    pub fn create(name: &str) -> Result<Box<dyn Flow>> {
        match name {
            "vision" | "h2" | "flow-j-vision" => {
                Ok(Box::new(crate::protocols::vless_vision::VisionFlow::new()))
            }
            _ => Err(anyhow::anyhow!("Unknown flow protocol: {}", name)),
        }
    }

    /// True if the given flow name is supported.
    pub fn is_supported(name: &str) -> bool {
        matches!(name, "vision" | "h2" | "flow-j-vision")
    }
}

// ─── FlowStream ───────────────────────────────────────────────────────────────

/// Applies a `Flow` protocol on top of any async stream.
///
/// Reads are deobfuscated and writes are obfuscated in-place using the inner
/// `Flow` implementation's `process_read` / `process_write` hooks.
pub struct FlowStream<S> {
    inner: S,
    flow: Box<dyn Flow>,
    write_buf: BytesMut,
}

impl<S> FlowStream<S> {
    pub fn new(stream: S, flow: Box<dyn Flow>) -> Self {
        Self {
            inner: stream,
            flow,
            write_buf: BytesMut::with_capacity(8192),
        }
    }
}

impl<S> FlowStream<S>
where
    S: TrinityTransport + Unpin + Send + 'static,
{
    pub fn into_boxed(self) -> BoxedStream {
        Box::new(self)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FlowStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = result {
            let filled = buf.filled_mut();
            if !filled.is_empty()
                && let Err(e) = self.flow.process_read(filled)
            {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
        }

        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FlowStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let FlowStream {
            inner,
            flow,
            write_buf,
        } = &mut *self;

        // Flush any previously buffered output first.
        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Process new data through the flow.
        let processed = match flow.process_write(buf) {
            Ok(data) => data,
            Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
        };
        write_buf.put_slice(&processed);

        // Best-effort immediate flush.
        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let FlowStream {
            inner, write_buf, ..
        } = &mut *self;

        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let FlowStream {
            inner, write_buf, ..
        } = &mut *self;

        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

impl<S: TrinityTransport + Unpin + Send + 'static> TrinityTransport for FlowStream<S> {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner.switch_carrier(new_carrier)
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn handover(self, new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(Self {
            inner: self.inner.handover(new_tal)?,
            flow: self.flow,
            write_buf: self.write_buf,
        })
    }

    fn get_transport_info(&self) -> TransportStats {
        self.inner.get_transport_info()
    }
}

impl TrinityTransport for KcpStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "KcpStream: hot-swap not supported"))
    }
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(self)
    }
}

impl TrinityTransport for tokio::io::DuplexStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "DuplexStream: hot-swap not supported"))
    }
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(self)
    }
}

impl TrinityTransport for tokio::io::Empty {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Empty: hot-swap not supported"))
    }
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(self)
    }
}

impl TrinityTransport for arti_client::DataStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TorDataStream: hot-swap not supported"))
    }
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(self)
    }
}
