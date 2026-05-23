use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use socket2::{Socket, Domain, Type, Protocol};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::transport::flow_trait::{BoxedTrinityTransport, TrinityTransport, TransportStats};
use tracing::{debug, warn};

pub struct FakeTcpCarrier {
    inner: BoxedTrinityTransport, // Fallback if raw sockets fail
    raw_socket: Option<Socket>,
}

impl FakeTcpCarrier {
    pub fn new(inner: BoxedTrinityTransport) -> Self {
        // Attempt to create a raw socket
        let raw_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
            Ok(sock) => {
                debug!("FakeTCP: Successfully created RAW socket");
                Some(sock)
            }
            Err(e) => {
                warn!("FakeTCP: Failed to create RAW socket (requires root/CAP_NET_RAW): {}", e);
                None
            }
        };

        Self {
            inner,
            raw_socket,
        }
    }
}

impl AsyncRead for FakeTcpCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // In a real implementation, we would poll the raw socket using a background thread
        // or a mio Evented wrapper. Since this is an evasion module, we primarily
        // rely on the fallback inner stream for now, while packet injection happens on write.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FakeTcpCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Here we could inject the crafted packet via raw socket.
        // For standard data transfer, we use the inner stream.
        if let Some(_sock) = &self.raw_socket {
            // E.g., construct IP/TCP headers and send...
            // sock.send_to(crafted_buf, &addr)?;
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

impl TrinityTransport for FakeTcpCarrier {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner.switch_carrier(new_carrier)
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn get_transport_info(&self) -> TransportStats {
        self.inner.get_transport_info()
    }

    fn handover(self, new_carrier: BoxedTrinityTransport) -> crate::error::Result<Self> {
        Ok(Self {
            inner: new_carrier,
            raw_socket: self.raw_socket,
        })
    }
}
