// src/protocols/flow_trait.rs
//! Flow Protocol Abstraction
//!
//! Flow protocols are traffic obfuscation mechanisms that can be applied to proxy streams.
//! Examples include rustray Vision (TLS padding manipulation) and custom encryption flows.

use crate::error::Result;
use crate::transport::BoxedStream;
use std::io;

/// Trait for flow control protocols that manipulate traffic patterns
pub trait Flow: Send {
    /// Process data being read from the remote server
    /// Returns the processed data (may be modified for deobfuscation)
    fn process_read(&mut self, data: &mut [u8]) -> Result<usize> {
        // Default: passthrough
        Ok(data.len())
    }

    /// Process data being written to the remote server  
    /// Returns the processed data (may be modified for obfuscation)
    fn process_write(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Default: passthrough
        Ok(data.to_vec())
    }

    /// Get the flow protocol name
    fn name(&self) -> &str;

    /// Check if the flow is still active (some flows disable after handshake)
    fn is_active(&self) -> bool {
        true
    }
}

/// Trait for Flow-J compatible protocols (CDN, FEC, MQTT)
pub trait FlowJ: Flow {
    /// Get the operational mode (Reality, CDN, MQTT)
    fn mode(&self) -> &str;
}

/// Factory for creating flow instances
pub struct FlowFactory;

impl FlowFactory {
    /// Create a flow instance by name
    pub fn create(name: &str) -> Result<Box<dyn Flow>> {
        match name {
            "vision" | "h2" => {
                Ok(Box::new(crate::protocols::vless_vision::VisionFlow::new()))
            }
            // Flow-J is typically handled as a full transport, but we allow it here for compatibility
            "flow-j-vision" => Ok(Box::new(crate::protocols::vless_vision::VisionFlow::new())),
            _ => Err(anyhow::anyhow!("Unknown flow protocol: {}", name)),
        }
    }

    /// Check if a flow name is supported
    pub fn is_supported(name: &str) -> bool {
        matches!(name, "vision" | "h2" | "flow-j-vision")
    }
}

/// Wrapper stream that applies a flow protocol
pub struct FlowStream<S> {
    inner: S,
    flow: Box<dyn Flow>,
}

impl<S> FlowStream<S> {
    pub fn new(stream: S, flow: Box<dyn Flow>) -> Self {
        Self {
            inner: stream,
            flow,
        }
    }
}

impl<S> FlowStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    pub fn into_boxed(self) -> BoxedStream {
        Box::new(self)
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for FlowStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;

        // Read from inner stream
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        // Process through flow if data was read
        if let std::task::Poll::Ready(Ok(())) = result {
            let filled = buf.filled_mut();
            if let Err(e) = self.flow.process_read(filled) {
                return std::task::Poll::Ready(Err(io::Error::other(
                    e.to_string(),
                )));
            }
        }

        result
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for FlowStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::pin::Pin;

        // Process through flow
        let processed = match self.flow.process_write(buf) {
            Ok(data) => data,
            Err(e) => {
                return std::task::Poll::Ready(Err(io::Error::other(
                    e.to_string(),
                )));
            }
        };

        // Write processed data to inner stream
        Pin::new(&mut self.inner).poll_write(cx, &processed)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
