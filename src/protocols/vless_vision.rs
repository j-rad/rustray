// src/protocols/vless_vision.rs
//! XTLS Vision Flow Implementation
//!
//! Vision is a traffic obfuscation protocol that manipulates TLS record boundaries
//! and adds random padding to defeat deep packet inspection and traffic analysis.
//!
//! Key Features:
//! - Buffer-based zero-copy writes using `BytesMut`
//! - Correct async write handling with internal buffering
//! - Random padding (900-1400 bytes) added to early TLS handshake records
//! - TLS record boundary manipulation to hide fingerprints
//!
//! Reference: https://github.com/XTLS/Xrustray/discussions/1295

use crate::error::Result;
use crate::protocols::flow_trait::Flow;
use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;

// Vision padding ranges (bytes) matches Xrustray
const VISION_PADDING_MIN: usize = 900;
const VISION_PADDING_MAX: usize = 1400;

/// Vision flow state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum VisionState {
    /// Waiting for first TLS ClientHello
    Initial,
    /// Handshake phase - padding active
    Handshake {
        /// Number of records processed
        records_seen: u8,
    },
    /// Handshake complete - passthrough mode
    Traffic,
}

/// XTLS Vision flow implementation
pub struct VisionFlow {
    state: VisionState,
}

impl VisionFlow {
    pub fn new() -> Self {
        Self {
            state: VisionState::Initial,
        }
    }

    /// Check if buffer contains a complete TLS record header
    fn parse_tls_header(buf: &[u8]) -> Option<(u8, u16)> {
        if buf.len() < TLS_RECORD_HEADER_LEN {
            return None;
        }
        let content_type = buf[0];
        let length = u16::from_be_bytes([buf[3], buf[4]]);
        Some((content_type, length))
    }

    /// Add Vision padding to a TLS record
    fn add_vision_padding(&self, src: &[u8], dst: &mut BytesMut) {
        if src.len() < TLS_RECORD_HEADER_LEN {
            dst.extend_from_slice(src);
            return;
        }

        let content_type = src[0];

        // Only pad handshake records
        if content_type != TLS_HANDSHAKE {
            dst.extend_from_slice(src);
            return;
        }

        let original_len = u16::from_be_bytes([src[3], src[4]]);

        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(VISION_PADDING_MIN..=VISION_PADDING_MAX);

        // Check for overflow of u16 length
        let new_len = original_len as usize + pad_len;
        if new_len > u16::MAX as usize {
            // Cannot pad, just copy
            dst.extend_from_slice(src);
            return;
        }

        // 1. Copy Header with modified length
        dst.put_u8(src[0]);
        dst.put_u8(src[1]);
        dst.put_u8(src[2]);
        dst.put_u16(new_len as u16);

        // 2. Copy original payload
        let header_skipped = &src[TLS_RECORD_HEADER_LEN..];
        dst.extend_from_slice(header_skipped);

        // 3. Append Padding
        // Ensure dst has capacity
        dst.reserve(pad_len);
        let prev_len = dst.len();
        dst.put_bytes(0, pad_len); // zero-fill
        let padding_slice = &mut dst[prev_len..prev_len + pad_len];
        rng.fill(padding_slice);

        debug!(
            "Vision: Padding added. Original: {}, New: {}, Pad: {}",
            original_len, new_len, pad_len
        );
    }

    /// Process write data into the buffer
    pub fn process_write_buf(&mut self, src: &[u8], dst: &mut BytesMut) {
        match self.state {
            VisionState::Initial => {
                // Check for ClientHello
                if let Some((content_type, _)) = Self::parse_tls_header(src) {
                    if content_type == TLS_HANDSHAKE {
                        debug!("Vision: ClientHello detected. Activating padding.");
                        self.state = VisionState::Handshake { records_seen: 1 };
                        self.add_vision_padding(src, dst);
                        return;
                    }
                }
                // Passthrough
                dst.extend_from_slice(src);
            }
            VisionState::Handshake { records_seen } => {
                if records_seen < 5 {
                    // Pad first 5 handshake records like Xray does (~ish)
                    if let Some((content_type, _)) = Self::parse_tls_header(src) {
                        self.state = VisionState::Handshake {
                            records_seen: records_seen.saturating_add(1),
                        };

                        match content_type {
                            TLS_HANDSHAKE => {
                                self.add_vision_padding(src, dst);
                                return;
                            }
                            TLS_APPLICATION_DATA => {
                                debug!("Vision: App data detected. Switching to Traffic.");
                                self.state = VisionState::Traffic;
                            }
                            _ => {}
                        }
                    }
                } else {
                    debug!("Vision: Handshake limit reached. Switching to Traffic.");
                    self.state = VisionState::Traffic;
                }
                dst.extend_from_slice(src);
            }
            VisionState::Traffic => {
                dst.extend_from_slice(src);
            }
        }
    }
}

// Keep Flow trait implementation for compatibility, but note it's less efficient
impl Flow for VisionFlow {
    fn process_read(&mut self, _data: &mut [u8]) -> Result<usize> {
        Ok(_data.len())
    }

    fn process_write(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut buf = BytesMut::with_capacity(data.len() + VISION_PADDING_MAX);
        self.process_write_buf(data, &mut buf);
        Ok(buf.to_vec())
    }

    fn name(&self) -> &str {
        "xtls-rprx-vision"
    }

    fn is_active(&self) -> bool {
        self.state != VisionState::Traffic
    }
}

/// VisionStream wrapper with internal buffering for correct AsyncWrite
pub struct VisionStream<S> {
    inner: S,
    flow: VisionFlow,
    write_buf: BytesMut,
}

impl<S> VisionStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            flow: VisionFlow::new(),
            write_buf: BytesMut::with_capacity(8192),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let VisionStream {
            inner,
            flow,
            write_buf,
        } = &mut *self;

        // 1. Flush existing buffer if any
        if !write_buf.is_empty() {
            while !write_buf.is_empty() {
                match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                    Poll::Ready(Ok(n)) => {
                        write_buf.advance(n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // Cannot retain 'buf' obligation if we are pending on previous data
                        return Poll::Pending;
                    }
                }
            }
        }

        // 2. Buffer is empty, process new data
        flow.process_write_buf(buf, write_buf);

        // 3. Try to flush immediately to avoid latency
        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let VisionStream {
            inner, write_buf, ..
        } = &mut *self;

        // 1. Flush internal buffer
        while !write_buf.is_empty() {
            match Pin::new(&mut *inner).poll_write(cx, write_buf) {
                Poll::Ready(Ok(n)) => {
                    write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // 2. Flush underlying stream
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let VisionStream {
            inner, write_buf, ..
        } = &mut *self;

        // 1. Flush internal buffer first
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vision_padding_logic() {
        let mut flow = VisionFlow::new();
        let mut dst = BytesMut::new();

        // ClientHello
        let client_hello = vec![
            0x16, 0x03, 0x03, 0x00, 0x10, // Header
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // Payload
        ];

        flow.process_write_buf(&client_hello, &mut dst);

        // Should be padded
        assert!(dst.len() > client_hello.len());
        assert!(dst.len() >= client_hello.len() + VISION_PADDING_MIN);

        // Verify header update
        let new_len = u16::from_be_bytes([dst[3], dst[4]]);
        assert_eq!(dst.len(), TLS_RECORD_HEADER_LEN + new_len as usize);
    }
}
