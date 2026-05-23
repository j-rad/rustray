// src/transport/shadow_mieru.rs
use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport, TransportStats, TransportStats as FlowTransportStats};
use bytes::{BytesMut, Buf, BufMut};
use pin_project_lite::pin_project;
use std::any::Any;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn, error};
use rand::{Rng, RngCore};
use std::future::Future;

/// Mimic profile mapping to target mean packet sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProfile {
    WebBrowsing,
    VodFilimo,
    VoipDomestic,
    None,
}

impl MimicProfile {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "webbrowsing" | "web" => Self::WebBrowsing,
            "vodfilimo" | "vod" | "filimo" => Self::VodFilimo,
            "voipdomestic" | "voip" => Self::VoipDomestic,
            _ => Self::None,
        }
    }

    pub fn target_size(&self) -> usize {
        match self {
            Self::WebBrowsing => 800,
            Self::VodFilimo => 1200,
            Self::VoipDomestic => 160,
            Self::None => 0,
        }
    }
}

pin_project! {
    /// A chameleon wrapper implementing TrinityTransport that applies:
    /// 1. Mieru-Style rotating XOR obfuscation.
    /// 2. Brutal fixed-rate congestion-free pacing.
    /// 3. Entropy reduction via domestic app headers (RTP / HTTP2).
    /// 4. Generative dynamic padding and hard MTU limits.
    pub struct ShadowMieruStream<S> {
        #[pin]
        inner: S,
        entropy_key: [u8; 16],
        rate_bps: u64,
        decoy_profile: String, // "http2" or "webrtc"
        mimic_profile: MimicProfile,
        
        // Pacing state
        bytes_sent_window: u64,
        window_start: Instant,
        pacer_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
        consecutive_timeouts: usize,
        
        // Obfuscation states
        read_counter: u64,
        write_counter: u64,
        
        // Buffers
        read_buf: BytesMut,
        write_pending: BytesMut,
    }
}

impl<S> ShadowMieruStream<S> {
    pub fn new(
        inner: S,
        entropy_key: [u8; 16],
        rate_bps: u64,
        decoy_profile: &str,
        mimic_profile: &str,
    ) -> Self {
        Self {
            inner,
            entropy_key,
            rate_bps: if rate_bps == 0 { 50_000_000 } else { rate_bps },
            decoy_profile: decoy_profile.to_string(),
            mimic_profile: MimicProfile::from_str(mimic_profile),
            bytes_sent_window: 0,
            window_start: Instant::now(),
            pacer_sleep: None,
            consecutive_timeouts: 0,
            read_counter: 0,
            write_counter: 0,
            read_buf: BytesMut::with_capacity(8192),
            write_pending: BytesMut::with_capacity(8192),
        }
    }

    /// Derive rotating XOR mask for a given segment count.
    fn derive_xor_mask(entropy_key: &[u8; 16], counter: u64) -> [u8; 4] {
        let mut data = [0u8; 24];
        data[..16].copy_from_slice(entropy_key);
        data[16..24].copy_from_slice(&counter.to_le_bytes());
        let hash = blake3::hash(&data);
        let mut mask = [0u8; 4];
        mask.copy_from_slice(&hash.as_bytes()[0..4]);
        mask
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> TrinityTransport for ShadowMieruStream<S> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ShadowMieruStream: carrier switching not supported",
        ))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn handover(self, _new_carrier: BoxedTrinityTransport) -> Result<Self>
    where
        Self: Sized,
    {
        Err(anyhow::anyhow!("Handover not supported on ShadowMieruStream"))
    }

    fn get_transport_info(&self) -> TransportStats {
        TransportStats {
            rtt_ms: 0,
            jitter_ms: 0,
            buffer_usage_bytes: self.read_buf.len() + self.write_pending.len(),
            isp_asn: None,
            ..Default::default()
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowMieruStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.as_mut().project();

        // 1. Read raw bytes from downstream socket into internal buffer
        let mut temp_buf = [0u8; 4096];
        let mut temp_read_buf = ReadBuf::new(&mut temp_buf);
        match this.inner.as_mut().poll_read(cx, &mut temp_read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = temp_read_buf.filled();
                if filled.is_empty() && this.read_buf.is_empty() {
                    // Downstream closed EOF
                    return Poll::Ready(Ok(()));
                }
                this.read_buf.put_slice(filled);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.read_buf.is_empty() {
                    return Poll::Pending;
                }
            }
        }

        // 2. Loop to process buffered data and extract logical payloads
        loop {
            if this.read_buf.len() < 4 {
                return Poll::Pending;
            }

            // Peek 4-byte obfuscated header using rotating seed key mask
            let mask = Self::derive_xor_mask(this.entropy_key, *this.read_counter);
            let h_bytes: [u8; 4] = this.read_buf[0..4].try_into().unwrap();
            let decrypted = u32::from_be_bytes(h_bytes) ^ u32::from_be_bytes(mask);

            let segment_len = (decrypted & 0x000F_FFFF) as usize; // 20-bit allocation
            let padding_len = ((decrypted >> 20) & 0x0FFF) as usize; // 12-bit padding allocation

            if this.read_buf.len() < 4 + segment_len {
                // Wait for the full segment to assemble
                return Poll::Pending;
            }

            // Extract segment payload
            let mut segment = this.read_buf.split_to(4 + segment_len);
            segment.advance(4); // Remove header bytes

            // Strip decoy headers (HTTP/2 or WebRTC RTP)
            let decoy_header_len = match this.decoy_profile.as_str() {
                "http2" => 9,  // HTTP/2 frame header size
                "webrtc" => 12, // RTP header size
                _ => 0,
            };

            if segment_len < decoy_header_len + padding_len {
                warn!("Malformed SMR segment received: too short");
                *this.read_counter += 1;
                continue;
            }

            let payload_len = segment_len - decoy_header_len - padding_len;
            
            // Advance past the decoy header
            segment.advance(decoy_header_len);

            // Extract logical payload
            let payload = segment.split_to(payload_len);

            *this.read_counter += 1;

            if payload.is_empty() {
                // Was a junk frame, proceed to next segment in buffer
                continue;
            }

            // Yield payload to caller
            buf.put_slice(&payload);
            return Poll::Ready(Ok(()));
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowMieruStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.as_mut().project();

        // 1. Process pacing window
        let now = Instant::now();
        if now.duration_since(*this.window_start) >= Duration::from_millis(100) {
            *this.bytes_sent_window = 0;
            *this.window_start = now;
            *this.pacer_sleep = None;
        }

        // Check if we are waiting for pacer to expire
        if let Some(sleep) = this.pacer_sleep {
            match Pin::new(sleep).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    *this.bytes_sent_window = 0;
                    *this.window_start = Instant::now();
                    *this.pacer_sleep = None;
                }
            }
        }

        // 2. Check if we need to flush previous pending writes
        while !this.write_pending.is_empty() {
            match Pin::new(&mut *this.inner).poll_write(cx, this.write_pending) {
                Poll::Ready(Ok(n)) => {
                    this.write_pending.advance(n);
                }
                Poll::Ready(Err(e)) => {
                    if e.kind() == io::ErrorKind::TimedOut {
                        *this.consecutive_timeouts += 1;
                        if *this.consecutive_timeouts >= 3 {
                            // Scale down pacer speed by 15% p.a. steps to prevent collapse
                            let old_rate = *this.rate_bps;
                            *this.rate_bps = (*this.rate_bps as f64 * 0.85) as u64;
                            warn!(
                                "SMR: Persistent timeouts detected. Scaling down pacing rate: {} Mbps -> {} Mbps",
                                old_rate / 1_000_000,
                                *this.rate_bps / 1_000_000
                            );
                            *this.consecutive_timeouts = 0;
                        }
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Reset timeout counter on success
        *this.consecutive_timeouts = 0;

        // 3. Pacing enforcement: Check limit
        let max_allowed = (*this.rate_bps / 8) / 10; // 100ms window
        if *this.bytes_sent_window >= max_allowed {
            let elapsed = now.duration_since(*this.window_start);
            let remaining = Duration::from_millis(100).checked_sub(elapsed).unwrap_or(Duration::ZERO);
            let sleep_target = now + remaining;
            
            let mut sleep = Box::pin(tokio::time::sleep_until(sleep_target.into()));
            match Pin::new(&mut sleep).poll(cx) {
                Poll::Pending => {
                    *this.pacer_sleep = Some(sleep);
                    return Poll::Pending;
                }
                Poll::Ready(()) => {
                    *this.bytes_sent_window = 0;
                    *this.window_start = Instant::now();
                }
            }
        }

        // 4. Structure the outgoing packet under the MTU limit of 1280 bytes
        let decoy_header_len = match this.decoy_profile.as_str() {
            "http2" => 9,
            "webrtc" => 12,
            _ => 0,
        };

        // Max payload size to ensure the packet fits MTU
        let max_payload_len = 1280usize.saturating_sub(4 + decoy_header_len);
        if max_payload_len == 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "MTU limits exceeded by decoy structures")));
        }

        let payload_len = buf.len().min(max_payload_len);
        let payload = &buf[..payload_len];

        // Generative dynamic padding
        let target_size = this.mimic_profile.target_size();
        let current_size = 4 + decoy_header_len + payload_len;
        let mut padding_len = if current_size < target_size {
            target_size - current_size
        } else {
            0
        };

        // Enforce MTU constraint
        padding_len = padding_len.min(1280usize.saturating_sub(current_size));

        // Create packet payload buffer
        let segment_payload_len = decoy_header_len + payload_len + padding_len;
        let mut packet = BytesMut::with_capacity(4 + segment_payload_len);

        // Header construction with 20-bit segment length and 12-bit padding length
        let header_val = (segment_payload_len as u32 & 0x000F_FFFF) | (((padding_len as u32) & 0x0FFF) << 20);
        let mask = Self::derive_xor_mask(this.entropy_key, *this.write_counter);
        let encrypted_header = header_val ^ u32::from_be_bytes(mask);
        packet.put_u32(encrypted_header);

        // Decoy Header injection
        match this.decoy_profile.as_str() {
            "http2" => {
                // Mock HTTP/2 DATA frame header: 3 bytes length, 1 byte type (0x0 = DATA), 1 byte flags (0x0), 4 bytes Stream ID (e.g. 1)
                let frame_len = (payload_len + padding_len) as u32;
                packet.put_u8(((frame_len >> 16) & 0xFF) as u8);
                packet.put_u8(((frame_len >> 8) & 0xFF) as u8);
                packet.put_u8((frame_len & 0xFF) as u8);
                packet.put_u8(0x0); // Type: DATA
                packet.put_u8(0x0); // Flags
                packet.put_u32(1);   // Stream ID: 1
            }
            "webrtc" => {
                // Mock RTP header: V=2, P=0, X=0, CC=0, M=0, PT=96 (Dynamic), Seq = random, TS = increment, SSRC = 0x12345678
                packet.put_u8(0x80); // Version 2
                packet.put_u8(96);  // Payload type 96
                
                // Random seq and timestamp increments
                let mut rng = rand::thread_rng();
                packet.put_u16(rng.r#gen::<u16>()); // Sequence Number
                packet.put_u32((*this.write_counter as u32) * 160); // Timestamp
                packet.put_u32(0x12345678); // SSRC
            }
            _ => {}
        }

        // Add logical payload
        packet.put_slice(payload);

        // Generate dynamic high-entropy padding
        if padding_len > 0 {
            let mut padding_bytes = vec![0u8; padding_len];
            rand::thread_rng().fill_bytes(&mut padding_bytes);
            packet.put_slice(&padding_bytes);
        }

        // 5. Send packet
        let total_len = packet.len();
        match Pin::new(&mut *this.inner).poll_write(cx, &packet) {
            Poll::Ready(Ok(written)) => {
                *this.bytes_sent_window += written as u64;
                *this.write_counter += 1;
                
                if written < total_len {
                    // Buffer the remaining bytes
                    this.write_pending.put_slice(&packet[written..]);
                }
                
                // Report that we successfully accepted the entire payload_len of buf
                Poll::Ready(Ok(payload_len))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Buffer the entire constructed packet to try later
                this.write_pending.put_slice(&packet);
                *this.write_counter += 1;
                Poll::Ready(Ok(payload_len))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.as_mut().project();
        this.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.as_mut().project();
        this.inner.as_mut().poll_shutdown(cx)
    }
}
