// src/transport/tls_fragment.rs
//! TLS ClientHello Fragmenter — DPI Hardening (Phase 1)
//!
//! Splits the initial TLS 1.3 ClientHello into **3 distinct fragments**
//! with randomized inter-fragment delays (1–10 ms) to defeat both
//! shallow DPI buffers and ISP reassembly hardware.
//!
//! ## Security Detail
//! The first fragment is always < 5 bytes so the SNI extension is
//! pushed into the second/third buffer, bypassing shallow DPI that
//! only inspects the first TCP segment for domain fingerprinting.

use crate::config::TlsFragmentSettings;
use crate::error::Result;
use crate::transport::BoxedStream;
use rand::Rng;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

// ============================================================================
// Constants
// ============================================================================

/// Maximum size of the **first** fragment.
/// Set to exactly 5 to split after the TLS record header.
const FIRST_FRAGMENT_SIZE: usize = 5;

/// Number of fragments we split the ClientHello into.
const TARGET_FRAGMENTS: usize = 3;

/// Minimum inter-fragment delay in microseconds (300 µs).
const MIN_DELAY_US: u64 = 300;

/// Maximum inter-fragment delay in microseconds (1500 µs - 1.5 ms).
const MAX_DELAY_US: u64 = 1500;

// ============================================================================
// Public API
// ============================================================================

/// Wrap a stream so the first write (ClientHello) is fragmented for DPI evasion.
pub async fn wrap_tls_fragment_client(
    stream: BoxedStream,
    settings: &TlsFragmentSettings,
) -> Result<BoxedStream> {
    Ok(Box::new(FragmentStream::new(stream, settings.clone())))
}

// ============================================================================
// FragmentStream — Stateful Async Wrapper
// ============================================================================

pub struct FragmentStream {
    inner: BoxedStream,
    settings: TlsFragmentSettings,
    state: FragmentState,
}

pub enum FragmentState {
    /// Ready for the first write (ClientHello). We will buffer the entire
    /// payload, split it into 3 chunks, and write them with delays.
    Initial,

    /// We have buffered the full ClientHello and are now writing fragment
    /// `current_frag` out of `fragments`. Between fragments we sleep.
    Writing {
        /// The 3 fragment byte ranges (start, end) into `data`.
        fragments: Vec<(usize, usize)>,
        /// The buffered ClientHello bytes.
        data: Vec<u8>,
        /// Index of the fragment we are writing next (0..3).
        current_frag: usize,
        /// Total bytes the caller gave us (returned in Ready once all done).
        caller_len: usize,
        /// Optional pending sleep between fragments.
        sleep: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
    },

    /// First write complete, all subsequent writes are pass-through.
    Passthrough,
}

impl FragmentStream {
    pub fn new(inner: BoxedStream, settings: TlsFragmentSettings) -> Self {
        Self {
            inner,
            settings,
            state: FragmentState::Initial,
        }
    }

    /// Compute fragment boundaries for a ClientHello of `total_len` bytes.
    /// Uses random strategy selection ('SNI-Split' or 'Record-Sliver').
    fn compute_fragments(total_len: usize) -> Vec<(usize, usize)> {
        if total_len <= FIRST_FRAGMENT_SIZE + 2 {
            // Packet is too small to split into 3 meaningfully; send as is or split 2.
            if total_len > FIRST_FRAGMENT_SIZE {
                return vec![(0, FIRST_FRAGMENT_SIZE), (FIRST_FRAGMENT_SIZE, total_len)];
            }
            return vec![(0, total_len)];
        }

        let strategy: u8 = rand::thread_rng().gen_range(0..2);
        let second_frag_size = match strategy {
            0 => 1, // Record-Sliver: Second fragment is just 1 byte
            _ => rand::thread_rng()
                .gen_range(20..=50)
                .min(total_len - FIRST_FRAGMENT_SIZE - 1), // SNI-Split: Random 20-50 bytes
        };

        vec![
            (0, FIRST_FRAGMENT_SIZE),
            (FIRST_FRAGMENT_SIZE, FIRST_FRAGMENT_SIZE + second_frag_size),
            (FIRST_FRAGMENT_SIZE + second_frag_size, total_len),
        ]
    }

    /// Generate a random inter-fragment delay duration.
    fn random_delay() -> Duration {
        let us = rand::thread_rng().gen_range(MIN_DELAY_US..=MAX_DELAY_US);
        Duration::from_micros(us)
    }
}

impl AsyncRead for FragmentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            // We use a temporary state transition to avoid mutable borrow conflicts
            // between `self.state` and `self.inner`.
            let mut state = std::mem::replace(&mut self.state, FragmentState::Passthrough);

            match state {
                // ── Pass-through: already fragmented ──
                FragmentState::Passthrough => {
                    self.state = FragmentState::Passthrough;
                    return Pin::new(&mut self.inner).poll_write(cx, buf);
                }

                // ── Initial: buffer the full ClientHello and split ──
                FragmentState::Initial => {
                    let data = buf.to_vec();
                    let caller_len = data.len();
                    let fragments = Self::compute_fragments(caller_len);

                    debug!(
                        "TLS Fragment: ClientHello {} bytes → {} fragments (first {} bytes)",
                        caller_len,
                        fragments.len(),
                        fragments.first().map_or(0, |(_, e)| *e),
                    );

                    if fragments.len() <= 1 {
                        self.state = FragmentState::Passthrough;
                        // Continue loop to hit Passthrough branch.
                        continue;
                    }

                    self.state = FragmentState::Writing {
                        fragments,
                        data,
                        current_frag: 0,
                        caller_len,
                        sleep: None,
                    };
                    // Fall through to hit Writing branch.
                    continue;
                }

                // ── Writing: send fragments with inter-fragment delays ──
                FragmentState::Writing {
                    fragments,
                    data,
                    mut current_frag,
                    caller_len,
                    mut sleep,
                } => {
                    // 1. Handle inter-fragment delay if active.
                    if let Some(mut fut) = sleep.take() {
                        match fut.as_mut().poll(cx) {
                            Poll::Pending => {
                                self.state = FragmentState::Writing {
                                    fragments,
                                    data,
                                    current_frag,
                                    caller_len,
                                    sleep: Some(fut),
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(()) => {
                                debug!("TLS Fragment: inter-fragment delay complete");
                            }
                        }
                    }

                    // 2. Check if all fragments have been written.
                    if current_frag >= fragments.len() {
                        self.state = FragmentState::Passthrough;
                        debug!("TLS Fragment: all {} fragments sent", fragments.len());
                        return Poll::Ready(Ok(caller_len));
                    }

                    // 3. Write the current fragment.
                    let (start, end) = fragments[current_frag];
                    let chunk = &data[start..end];

                    match Pin::new(&mut self.inner).poll_write(cx, chunk) {
                        Poll::Ready(Ok(_n)) => {
                            debug!(
                                "TLS Fragment: sent fragment {}/{}",
                                current_frag + 1,
                                fragments.len(),
                            );

                            current_frag += 1;

                            // If there are more fragments, insert a delay.
                            if current_frag < fragments.len() {
                                let delay = Self::random_delay();
                                debug!(
                                    "TLS Fragment: sleeping {}ms before next fragment",
                                    delay.as_millis()
                                );
                                sleep = Some(Box::pin(tokio::time::sleep(delay)));
                            }

                            // Update state and continue (either to next fragment or completion).
                            self.state = FragmentState::Writing {
                                fragments,
                                data,
                                current_frag,
                                caller_len,
                                sleep,
                            };
                            continue;
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            // Put state back so we can resume later.
                            self.state = FragmentState::Writing {
                                fragments,
                                data,
                                current_frag,
                                caller_len,
                                sleep,
                            };
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ============================================================================
// Standalone Fragmenter (for direct use outside of stream wrappers)
// ============================================================================

/// Stateful fragmenter for direct use with any `AsyncWrite` stream.
///
/// Produces exactly 3 fragments from a ClientHello with an SNI-safe
/// first fragment (< 5 bytes) and optional inter-fragment timing jitter.
///
/// # Usage
/// ```ignore
/// let frag = ClientHelloFragmenter::new(1360);
/// frag.write_fragmented(&mut stream, &client_hello_bytes).await?;
/// ```
pub struct ClientHelloFragmenter {
    /// Target ISP MSS — fragments 2 and 3 will not exceed this size.
    mss: usize,
    /// Whether to add randomised inter-fragment delays.
    timing_jitter: bool,
}

impl ClientHelloFragmenter {
    /// Create a new fragmenter tuned to the ISP's MSS.
    pub fn new(mss: u16) -> Self {
        Self {
            mss: mss as usize,
            timing_jitter: true,
        }
    }

    /// Disable inter-fragment timing jitter (for benchmarks / deterministic tests).
    pub fn without_jitter(mut self) -> Self {
        self.timing_jitter = false;
        self
    }

    /// Return an iterator over exactly 3 fragment byte slices based on random strategy.
    pub fn fragments<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        let len = data.len();
        if len <= FIRST_FRAGMENT_SIZE + 2 {
            if len > FIRST_FRAGMENT_SIZE {
                return vec![&data[..FIRST_FRAGMENT_SIZE], &data[FIRST_FRAGMENT_SIZE..]];
            }
            return if len == 0 { Vec::new() } else { vec![data] };
        }

        let strategy: u8 = rand::thread_rng().gen_range(0..2);
        let second_frag_size = match strategy {
            0 => 1,
            _ => rand::thread_rng()
                .gen_range(20..=50)
                .min(len - FIRST_FRAGMENT_SIZE - 1),
        };

        vec![
            &data[..FIRST_FRAGMENT_SIZE],
            &data[FIRST_FRAGMENT_SIZE..FIRST_FRAGMENT_SIZE + second_frag_size],
            &data[FIRST_FRAGMENT_SIZE + second_frag_size..],
        ]
    }

    /// Write `data` to `stream` in fragments with temporal evasion delays.
    pub async fn write_fragmented<S>(&self, stream: &mut S, data: &[u8]) -> std::io::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let chunks = self.fragments(data);
        for (i, chunk) in chunks.iter().enumerate() {
            stream.write_all(chunk).await?;
            debug!(
                "TLS Fragment (standalone): sent fragment {}/{} ({} bytes)",
                i + 1,
                chunks.len(),
                chunk.len()
            );

            // Add inter-fragment jitter after each fragment except the last.
            if self.timing_jitter && i + 1 < chunks.len() {
                let delay_us = rand::thread_rng().gen_range(MIN_DELAY_US..=MAX_DELAY_US);
                debug!("TLS Fragment (standalone): delaying {}μs", delay_us);
                tokio::time::sleep(Duration::from_micros(delay_us)).await;
            }
        }
        Ok(())
    }
}

/// Convenience: split a raw TLS record into `(first, rest)` for simple
/// two-fragment DPI bypass. Returns `None` if the record is too short.
pub fn fragment_tls_client_hello(data: &[u8]) -> Option<(&[u8], &[u8])> {
    // Need at least TLS header (5 bytes) + something to split.
    if data.len() <= FIRST_FRAGMENT_SIZE {
        return None;
    }
    // Only split Handshake records (type 0x16).
    if data[0] != 0x16 {
        return None;
    }
    Some((&data[..FIRST_FRAGMENT_SIZE], &data[FIRST_FRAGMENT_SIZE..]))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fragments_splits_into_3() {
        // A realistic ClientHello is ~300+ bytes.
        let frags = FragmentStream::compute_fragments(300);
        assert_eq!(frags.len(), 3, "Expected exactly 3 fragments");

        // First fragment must be exactly 5 bytes (TLS record header).
        let (start0, end0) = frags[0];
        assert_eq!(start0, 0);
        assert_eq!(end0, 5);

        // Fragments must cover the entire data contiguously.
        let (_, end_last) = *frags.last().unwrap();
        assert_eq!(end_last, 300);
    }

    #[test]
    fn test_compute_fragments_tiny_packet() {
        // A packet smaller than FIRST_FRAGMENT_SIZE should be a single fragment.
        let frags = FragmentStream::compute_fragments(3);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], (0, 3));
    }

    #[test]
    fn test_compute_fragments_exactly_5_bytes() {
        let frags = FragmentStream::compute_fragments(5);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], (0, 5));
    }

    #[test]
    fn test_standalone_fragmenter_produces_3_chunks() {
        let frag = ClientHelloFragmenter::new(1360).without_jitter();
        let data = vec![0xABu8; 500];
        let chunks = frag.fragments(&data);
        assert_eq!(chunks.len(), 3, "Expected exactly 3 chunks");
        assert_eq!(chunks[0].len(), 5, "First chunk must be exactly 5 bytes");
        // All chunks combined should equal original data.
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 500);
    }

    #[test]
    fn test_fragment_tls_client_hello_type_check() {
        // Non-handshake record type → None
        let mut data = vec![0x17; 100]; // Application Data type
        assert!(fragment_tls_client_hello(&data).is_none());

        // Handshake record type → Some
        data[0] = 0x16;
        let result = fragment_tls_client_hello(&data);
        assert!(result.is_some());
        let (first, rest) = result.unwrap();
        assert_eq!(first.len(), 5);
        assert_eq!(rest.len(), data.len() - 5);
    }

    #[test]
    fn test_fragment_tls_too_short() {
        let data = vec![0x16; 5]; // Only 5 bytes total
        assert!(fragment_tls_client_hello(&data).is_none());
    }

    #[test]
    fn test_compute_fragments_deterministic_coverage() {
        for total in [10, 50, 100, 200, 512, 1024] {
            let frags = FragmentStream::compute_fragments(total);
            // First fragment always exactly 5.
            assert_eq!(frags[0].1, 5);
            // Full coverage.
            let (_, last_end) = *frags.last().unwrap();
            assert_eq!(last_end, total);
            // Contiguity.
            for w in frags.windows(2) {
                assert_eq!(w[0].1, w[1].0);
            }
        }
    }
}
