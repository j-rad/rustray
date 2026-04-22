// src/transport/db_mimic.rs
//! Database Mimicry Transport
//!
//! Wraps arbitrary data streams in database wire protocols (PostgreSQL, Redis)
//! to evade DPI filters that block unknown protocols or look for specific signatures.

use crate::config::DbMimicConfig;
use crate::error::Result;
use bytes::{Buf, BufMut, BytesMut};
use md5::{Digest, Md5};
use rand_distr::{Distribution, Normal};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

// --- PostgreSQL Constants ---
const PG_STARTUP_MSG_CODE: i32 = 196608; // Protocol 3.0
const PG_TYPE_DATA_ROW: u8 = b'D';
const PG_TYPE_AUTH_REQUEST: u8 = b'R';
const PG_TYPE_READY_FOR_QUERY: u8 = b'Z';
const PG_TYPE_PASSWORD_MESSAGE: u8 = b'p';

// --- Redis Constants ---
const REDIS_BULK_STRING: u8 = b'$';

pub struct DbMimicStream {
    inner: TcpStream,
    protocol: DbProtocol,
    rx_buf: BytesMut,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DbProtocol {
    Postgres,
    Redis,
}

impl DbMimicStream {
    pub async fn connect(host: &str, port: u16, config: &DbMimicConfig) -> Result<Self> {
        let stream = TcpStream::connect((host, port)).await?;
        let protocol = match config.protocol.to_lowercase().as_str() {
            "redis" => DbProtocol::Redis,
            "postgresql" | "postgres" | "pg" => DbProtocol::Postgres,
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported DB protocol: {}",
                    config.protocol
                ));
            }
        };

        let mut mimic = Self {
            inner: stream,
            protocol,
            rx_buf: BytesMut::with_capacity(8192),
        };

        // Perform Initial Handshake
        mimic.handshake(config).await?;

        Ok(mimic)
    }

    async fn handshake(&mut self, config: &DbMimicConfig) -> Result<()> {
        match self.protocol {
            DbProtocol::Postgres => self.handshake_postgres(config).await,
            DbProtocol::Redis => self.handshake_redis(config).await,
        }
    }

    async fn handshake_postgres(&mut self, config: &DbMimicConfig) -> Result<()> {
        // 1. Send StartupMessage
        let user = config.user.as_deref().unwrap_or("postgres");
        let database = config.database.as_deref().unwrap_or("postgres");

        let mut buf = BytesMut::new();
        buf.put_i32(0); // Placeholder length
        buf.put_i32(PG_STARTUP_MSG_CODE);

        buf.put_slice(b"user\0");
        buf.put_slice(user.as_bytes());
        buf.put_u8(0);
        buf.put_slice(b"database\0");
        buf.put_slice(database.as_bytes());
        buf.put_u8(0);
        buf.put_u8(0); // Terminator

        let len = buf.len() as i32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());

        self.inner.write_all(&buf).await?;

        // 2. Loop until ReadyForQuery
        loop {
            let mut type_buf = [0u8; 1];
            self.inner.read_exact(&mut type_buf).await?;
            let msg_type = type_buf[0];

            let mut len_buf = [0u8; 4];
            self.inner.read_exact(&mut len_buf).await?;
            let msg_len = i32::from_be_bytes(len_buf) as usize;

            if msg_len < 4 {
                return Err(anyhow::anyhow!("Invalid PG message length: {}", msg_len));
            }

            let mut body = vec![0u8; msg_len - 4];
            if !body.is_empty() {
                self.inner.read_exact(&mut body).await?;
            }

            match msg_type {
                PG_TYPE_AUTH_REQUEST => {
                    let auth_type = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    match auth_type {
                        0 => {
                            // AuthOK
                            continue;
                        }
                        5 => {
                            // MD5 Password
                            let salt = &body[4..8];
                            let password = config.password_hash.as_deref().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Postgres MD5 auth requested but no password provided"
                                )
                            })?;

                            // concat("md5", md5(concat(md5(concat(password, username)), salt)))
                            let mut hasher = Md5::new();
                            hasher.update(password.as_bytes());
                            hasher.update(user.as_bytes());
                            let h1 = format!("{:x}", hasher.finalize_reset());

                            hasher.update(h1.as_bytes());
                            hasher.update(salt);
                            let h2 = format!("md5{:x}", hasher.finalize());

                            let mut pass_msg = BytesMut::with_capacity(h2.len() + 6);
                            pass_msg.put_u8(PG_TYPE_PASSWORD_MESSAGE);
                            pass_msg.put_i32((h2.len() + 5) as i32);
                            pass_msg.put_slice(h2.as_bytes());
                            pass_msg.put_u8(0);

                            self.inner.write_all(&pass_msg).await?;
                        }
                        _ => {
                            return Err(anyhow::anyhow!("Unsupported PG auth type: {}", auth_type));
                        }
                    }
                }
                PG_TYPE_READY_FOR_QUERY => {
                    break;
                }
                _ => {
                    // Ignore other messages during handshake (ParameterStatus, etc.)
                    continue;
                }
            }
        }

        Ok(())
    }

    async fn handshake_redis(&mut self, config: &DbMimicConfig) -> Result<()> {
        if let Some(user) = &config.user {
            let cmd = format!(
                "AUTH {} {}\r\n",
                user,
                config.password_hash.as_deref().unwrap_or("")
            );
            self.inner.write_all(cmd.as_bytes()).await?;
            let mut junk = [0u8; 128];
            let _ = self.inner.read(&mut junk).await?;
        }
        Ok(())
    }
}

// --- AsyncRead / AsyncWrite Implementation ---

impl AsyncRead for DbMimicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.rx_buf.is_empty() {
                let len = std::cmp::min(buf.remaining(), self.rx_buf.len());
                buf.put_slice(&self.rx_buf[..len]);
                self.rx_buf.advance(len);
                return Poll::Ready(Ok(()));
            }

            let mut temp_buf = [0u8; 8192];
            let mut read_buf = tokio::io::ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n > 0 {
                        let mut raw = &temp_buf[..n];
                        match self.protocol {
                            DbProtocol::Postgres => {
                                while raw.remaining() >= 5 {
                                    let msg_type = raw[0];
                                    // Postgres length includes self (4 bytes)
                                    let msg_len =
                                        i32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]])
                                            as usize;

                                    if raw.len() < 1 + msg_len {
                                        break; // Incomplete frame
                                    }

                                    if msg_type == PG_TYPE_DATA_ROW {
                                        // 'D' + Len(4) + ColCount(2) + [ColLen(4)+Bytes]
                                        // Header is 1 + 4 = 5 bytes. Body is msg_len - 4.
                                        // Body starts at raw[5].
                                        let mut body = &raw[5..1 + msg_len]; // Limit to this frame
                                        if body.remaining() >= 2 {
                                            let _col_count = body.get_i16();
                                            if body.remaining() >= 4 {
                                                let col_len = body.get_i32();
                                                if col_len >= 0 {
                                                    let ulen = col_len as usize;
                                                    if body.remaining() >= ulen {
                                                        self.rx_buf.put_slice(&body[..ulen]);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    raw.advance(1 + msg_len);
                                }
                            }
                            DbProtocol::Redis => {
                                // Stream-based parsing for RESP
                                // We are looking for BulkStrings: $<len>\r\n<data>\r\n
                                while raw.has_remaining() {
                                    // Check for Bulk String marker
                                    if raw[0] == REDIS_BULK_STRING {
                                        // Find first \r\n
                                        if let Some(idx) =
                                            raw.chunk().windows(2).position(|w| w == b"\r\n")
                                        {
                                            // Parse length
                                            if let Ok(len_str) =
                                                std::str::from_utf8(&raw.chunk()[1..idx])
                                                && let Ok(len) = len_str.parse::<i32>() {
                                                    let data_start = idx + 2;
                                                    if len >= 0 {
                                                        let ulen = len as usize;
                                                        // Check if we have the full payload + trailing \r\n
                                                        if raw.remaining() >= data_start + ulen + 2
                                                        {
                                                            self.rx_buf.put_slice(
                                                                &raw.chunk()
                                                                    [data_start..data_start + ulen],
                                                            );
                                                            raw.advance(data_start + ulen + 2);
                                                            continue;
                                                        }
                                                    } else if len == -1 {
                                                        // Null Bulk String, just skip
                                                        raw.advance(data_start);
                                                        continue;
                                                    }
                                                }
                                        }
                                        // Incomplete or invalid
                                        break;
                                    } else {
                                        // Skip unknown/protocol bytes (e.g. +OK, -Err)
                                        // Simply advance one byte to try to find sync
                                        // Real implementation might want to be smarter
                                        raw.advance(1);
                                    }
                                }
                            }
                        }
                    } else {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for DbMimicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let encoded = match self.protocol {
            DbProtocol::Postgres => {
                // Wrap in DataRow 'D'
                // Format: 'D' + Length(i32) + ColCount(i16) + ColLen(i32) + Data
                let mut frame = BytesMut::with_capacity(buf.len() + 11);
                frame.put_u8(PG_TYPE_DATA_ROW);
                frame.put_i32((buf.len() + 10) as i32); // Length
                frame.put_i16(1); // One column
                frame.put_i32(buf.len() as i32); // Column length
                frame.put_slice(buf);
                frame
            }
            DbProtocol::Redis => {
                let header = format!("${}\r\n", buf.len());
                let mut frame = BytesMut::with_capacity(header.len() + buf.len() + 2);
                frame.put_slice(header.as_bytes());
                frame.put_slice(buf);
                frame.put_slice(b"\r\n");
                frame
            }
        };

        match Pin::new(&mut self.inner).poll_write(cx, &encoded) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// --- Decoy Engine ---

/// Represents a whitelisted decoy target site for probe trapping.
#[derive(Debug, Clone)]
pub struct DecoyTarget {
    /// Address of the domestic whitelisted site (e.g., `shatelland.ir:443`).
    pub address: String,
    /// Human-readable label for logging.
    pub label: String,
}

impl Default for DecoyTarget {
    fn default() -> Self {
        Self {
            address: "10.10.34.35:443".to_string(),
            label: "shatelland-decoy".to_string(),
        }
    }
}

/// Configuration for the DecoyEngine's Gaussian TTFB delay.
#[derive(Debug, Clone)]
pub struct GaussianTtfbConfig {
    /// Mean delay in milliseconds (default: 45ms — matches Iranian ISP TTFB).
    pub mean_ms: f64,
    /// Standard deviation in milliseconds (default: 12ms).
    pub stddev_ms: f64,
    /// Minimum clamp value (prevents negative or zero delays).
    pub min_ms: f64,
    /// Maximum clamp value (prevents suspiciously long delays).
    pub max_ms: f64,
}

impl Default for GaussianTtfbConfig {
    fn default() -> Self {
        Self {
            mean_ms: 45.0,
            stddev_ms: 12.0,
            min_ms: 5.0,
            max_ms: 200.0,
        }
    }
}

impl GaussianTtfbConfig {
    /// Sample a jitter delay from this distribution.
    pub fn sample_delay(&self) -> std::time::Duration {
        let normal = Normal::new(self.mean_ms, self.stddev_ms)
            .unwrap_or_else(|_| Normal::new(45.0, 12.0).unwrap());
        let raw: f64 = normal.sample(&mut rand::thread_rng());
        let clamped = raw.clamp(self.min_ms, self.max_ms);
        std::time::Duration::from_micros((clamped * 1000.0) as u64)
    }
}

/// Active Decoy & Probe Trap Engine.
///
/// When a connection fails Flow-J authentication (i.e., the client does not
/// present valid proxy credentials), the DecoyEngine transparently proxies
/// the connection to a domestic whitelisted site so that:
///
/// 1. Active probes (GFW scanners) see a legitimate HTTPS service.
/// 2. Gaussian jitter on the TTFB makes timing analysis indistinguishable
///    from normal web browsing.
/// 3. Connection accounting tracks probe frequency for adaptive throttling.
pub struct DecoyEngine {
    /// Pool of decoy targets to round-robin through.
    targets: Vec<DecoyTarget>,
    /// Current target rotation index.
    target_idx: std::sync::atomic::AtomicUsize,
    /// Gaussian TTFB configuration.
    ttfb_config: GaussianTtfbConfig,
    /// Total connections served as decoys (for metrics).
    served_count: std::sync::atomic::AtomicU64,
    /// Total connections rejected (connect failures).
    failed_count: std::sync::atomic::AtomicU64,
    /// Maximum concurrent decoy sessions (rate-limiting).
    max_concurrent: usize,
    /// Current concurrent sessions.
    active_sessions: std::sync::atomic::AtomicUsize,
}

impl DecoyEngine {
    /// Create a new DecoyEngine with configurable targets and TTFB.
    pub fn new(
        targets: Vec<DecoyTarget>,
        ttfb_config: GaussianTtfbConfig,
        max_concurrent: usize,
    ) -> Self {
        let targets = if targets.is_empty() {
            vec![
                DecoyTarget::default(),
                DecoyTarget {
                    address: "shaparak.ir:443".to_string(),
                    label: "shaparak-decoy".to_string(),
                },
                DecoyTarget {
                    address: "digikala.com:443".to_string(),
                    label: "digikala-decoy".to_string(),
                },
            ]
        } else {
            targets
        };

        Self {
            targets,
            target_idx: std::sync::atomic::AtomicUsize::new(0),
            ttfb_config,
            served_count: std::sync::atomic::AtomicU64::new(0),
            failed_count: std::sync::atomic::AtomicU64::new(0),
            max_concurrent,
            active_sessions: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(Vec::new(), GaussianTtfbConfig::default(), 64)
    }

    /// Select the next decoy target (round-robin).
    fn next_target(&self) -> &DecoyTarget {
        let idx = self
            .target_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        &self.targets[idx % self.targets.len()]
    }

    /// Check if a connection should be treated as authenticated Flow-J traffic.
    ///
    /// Examines the first bytes of the TLS ClientHello for the expected Trojan
    /// password hash or VLESS UUID. If the authentication header is absent or
    /// invalid, the connection is presumed to be an active probe.
    ///
    /// Returns `true` if the connection is authenticated (real proxy client).
    pub fn check_flow_j_auth(initial_bytes: &[u8], expected_hash: &[u8]) -> bool {
        if initial_bytes.len() < expected_hash.len() {
            return false;
        }
        // Constant-time comparison to prevent timing side-channel
        let mut acc: u8 = 0;
        for (a, b) in initial_bytes.iter().zip(expected_hash.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }

    /// Serve a decoy response to a suspected active probe.
    ///
    /// Proxies the connection to a domestic whitelisted site with Gaussian
    /// jitter applied to the TTFB to evade timing analysis.
    pub async fn serve_decoy(&self, stream: &mut tokio::net::TcpStream) -> Result<()> {
        // Rate limiting check
        let active = self
            .active_sessions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if active >= self.max_concurrent {
            self.active_sessions
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.failed_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = stream.shutdown().await;
            return Ok(());
        }

        let target = self.next_target();

        let result = self.proxy_to_decoy(stream, target).await;

        self.active_sessions
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.served_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        result
    }

    /// Core proxy logic with Gaussian TTFB jitter.
    async fn proxy_to_decoy(
        &self,
        stream: &mut tokio::net::TcpStream,
        target: &DecoyTarget,
    ) -> Result<()> {
        // Connect to decoy target with a timeout
        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(&target.address),
        )
        .await;

        let mut target_stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => {
                self.failed_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = stream.shutdown().await;
                return Ok(());
            }
        };

        // Apply Gaussian TTFB jitter before forwarding the first response
        let delay = self.ttfb_config.sample_delay();
        tokio::time::sleep(delay).await;

        // Bidirectional proxy relay
        let _ = tokio::io::copy_bidirectional(stream, &mut target_stream).await;
        Ok(())
    }

    /// Get total number of decoy sessions served.
    pub fn served_count(&self) -> u64 {
        self.served_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total number of failed connections.
    pub fn failed_count(&self) -> u64 {
        self.failed_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current number of active decoy sessions.
    pub fn active_sessions(&self) -> usize {
        self.active_sessions
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Backward-compatible server struct wrapping DecoyEngine.
pub struct DbMimicServer;

impl DbMimicServer {
    /// Serve a decoy rejection to an active probe.
    /// This acts as a honeypot, proxying the connection to a domestic whitelisted site
    /// (e.g., shatelland.ir) over standard TCP with Gaussian jitter applied to the TTFB.
    pub async fn serve_decoy(stream: &mut tokio::net::TcpStream, _protocol: &str) -> Result<()> {
        let engine = DecoyEngine::with_defaults();
        engine.serve_decoy(stream).await
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gaussian_ttfb_config_default() {
        let config = GaussianTtfbConfig::default();
        assert!((config.mean_ms - 45.0).abs() < f64::EPSILON);
        assert!((config.stddev_ms - 12.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_gaussian_ttfb_delay_in_bounds() {
        let config = GaussianTtfbConfig::default();
        for _ in 0..1000 {
            let delay = config.sample_delay();
            let ms = delay.as_micros() as f64 / 1000.0;
            assert!(
                ms >= config.min_ms,
                "delay {} ms below min {} ms",
                ms,
                config.min_ms
            );
            assert!(
                ms <= config.max_ms,
                "delay {} ms above max {} ms",
                ms,
                config.max_ms
            );
        }
    }

    #[test]
    fn test_gaussian_ttfb_mean_approximation() {
        let config = GaussianTtfbConfig::default();
        let samples: Vec<f64> = (0..10_000)
            .map(|_| config.sample_delay().as_micros() as f64 / 1000.0)
            .collect();
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        // Mean should be within 3ms of configured mean (generous for 10K samples)
        assert!(
            (mean - config.mean_ms).abs() < 3.0,
            "sample mean {} ms too far from configured mean {} ms",
            mean,
            config.mean_ms
        );
    }

    #[test]
    fn test_flow_j_auth_valid() {
        let expected = b"abcdef1234567890abcdef1234567890";
        let incoming = b"abcdef1234567890abcdef1234567890extra_data_here";
        assert!(DecoyEngine::check_flow_j_auth(incoming, expected));
    }

    #[test]
    fn test_flow_j_auth_invalid() {
        let expected = b"abcdef1234567890abcdef1234567890";
        let incoming = b"WRONG_1234567890abcdef1234567890extra_data";
        assert!(!DecoyEngine::check_flow_j_auth(incoming, expected));
    }

    #[test]
    fn test_flow_j_auth_too_short() {
        let expected = b"abcdef1234567890abcdef1234567890";
        let incoming = b"abc";
        assert!(!DecoyEngine::check_flow_j_auth(incoming, expected));
    }

    #[test]
    fn test_decoy_engine_target_rotation() {
        let targets = vec![
            DecoyTarget {
                address: "a.com:443".to_string(),
                label: "a".to_string(),
            },
            DecoyTarget {
                address: "b.com:443".to_string(),
                label: "b".to_string(),
            },
        ];
        let engine = DecoyEngine::new(targets, GaussianTtfbConfig::default(), 10);

        let t1 = engine.next_target().address.clone();
        let t2 = engine.next_target().address.clone();
        let t3 = engine.next_target().address.clone();

        assert_eq!(t1, "a.com:443");
        assert_eq!(t2, "b.com:443");
        assert_eq!(t3, "a.com:443"); // wraps around
    }

    #[test]
    fn test_decoy_engine_default_targets() {
        let engine = DecoyEngine::with_defaults();
        assert_eq!(engine.targets.len(), 3);
        assert!(engine.targets[0].address.contains("10.10.34.35"));
    }

    #[test]
    fn test_decoy_engine_counters() {
        let engine = DecoyEngine::with_defaults();
        assert_eq!(engine.served_count(), 0);
        assert_eq!(engine.failed_count(), 0);
        assert_eq!(engine.active_sessions(), 0);
    }
}
