// src/protocols/hysteria2.rs
//!
//! Hysteria 2 Protocol Implementation
//!
//! Hysteria 2 is a high-performance proxy protocol that uses QUIC with a custom
//! "Brutal" congestion control algorithm designed for high-bandwidth, high-latency
//! networks. It masquerades as HTTP/3 traffic to evade censorship.

use crate::app::stats::StatsManager;
use crate::config::{Hysteria2OutboundSettings, Hysteria2Settings, LevelPolicy, Obfuscation};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::{BoxedStream, quic};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use std::future::Future;
use std::io::{self};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;
use tokio::time::Sleep;
use tracing::{debug, info, warn};

// --- Constants ---

/// ALPN for Hysteria 2
pub const ALPN_HY2: &[u8] = b"h3";

/// Frame types
mod frame_type {
    pub const AUTH: u8 = 0x00;
    pub const CONNECT: u8 = 0x01;
}

/// Authentication result codes
mod auth_result {
    pub const SUCCESS: u8 = 0x00;
    pub const FAILED: u8 = 0x01;
}

/// Default bandwidth limits (in Mbps)
const DEFAULT_UP_MBPS: u64 = 100;
const DEFAULT_DOWN_MBPS: u64 = 100;

/// Brutal congestion control parameters
const BRUTAL_PACING_GAIN: f64 = 1.25;
const BRUTAL_MIN_CWND: u64 = 4;

/// Salamander obfuscation key derivation salt
const SALAMANDER_SALT: &[u8] = b"hysteria2-salamander-obfs";

// --- Obfuscation ---

/// Salamander obfuscation state
pub struct SalamanderObfs {
    /// Encryption key derived from password
    key: [u8; 32],
    /// Nonce counter
    nonce_counter: AtomicU64,
}

impl SalamanderObfs {
    /// Create a new Salamander obfuscator from password
    pub fn new(password: &str) -> Self {
        let key = Self::derive_key(password);
        Self {
            key,
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// Derive key from password using BLAKE3
    fn derive_key(password: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SALAMANDER_SALT);
        hasher.update(password.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Obfuscate a packet (XOR with keystream)
    pub fn obfuscate(&self, data: &mut [u8]) {
        let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.key);
        hasher.update(&nonce.to_le_bytes());
        let keystream = hasher.finalize();

        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= keystream.as_bytes()[i % 32];
        }
    }

    /// Deobfuscate a packet (same as obfuscate due to XOR)
    pub fn deobfuscate(&self, data: &mut [u8]) {
        self.obfuscate(data);
    }
}

// --- Brutal Congestion Control ---

/// Brutal congestion control state
pub struct BrutalCongestion {
    /// Target sending rate in bytes per second
    target_rate_bps: u64,
    /// Current congestion window
    cwnd: AtomicU64,
    /// Bytes sent in current window
    bytes_sent: AtomicU64,
    /// Smoothed RTT estimate
    #[allow(dead_code)]
    srtt_ms: AtomicU64,
    /// Minimum RTT observed
    #[allow(dead_code)]
    min_rtt_ms: AtomicU64,
    /// Token bucket for rate limiting
    tokens: AtomicU64,
    /// Last token refill time
    last_refill: Mutex<Instant>,
}

impl BrutalCongestion {
    /// Create a new Brutal congestion controller
    pub fn new(upload_mbps: u64) -> Self {
        let target_rate_bps = upload_mbps * 1_000_000 / 8; // Convert Mbps to bytes/s
        let initial_cwnd = std::cmp::max(
            target_rate_bps * 100 / 1000, // 100ms of data
            BRUTAL_MIN_CWND * 1500,                // Minimum of 4 packets
        );

        Self {
            target_rate_bps,
            cwnd: AtomicU64::new(initial_cwnd),
            bytes_sent: AtomicU64::new(0),
            srtt_ms: AtomicU64::new(50), // Initial RTT estimate
            min_rtt_ms: AtomicU64::new(u64::MAX),
            tokens: AtomicU64::new(initial_cwnd),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Consume tokens for sending
    pub fn consume(&self, bytes: u64) {
        self.tokens.fetch_sub(
            bytes.min(self.tokens.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Refill tokens based on elapsed time
    #[allow(dead_code)]
    async fn refill_tokens(&self) {
        let mut last_refill = self.last_refill.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);

        // Calculate how many bytes we can send in elapsed time
        let new_tokens = (elapsed.as_secs_f64() * self.target_rate_bps as f64) as u64;

        if new_tokens > 0 {
            let max_tokens = self.cwnd.load(Ordering::Relaxed) * 2;
            let current = self.tokens.load(Ordering::Relaxed);
            let new_total = (current + new_tokens).min(max_tokens);
            self.tokens.store(new_total, Ordering::Relaxed);
            *last_refill = now;
        }
    }

    /// Calculate pacing delay for a given packet size
    pub fn pacing_delay(&self, bytes: u64) -> Duration {
        let rate = self.target_rate_bps as f64 * BRUTAL_PACING_GAIN;
        let seconds = bytes as f64 / rate;
        Duration::from_secs_f64(seconds)
    }
}

// --- Authentication ---

/// Authentication frame
#[derive(Debug, Clone)]
pub struct AuthFrame {
    /// Authentication type
    pub auth_type: u8,
    /// Password/token
    pub password: String,
    /// Requested upload bandwidth (Mbps)
    pub upload_mbps: u64,
    /// Requested download bandwidth (Mbps)
    pub download_mbps: u64,
}

impl AuthFrame {
    /// Parse authentication frame from stream
    pub async fn parse<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let auth_type = reader.read_u8().await?;
        let password_len = reader.read_u16().await? as usize;

        let mut password_bytes = vec![0u8; password_len];
        reader.read_exact(&mut password_bytes).await?;
        let password = String::from_utf8(password_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid password encoding"))?;

        let upload_mbps = reader.read_u64().await?;
        let download_mbps = reader.read_u64().await?;

        Ok(Self {
            auth_type,
            password,
            upload_mbps,
            download_mbps,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let password_bytes = self.password.as_bytes();
        let mut buf = BytesMut::with_capacity(1 + 2 + password_bytes.len() + 8 + 8);

        buf.put_u8(self.auth_type);
        buf.put_u16(password_bytes.len() as u16);
        buf.put_slice(password_bytes);
        buf.put_u64(self.upload_mbps);
        buf.put_u64(self.download_mbps);

        buf
    }
}

/// Authentication response
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub result: u8,
    pub message: String,
    pub server_upload_mbps: u64,
    pub server_download_mbps: u64,
}

impl AuthResponse {
    pub fn success(upload: u64, download: u64) -> Self {
        Self {
            result: auth_result::SUCCESS,
            message: String::new(),
            server_upload_mbps: upload,
            server_download_mbps: download,
        }
    }

    pub fn failed(message: &str) -> Self {
        Self {
            result: auth_result::FAILED,
            message: message.to_string(),
            server_upload_mbps: 0,
            server_download_mbps: 0,
        }
    }

    pub async fn parse<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let result = reader.read_u8().await?;
        let message_len = reader.read_u16().await? as usize;

        let mut message_bytes = vec![0u8; message_len];
        reader.read_exact(&mut message_bytes).await?;
        let message = String::from_utf8(message_bytes).unwrap_or_default();

        let server_upload_mbps = reader.read_u64().await?;
        let server_download_mbps = reader.read_u64().await?;

        Ok(Self {
            result,
            message,
            server_upload_mbps,
            server_download_mbps,
        })
    }

    pub fn to_bytes(&self) -> BytesMut {
        let message_bytes = self.message.as_bytes();
        let mut buf = BytesMut::with_capacity(1 + 2 + message_bytes.len() + 8 + 8);

        buf.put_u8(self.result);
        buf.put_u16(message_bytes.len() as u16);
        buf.put_slice(message_bytes);
        buf.put_u64(self.server_upload_mbps);
        buf.put_u64(self.server_download_mbps);

        buf
    }
}

// --- HTTP/3 Masquerading ---

/// HTTP/3 masquerade handler
pub struct Http3Masquerade {}

impl Http3Masquerade {
    /// Read variable-length integer (QUIC VARINT)
    #[allow(dead_code)]
    fn read_varint(data: &[u8]) -> Option<u64> {
        if data.is_empty() {
            return None;
        }

        let first = data[0];
        let len = 1 << (first >> 6);

        if data.len() < len {
            return None;
        }

        let mut value = (first & 0x3f) as u64;
        for byte in data[1..len].iter() {
            value = (value << 8) | (*byte as u64);
        }

        Some(value)
    }

    /// Calculate varint size
    #[allow(dead_code)]
    fn varint_size(value: u64) -> usize {
        if value < 64 {
            1
        } else if value < 16384 {
            2
        } else if value < 1073741824 {
            4
        } else {
            8
        }
    }
}

// --- Inbound Handler ---

/// Handle incoming Hysteria 2 connection
pub async fn handle_inbound_stream(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    mut stream: BoxedStream,
    settings: Arc<Hysteria2Settings>,
    source: String,
) -> Result<()> {
    debug!("Hysteria2: Handling new inbound stream from {}", source);

    // Fix for peek: Read a small chunk to detect frame type
    let mut header_buf = [0u8; 1];
    if stream.read_exact(&mut header_buf).await.is_err() {
        return Err(anyhow::anyhow!("Hysteria2: Failed to read stream header"));
    }

    let first_byte = header_buf[0];

    // Construct a PrefixedStream so we can read subsequent data seamlessly
    // But since BoxedStream is generic and we read one byte, we can just use that knowledge.
    // However, AuthFrame::parse expects the TYPE byte.
    // So we use PrefixedStream to put it back conceptually.
    // Wait, stream is &mut BoxedStream? No, it's BoxedStream.
    // stream is `Box<dyn AsyncStream>`.

    // Since we consumed `stream` into `PrefixedStream`, we must use the new wrapper.
    let mut stream = PrefixedStream::new(header_buf, stream);

    let auth_frame = if first_byte == frame_type::AUTH {
        // Auth Frame
        AuthFrame::parse(&mut stream).await?
    } else {
        // Masquerade Frame (e.g. HTTP/3 HEADERS)
        // 1. Read VarInt length (we already have first byte, need rest of varint)
        // We use a helper that handles the prefix logic internally or just read from our stream.
        let length = read_varint_from_stream(&mut stream).await?;

        // 2. Discard payload
        let mut discard = vec![0u8; length as usize];
        stream.read_exact(&mut discard).await?;

        debug!("Hysteria2: Stripped masquerade frame of {} bytes", length);

        // 3. Now verify Auth Frame follows
        AuthFrame::parse(&mut stream).await?
    };

    // Verify authentication
    let expected_password = settings.password.as_deref().unwrap_or("");

    if auth_frame.password != expected_password {
        warn!("Hysteria2: Authentication failed");
        let response = AuthResponse::failed("Invalid password");
        stream.write_all(&response.to_bytes()).await?;
        stream.flush().await?;
        return Err(anyhow::anyhow!("Hysteria2: Authentication failed"));
    }

    info!("Hysteria2: Authentication successful");

    // Negotiate bandwidth limits
    let server_up = settings.up_mbps.unwrap_or(DEFAULT_UP_MBPS);
    let server_down = settings.down_mbps.unwrap_or(DEFAULT_DOWN_MBPS);

    let negotiated_up = auth_frame.upload_mbps.min(server_up);
    let negotiated_down = auth_frame.download_mbps.min(server_down);

    // Send success response
    let response = AuthResponse::success(negotiated_up, negotiated_down);
    stream.write_all(&response.to_bytes()).await?;
    stream.flush().await?;

    // Handle Connection Request
    // After Auth, client sends a Request Frame?
    // Spec: "Client sends Auth. Server sends Response. Client sends Data."
    // Data stream starts with Connect Request?
    // Hysteria 2 stream format: [FrameType][FramePayload]
    // If we are here, we are authenticated. The next frame should be CONNECT (0x01) or UDP (0x02).

    let frame_type = stream.read_u8().await?;
    if frame_type == frame_type::CONNECT {
        // Parse Connect Request
        // Format: [DomainLen][Domain][Port]
        let domain_len = stream.read_u8().await? as usize;
        let mut domain_bytes = vec![0u8; domain_len];
        stream.read_exact(&mut domain_bytes).await?;
        let host =
            String::from_utf8(domain_bytes).map_err(|_| anyhow::anyhow!("Invalid domain"))?;
        let port = stream.read_u16().await?;

        info!("Hysteria2 Connect: {}:{}", host, port);

        // Route
        // Create Brutal congestion controller
        // Note: Congestion control is usually per-connection (UDP session), not per-stream?
        // Hysteria 2 maps streams to QUIC streams.
        // We wrap the stream.

        // We need to re-box the stream because it's now a PrefixedStream.
        let stream: BoxedStream = Box::new(stream);

        // Add Obfuscation/Brutal if needed
        // For simplicity, passing directly for now as router expects BoxedStream.

        let policy = state.policy_manager.get_policy(0); // Default level
        router
            .route_stream(stream, host, port, source, policy)
            .await
    } else {
        Err(anyhow::anyhow!(
            "Unsupported Hysteria2 frame type: {}",
            frame_type
        ))
    }
}

// Helper to read QUIC VarInt from AsyncRead
async fn read_varint_from_stream<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await?;
    let first = buf[0];
    let prefix = first >> 6;
    let length = 1 << prefix;

    let mut raw_val = (first & 0x3f) as u64;
    for _ in 1..length {
        reader.read_exact(&mut buf).await?;
        raw_val = (raw_val << 8) | (buf[0] as u64);
    }
    Ok(raw_val)
}

// --- Stream Wrapper with Brutal Rate Limiting ---

pub struct BrutalStreamWrapper<S> {
    inner: S,
    congestion: Arc<BrutalCongestion>,
    obfs: Option<Arc<SalamanderObfs>>,
    // Pacing sleep future
    pacing_sleep: Option<Pin<Box<Sleep>>>,
    // Scratch buffer for encryption to avoid allocation
    scratch_buf: Vec<u8>,
    // Unique ID for metric tracking
    conn_id: String,
}

impl<S> BrutalStreamWrapper<S> {
    pub fn new(
        inner: S,
        upload_mbps: u64,
        obfs: Option<Arc<SalamanderObfs>>,
        host: &str,
        port: u16,
    ) -> Self {
        Self {
            inner,
            congestion: Arc::new(BrutalCongestion::new(upload_mbps)),
            obfs,
            pacing_sleep: None,
            scratch_buf: Vec::with_capacity(2048), // Reasonable MTU size
            conn_id: format!("{}:{}", host, port),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BrutalStreamWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Read from inner stream
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        // If we have obfuscation, deobfuscate
        if let Poll::Ready(Ok(())) = &poll
            && let Some(ref obfs) = self.obfs {
                let filled = buf.filled_mut();
                obfs.deobfuscate(filled);
            }

        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BrutalStreamWrapper<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. Check Pacing
        if let Some(ref mut sleep) = this.pacing_sleep {
            match sleep.as_mut().poll(cx) {
                Poll::Ready(_) => {
                    this.pacing_sleep = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let bytes_to_send = buf.len() as u64;

        // 2. Check tokens using relaxed load (non-async part)
        this.congestion.refill_tokens_sync();
        let tokens = this.congestion.tokens.load(Ordering::Relaxed);

        if tokens < bytes_to_send {
            // Not enough tokens. Calculate delay.
            let delay = this.congestion.pacing_delay(bytes_to_send);
            let sleep = tokio::time::sleep(delay);
            this.pacing_sleep = Some(Box::pin(sleep));

            // Poll the new sleep immediately to register waker
            match this.pacing_sleep.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Ready(_) => {
                    this.pacing_sleep = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // 3. Obfuscate using scratch buffer
        let data_to_write = if let Some(ref obfs) = this.obfs {
            // Ensure scratch buffer is large enough
            if this.scratch_buf.len() < buf.len() {
                this.scratch_buf.resize(buf.len(), 0);
            }

            // Copy data to scratch
            this.scratch_buf[..buf.len()].copy_from_slice(buf);

            let slice = &mut this.scratch_buf[..buf.len()];
            obfs.obfuscate(slice);
            &*slice
        } else {
            buf
        };

        // 4. Write
        match Pin::new(&mut this.inner).poll_write(cx, data_to_write) {
            Poll::Ready(Ok(n)) => {
                this.congestion.consume(n as u64);

                // Push metrics to StatsManager
                if let Some(stats) = StatsManager::global() {
                    let rtt = this.congestion.srtt_ms.load(Ordering::Relaxed);
                    let cwnd = this.congestion.cwnd.load(Ordering::Relaxed);
                    stats.update_connection_metrics(
                        &this.conn_id,
                        rtt,
                        cwnd,
                        crate::app::stats::DpiState::Clear,
                    );
                }

                Poll::Ready(Ok(n))
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

// Helper extension for BrutalCongestion to work synchronously in poll_write
impl BrutalCongestion {
    fn refill_tokens_sync(&self) {
        // We use a TryLock or similar? Mutex is async.
        // We can use std::sync::Mutex or parking_lot if we need sync access in poll.
        // Or AtomicU64 for last_refill timestamp (if we treat Instant as u64 nanos).
        // For simplicity, if we cannot lock immediately, we skip refill (tokens refill next time).

        if let Ok(mut last_refill) = self.last_refill.try_lock() {
            let now = Instant::now();
            let elapsed = now.duration_since(*last_refill);
            let new_tokens = (elapsed.as_secs_f64() * self.target_rate_bps as f64) as u64;

            if new_tokens > 0 {
                let max_tokens = self.cwnd.load(Ordering::Relaxed) * 2;
                let current = self.tokens.load(Ordering::Relaxed);
                let new_total = (current + new_tokens).min(max_tokens);
                self.tokens.store(new_total, Ordering::Relaxed);
                *last_refill = now;
            }
        }
    }
}

// Temporary struct to allow stream construction logic
struct PrefixedStream<S> {
    prefix: Option<[u8; 1]>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: [u8; 1], inner: S) -> Self {
        Self {
            prefix: Some(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(p) = self.prefix {
            buf.put_slice(&p);
            self.prefix = None;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// --- Connection State ---

/// Connection state with authentication tracking
struct ConnectionState {
    conn: quic::QuicConnection,
    last_used: Instant,
    is_authenticated: bool,
}

impl ConnectionState {
    #[allow(dead_code)]
    fn new(conn: quic::QuicConnection) -> Self {
        Self {
            conn,
            last_used: Instant::now(),
            is_authenticated: false,
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

// --- Outbound Handler ---

/// Hysteria 2 Outbound Handler
pub struct Hysteria2Outbound {
    settings: Hysteria2OutboundSettings,
    // Shared QUIC connection with auth state
    connection: Arc<Mutex<Option<ConnectionState>>>,
}

impl Hysteria2Outbound {
    pub fn new(settings: Hysteria2OutboundSettings) -> Self {
        Self {
            settings,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    /// Get or establish and authenticate a QUIC connection
    async fn get_or_auth_connection(&self) -> Result<quic::QuicConnection> {
        let mut guard = self.connection.lock().await;

        // Check existing connection
        if let Some(state) = guard.as_mut() {
            // Health check
            if !state.conn.is_closed().await {
                state.touch();

                // If already authenticated, return immediately
                if state.is_authenticated {
                    return Ok(state.conn.clone());
                }

                // Connection exists but not authenticated - authenticate it
                self.authenticate_connection(&mut state.conn).await?;
                state.is_authenticated = true;
                return Ok(state.conn.clone());
            }

            // Connection is closed, clear it
            *guard = None;
        }

        // Establish new connection
        let address = self.settings.address.parse()?;
        let server_name = self.settings.server_name.clone().unwrap_or_default();
        let mut conn = quic::connect(address, &server_name, &[ALPN_HY2], None).await?;

        // Authenticate the new connection
        self.authenticate_connection(&mut conn).await?;

        // Store authenticated connection
        *guard = Some(ConnectionState {
            conn: conn.clone(),
            last_used: Instant::now(),
            is_authenticated: true,
        });

        Ok(conn)
    }

    /// Authenticate a QUIC connection (called once per connection)
    async fn authenticate_connection(&self, conn: &mut quic::QuicConnection) -> Result<()> {
        // Open control stream for authentication
        let mut auth_stream = conn.open_stream().await?;

        // Send Auth Frame
        let auth_frame = AuthFrame {
            auth_type: frame_type::AUTH,
            password: self.settings.password.clone().unwrap_or_default(),
            upload_mbps: self.settings.up_mbps.unwrap_or(DEFAULT_UP_MBPS),
            download_mbps: self.settings.down_mbps.unwrap_or(DEFAULT_DOWN_MBPS),
        };
        auth_stream.write_all(&auth_frame.to_bytes()).await?;
        auth_stream.flush().await?;

        // Read Auth Response
        let auth_response = AuthResponse::parse(&mut auth_stream).await?;
        if auth_response.result != auth_result::SUCCESS {
            return Err(anyhow::anyhow!(
                "Hysteria2 Auth Failed: {}",
                auth_response.message
            ));
        }

        debug!(
            "Hysteria2: Connection authenticated. Server BW: Up={}, Down={}",
            auth_response.server_upload_mbps, auth_response.server_download_mbps
        );

        Ok(())
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    async fn handle<'a>(
        &'a self,
        mut stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut wrapped_out = self.dial(host, port).await?;

        // Relay
        crate::transport::copy_bidirectional(&mut stream, &mut wrapped_out).await?;

        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        // Get authenticated connection (auth happens once per connection)
        let mut connection = self.get_or_auth_connection().await?;

        // Open a new stream for this request
        let mut out_stream = connection.open_stream().await?;

        // Send Connect Request (no auth frame - already authenticated)
        out_stream.write_u8(frame_type::CONNECT).await?;
        let host_bytes = host.as_bytes();
        out_stream.write_u8(host_bytes.len() as u8).await?;
        out_stream.write_all(host_bytes).await?;
        out_stream.write_u16(port).await?;

        // Wrap with Brutal Congestion Control
        let obfs = if let Some(ref obfs_setting) = self.settings.obfuscation {
            match obfs_setting {
                Obfuscation {
                    obfs_type,
                    password,
                } if obfs_type == "Salamander" => Some(Arc::new(SalamanderObfs::new(password))),
                _ => None,
            }
        } else {
            None
        };

        let upload_limit = self.settings.up_mbps.unwrap_or(DEFAULT_UP_MBPS);
        let wrapped_out = BrutalStreamWrapper::new(out_stream, upload_limit, obfs, &host, port);

        Ok(Box::new(wrapped_out) as BoxedStream)
    }

    async fn handle_packet(
        &self,
        packet: Box<dyn crate::transport::Packet>,
        _reply_tx: Option<tokio::sync::mpsc::Sender<Box<dyn crate::transport::Packet>>>,
    ) -> Result<()> {
        let connection = self.get_or_auth_connection().await?;

        // Hysteria 2 UDP over Datagrams
        // We receive an IP packet? Or UDP payload?
        // Packet trait usually provides payload.
        // Assuming payload is the data to send.
        // Format: [Payload] (Raw datagram for now, as negotiated by ALPN h3/hy2 usually implies flow)
        // But without Masque, we send raw.
        // Note: Real implementation needs session ID if multiplexed.
        // For this task, we send the payload directly.

        connection.send_dgram(packet.payload()).await?;
        Ok(())
    }
}
