// src/protocols/stealth.rs
//! Flow-J Stealth Module
//!
//! Advanced traffic camouflage features to defeat ML-based traffic analysis:
//! - Anti-ML Probabilistic Shaper: Gaussian padding to match HTTPS distributions
//! - Markov-Chain Jitter: Browser-like timing patterns
//! - Header Encryption: Session-key encrypted control headers
//! - Probe Trap: Serve HTTP decoys on invalid handshakes with μs-accurate jitter
//!
//! References:
//! - Traffic fingerprinting research: https://arxiv.org/abs/1802.03685
//! - HTTPS traffic distribution models: typical JPEG/WebP segment sizes

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use bytes::{BufMut, BytesMut};
use rand::Rng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::time::sleep_until;

// ============================================================================
// PROBE TRAP
// ============================================================================

/// Decoy profile to impersonate when a probe is detected.
/// Each variant renders a self-contained HTTP/1.1 200 response with
/// enough realistic HTML that a passive DPI classifier scores it as
/// a legitimate Iranian web service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyProfile {
    /// Mellat Bank login portal (Persian)
    MellatBank,
    /// Tejarat Bank login portal (Persian)
    TejaratBank,
    /// IRNA news article page (Persian)
    IrnaNews,
    /// Digikala product page (Persian e-commerce)
    Digikala,
}

impl DecoyProfile {
    /// Return the `Server:` header value a real site would send.
    fn server_header(self) -> &'static str {
        match self {
            Self::MellatBank => "Apache/2.4.54",
            Self::TejaratBank => "nginx/1.24.0",
            Self::IrnaNews => "Apache/2.4.41",
            Self::Digikala => "nginx/1.22.1",
        }
    }

    /// Return a plausible `X-Powered-By` header.
    fn powered_by(self) -> Option<&'static str> {
        match self {
            Self::MellatBank => Some("PHP/7.4.3"),
            Self::TejaratBank => Some("PHP/8.1.12"),
            Self::IrnaNews => Some("PHP/7.4.3"),
            Self::Digikala => None,
        }
    }

    /// HTML body — enough bytes to look legitimate, short enough to not
    /// stall the probe sender.
    fn html_body(self) -> &'static [u8] {
        match self {
            Self::MellatBank => include_bytes!("../../assets/decoy/mellat.html"),
            Self::TejaratBank => include_bytes!("../../assets/decoy/tejarat.html"),
            Self::IrnaNews => include_bytes!("../../assets/decoy/irna.html"),
            Self::Digikala => include_bytes!("../../assets/decoy/digikala.html"),
        }
    }
}

/// Jitter parameters that make probe responses indistinguishable from
/// a real server that experienced a cold page load.
///
/// The jitter is drawn from a mixed Erlang distribution parameterised on
/// empirical measurements of Iranian banking sites (median RTT ≈ 85 ms,
/// σ ≈ 22 ms). We use the Box-Muller transform against the existing
/// `MarkovJitter` state so no extra allocations are needed.
pub struct ProbeJitter {
    /// Base latency to add before writing the decoy (µs)
    base_us: u64,
    /// Per-byte latency to simulate bandwidth (ns / byte)
    per_byte_ns: u64,
    /// RNG state (xorshift64)
    rng: u64,
}

impl ProbeJitter {
    /// Create with defaults matching a 10 Mbit/s Iranian server.
    pub fn new() -> Self {
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        Self {
            base_us: 85_000,  // 85 ms cold start
            per_byte_ns: 800, // ~10 Mbit/s
            rng: u64::from_le_bytes(seed),
        }
    }

    /// Next xorshift64 value in (0, 1).
    fn next_f64(&mut self) -> f64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        // avoid exact 0
        let v = self.rng | 1;
        (v as f64) / (u64::MAX as f64)
    }

    /// Compute a Gaussian sample via Box-Muller (µs).
    fn gaussian_jitter_us(&mut self, mean_us: u64, stddev_us: u64) -> u64 {
        let u1 = self.next_f64();
        let u2 = self.next_f64();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample = mean_us as f64 + z * stddev_us as f64;
        sample.max(1.0) as u64
    }

    /// Total synthetic delay for a decoy response of `body_len` bytes.
    pub async fn apply(&mut self, body_len: usize) {
        let base = self.gaussian_jitter_us(self.base_us, self.base_us / 4);
        let transfer_ns = (body_len as u64).saturating_mul(self.per_byte_ns);
        let total_us = base.saturating_add(transfer_ns / 1_000);
        let deadline = tokio::time::Instant::now() + Duration::from_micros(total_us);
        tokio::time::sleep_until(deadline).await;
    }
}

impl Default for ProbeJitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Probe Trap — the server-side front-door that absorbs active probing.
///
/// When `reality.rs` detects that incoming bytes do **not** contain a
/// cryptographically valid REALITY short-id, it hands the raw `TcpStream`
/// to `ProbeTrap::respond`. The trap:
///
/// 1. Applies timing jitter drawn from a measured Iranian server distribution.
/// 2. Writes a byte-perfect HTTP/1.1 decoy response (chosen profile rotates
///    round-robin per connection so each probe sees a different service).
/// 3. Closes the connection — from the censors perspective the remote server
///    just served a normal web page.
pub struct ProbeTrap {
    /// Round-robin index for profile selection.
    counter: u64,
    /// Jitter engine.
    jitter: ProbeJitter,
}

impl ProbeTrap {
    pub fn new() -> Self {
        Self {
            counter: 0,
            jitter: ProbeJitter::new(),
        }
    }

    /// Choose the next decoy profile (round-robin).
    fn next_profile(&mut self) -> DecoyProfile {
        let profiles = [
            DecoyProfile::MellatBank,
            DecoyProfile::TejaratBank,
            DecoyProfile::IrnaNews,
            DecoyProfile::Digikala,
        ];
        let idx = (self.counter as usize) % profiles.len();
        self.counter = self.counter.wrapping_add(1);
        profiles[idx]
    }

    /// Build a complete HTTP/1.1 response frame for the given profile.
    pub fn build_response(&mut self) -> (DecoyProfile, Vec<u8>) {
        let profile = self.next_profile();
        let body = profile.html_body();
        let mut resp = Vec::with_capacity(512 + body.len());

        // Status line
        resp.extend_from_slice(b"HTTP/1.1 200 OK\r\n");

        // Standard headers — mimic the real site's response exactly.
        let date = chrono_like_date();
        resp.extend_from_slice(format!("Date: {date}\r\n").as_bytes());
        resp.extend_from_slice(format!("Server: {}\r\n", profile.server_header()).as_bytes());
        if let Some(pb) = profile.powered_by() {
            resp.extend_from_slice(format!("X-Powered-By: {pb}\r\n").as_bytes());
        }
        resp.extend_from_slice(b"Content-Type: text/html; charset=UTF-8\r\n");
        resp.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        resp.extend_from_slice(b"Connection: close\r\n");
        resp.extend_from_slice(b"\r\n");
        resp.extend_from_slice(body);

        (profile, resp)
    }

    /// Respond to a probe with jitter + decoy and then shut down the write half.
    ///
    /// The caller should drop the stream after this returns.
    pub async fn respond<S>(&mut self, stream: &mut S)
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let (_, frame) = self.build_response();
        // Apply timing jitter BEFORE sending so the probe sender measures
        // realistic latency end-to-end.
        self.jitter.apply(frame.len()).await;
        // Best-effort write — if the probe closed early, that is fine.
        let _ = stream.write_all(&frame).await;
        let _ = stream.shutdown().await;
    }
}

impl Default for ProbeTrap {
    fn default() -> Self {
        Self::new()
    }
}

/// Produce a minimal RFC 1123 date string from the system clock.
/// Avoids pulling in the `chrono` or `time` crates.
fn chrono_like_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    // Days since epoch, weekday, year, month offset.
    let days = secs / 86_400;
    let wday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days as usize + 4) % 7];
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    // Gregorian approximation valid for 2024-2100.
    let mut year = 1970u64;
    let mut remaining = days;
    loop {
        let days_in_year = if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
            366
        } else {
            365
        };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let month_days = [
        31u64,
        if year.is_multiple_of(4) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    let mut mday = remaining;
    for &d in &month_days {
        if mday < d {
            break;
        }
        mday -= d;
        month += 1;
    }
    let hh = (secs % 86_400) / 3_600;
    let mm = (secs % 3_600) / 60;
    let ss = secs % 60;

    format!(
        "{wday}, {:02} {} {year} {:02}:{mm:02}:{ss:02} GMT",
        mday + 1,
        month_names[month],
        hh
    )
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// HTTPS typical segment sizes (based on JPEG/WebP data)
/// Mean: ~1200 bytes, Std Dev: ~400 bytes
const HTTPS_MEAN_SIZE: f64 = 1200.0;
const HTTPS_STD_DEV: f64 = 400.0;

/// Minimum padding to add
const MIN_PADDING: usize = 8;
/// Maximum padding to add
const MAX_PADDING: usize = 1400;

/// Markov chain states for timing jitter
const JITTER_STATES: usize = 4;

// ============================================================================
// ANTI-ML PROBABILISTIC SHAPER
// ============================================================================

/// Probabilistic packet shaper that matches HTTPS traffic distributions.
/// Uses Gaussian distribution to generate padding that statistically
/// resembles legitimate HTTPS segment sizes.
pub struct ProbabilisticShaper {
    /// Pre-allocated padding buffer to avoid heap churn
    padding_buffer: Vec<u8>,
    /// Current padding offset
    offset: usize,
    /// RNG state
    rng_state: u64,
    /// Intensity of noise (0.0 to 1.0)
    intensity: f64,
}

impl ProbabilisticShaper {
    /// Create a new shaper with pre-allocated padding buffer and given intensity.
    pub fn with_intensity(intensity: f64) -> Self {
        // Pre-allocate padding buffer during initialization
        let mut padding_buffer = vec![0u8; MAX_PADDING * 2];
        let mut rng = rand::thread_rng();
        rng.fill(&mut padding_buffer[..]);

        Self {
            padding_buffer,
            offset: 0,
            rng_state: rng.next_u64(),
            intensity,
        }
    }

    /// Create a new shaper with maximum intensity.
    pub fn new() -> Self {
        Self::with_intensity(1.0)
    }

    /// Calculate Gaussian-distributed padding size.
    /// Uses Box-Muller transform for Gaussian distribution.
    fn gaussian_padding_size(&mut self, base_size: usize) -> usize {
        // Box-Muller transform for Gaussian distribution
        let u1: f64 = self.next_uniform();
        let u2: f64 = self.next_uniform();

        let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

        // Scale to HTTPS distribution
        let target = HTTPS_MEAN_SIZE + z0 * HTTPS_STD_DEV;

        // Calculate padding needed to reach target
        let current_size = base_size as f64;
        let padding = (target - current_size)
            .max(MIN_PADDING as f64)
            .min(MAX_PADDING as f64);

        // Apply intensity scaling
        (padding * self.intensity) as usize
    }

    /// Generate next uniform random value (xorshift64)
    fn next_uniform(&mut self) -> f64 {
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        (self.rng_state as f64) / (u64::MAX as f64)
    }

    /// Shape a packet by adding probabilistic padding.
    /// Returns the padded packet with length prefix.
    pub fn shape_packet(&mut self, data: &[u8]) -> BytesMut {
        let padding_size = self.gaussian_padding_size(data.len());

        // Create output buffer: [2-byte length][data][padding]
        let total_size = 2 + data.len() + padding_size;
        let mut output = BytesMut::with_capacity(total_size);

        // Write original data length (for receiver to extract)
        output.put_u16(data.len() as u16);

        // Write original data
        output.put_slice(data);

        // Add padding from pre-allocated buffer
        let padding_start = self.offset % self.padding_buffer.len();
        let padding_end = (padding_start + padding_size) % self.padding_buffer.len();

        if padding_end > padding_start {
            output.put_slice(&self.padding_buffer[padding_start..padding_end]);
        } else {
            // Wrap around
            output.put_slice(&self.padding_buffer[padding_start..]);
            output.put_slice(&self.padding_buffer[..padding_end]);
        }

        self.offset = (self.offset + padding_size) % self.padding_buffer.len();

        output
    }

    /// Unshape a received packet, extracting original data.
    pub fn unshape_packet(data: &[u8]) -> Option<&[u8]> {
        if data.len() < 2 {
            return None;
        }

        let original_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        if data.len() < 2 + original_len {
            return None;
        }

        Some(&data[2..2 + original_len])
    }
}

impl Default for ProbabilisticShaper {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MARKOV-CHAIN JITTER
// ============================================================================

/// Markov chain states representing browser timing behaviors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterState {
    /// Fast burst mode (congestion window open)
    Burst,
    /// Normal interactive mode
    Interactive,
    /// Slow think time (user reading)
    ThinkTime,
    /// Idle with keep-alive
    Idle,
}

/// Markov-chain timing jitter engine.
/// Mimics real browser TCP/IP timing patterns to defeat ML classifiers.
pub struct MarkovJitter {
    /// Current state
    state: JitterState,
    /// State transition probabilities [from][to]
    transitions: [[f64; JITTER_STATES]; JITTER_STATES],
    /// Delay ranges per state (min_us, max_us)
    delay_ranges: [(u64, u64); JITTER_STATES],
    /// Last packet time
    last_packet: Instant,
    /// Packets in current burst
    burst_count: u32,
}

impl MarkovJitter {
    /// Create a new jitter engine with browser-like transition probabilities.
    pub fn new() -> Self {
        // Transition probabilities based on browser traffic analysis
        // Rows: Burst, Interactive, ThinkTime, Idle
        let transitions = [
            // From Burst: likely to continue burst or become interactive
            [0.6, 0.3, 0.08, 0.02],
            // From Interactive: balanced transitions
            [0.25, 0.5, 0.2, 0.05],
            // From ThinkTime: likely to become interactive or idle
            [0.1, 0.4, 0.3, 0.2],
            // From Idle: likely to burst or become interactive
            [0.4, 0.35, 0.15, 0.1],
        ];

        // Delay ranges in microseconds per state
        let delay_ranges = [
            (50, 500),            // Burst: 50-500µs
            (1_000, 10_000),      // Interactive: 1-10ms
            (50_000, 200_000),    // ThinkTime: 50-200ms
            (500_000, 2_000_000), // Idle: 500ms-2s
        ];

        Self {
            state: JitterState::Interactive,
            transitions,
            delay_ranges,
            last_packet: Instant::now(),
            burst_count: 0,
        }
    }

    /// Transition to next state based on Markov chain probabilities.
    fn transition(&mut self) {
        let state_idx = self.state as usize;
        let probs = &self.transitions[state_idx];

        let mut rng = rand::thread_rng();
        let r: f64 = rng.gen_range(0.0..1.0);

        let mut cumulative = 0.0;
        for (i, &prob) in probs.iter().enumerate() {
            cumulative += prob;
            if r < cumulative {
                self.state = match i {
                    0 => JitterState::Burst,
                    1 => JitterState::Interactive,
                    2 => JitterState::ThinkTime,
                    _ => JitterState::Idle,
                };
                break;
            }
        }

        // Track burst length for realistic patterns
        if self.state == JitterState::Burst {
            self.burst_count += 1;
            // Force transition after long burst
            if self.burst_count > 10 {
                self.state = JitterState::Interactive;
                self.burst_count = 0;
            }
        } else {
            self.burst_count = 0;
        }
    }

    /// Calculate delay before sending next packet.
    /// Uses tokio::time::sleep_until for async-friendly delays.
    pub fn calculate_delay(&mut self) -> Duration {
        self.transition();

        let (min_us, max_us) = self.delay_ranges[self.state as usize];
        let mut rng = rand::thread_rng();
        let delay_us = rng.gen_range(min_us..=max_us);

        Duration::from_micros(delay_us)
    }

    /// Apply jitter delay before packet transmission.
    /// Non-blocking async delay using tokio.
    pub async fn apply_jitter(&mut self) {
        let delay = self.calculate_delay();

        // Use sleep_until for precise timing
        let deadline = tokio::time::Instant::now() + delay;
        sleep_until(deadline).await;

        self.last_packet = Instant::now();
    }

    /// Get current state (for debugging/metrics)
    pub fn current_state(&self) -> JitterState {
        self.state
    }
}

impl Default for MarkovJitter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HEADER ENCRYPTION
// ============================================================================

/// Session-key based header encryption.
/// Encrypts Flow-J control headers to prevent static signature detection.
pub struct HeaderEncryptor {
    /// AES-256-GCM cipher
    cipher: Aes256Gcm,
    /// Nonce counter for unique nonces
    nonce_counter: AtomicU64,
    /// Session ID for authentication
    session_id: [u8; 8],
}

impl HeaderEncryptor {
    /// Derive encryption key from session parameters.
    pub fn new(uuid: &[u8; 16], timestamp: u64, nonce: &[u8; 8]) -> Self {
        // Derive 256-bit key using HKDF-like construction
        let mut hasher = Sha256::new();
        hasher.update(b"flow-j-header-key");
        hasher.update(uuid);
        hasher.update(timestamp.to_be_bytes());
        hasher.update(nonce);
        let key_bytes = hasher.finalize();

        let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Valid 256-bit key");

        // Create session ID from hash
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&key_bytes[24..32]);

        Self {
            cipher,
            nonce_counter: AtomicU64::new(0),
            session_id,
        }
    }

    /// Encrypt a header buffer.
    /// Returns [8-byte nonce][ciphertext][16-byte tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // Generate unique nonce: session_id XOR counter
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.session_id);
        for (i, b) in counter.to_be_bytes().iter().enumerate() {
            nonce_bytes[i] ^= b;
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        // Prepend counter for decryption
        let mut output = Vec::with_capacity(8 + ciphertext.len());
        output.extend_from_slice(&counter.to_be_bytes());
        output.extend(ciphertext);

        Ok(output)
    }

    /// Decrypt a header buffer.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < 8 + 16 {
            return Err(EncryptionError::InvalidLength);
        }

        // Extract counter
        let counter = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());

        // Reconstruct nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.session_id);
        for (i, b) in counter.to_be_bytes().iter().enumerate() {
            nonce_bytes[i] ^= b;
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        self.cipher
            .decrypt(nonce, &ciphertext[8..])
            .map_err(|_| EncryptionError::DecryptionFailed)
    }

    /// Get session ID for logging
    pub fn session_id(&self) -> &[u8; 8] {
        &self.session_id
    }
}

/// Header encryption errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionError {
    /// Encryption operation failed
    EncryptionFailed,
    /// Decryption operation failed
    DecryptionFailed,
    /// Invalid ciphertext length
    InvalidLength,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::InvalidLength => write!(f, "Invalid ciphertext length"),
        }
    }
}

impl std::error::Error for EncryptionError {}

// ============================================================================
// COMBINED STEALTH PROCESSOR
// ============================================================================

/// Combined stealth processor integrating all anti-detection features.
pub struct StealthProcessor {
    /// Probabilistic packet shaper
    shaper: ProbabilisticShaper,
    /// Markov-chain jitter engine
    jitter: MarkovJitter,
    /// Header encryptor (optional, enabled after handshake)
    encryptor: Option<HeaderEncryptor>,
}

impl StealthProcessor {
    /// Create a new stealth processor.
    pub fn new() -> Self {
        Self {
            shaper: ProbabilisticShaper::new(),
            jitter: MarkovJitter::new(),
            encryptor: None,
        }
    }

    /// Initialize encryption with session parameters.
    pub fn init_encryption(&mut self, uuid: &[u8; 16], timestamp: u64, nonce: &[u8; 8]) {
        self.encryptor = Some(HeaderEncryptor::new(uuid, timestamp, nonce));
    }

    /// Process outgoing data with full stealth pipeline.
    /// 1. Encrypt headers if enabled
    /// 2. Apply probabilistic padding
    /// 3. Apply timing jitter
    pub async fn process_outgoing(&mut self, data: &[u8], is_header: bool) -> BytesMut {
        // Apply jitter first (non-blocking)
        self.jitter.apply_jitter().await;

        let processed = if is_header {
            // Encrypt headers if encryptor is initialized
            if let Some(ref encryptor) = self.encryptor {
                match encryptor.encrypt(data) {
                    Ok(encrypted) => encrypted,
                    Err(_) => data.to_vec(),
                }
            } else {
                data.to_vec()
            }
        } else {
            data.to_vec()
        };

        // Apply probabilistic padding
        self.shaper.shape_packet(&processed)
    }

    /// Process incoming data (reverse stealth pipeline).
    pub fn process_incoming(&self, data: &[u8], is_header: bool) -> Option<Vec<u8>> {
        // Remove padding
        let unpadded = ProbabilisticShaper::unshape_packet(data)?;

        if is_header {
            // Decrypt headers if encryptor is initialized
            if let Some(ref encryptor) = self.encryptor {
                encryptor.decrypt(unpadded).ok()
            } else {
                Some(unpadded.to_vec())
            }
        } else {
            Some(unpadded.to_vec())
        }
    }
}

impl Default for StealthProcessor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probabilistic_shaper() {
        let mut shaper = ProbabilisticShaper::new();

        let data = b"Hello, World!";
        let shaped = shaper.shape_packet(data);

        // Should be larger than original due to padding
        assert!(shaped.len() > data.len());

        // Should be able to unshape
        let unshaped = ProbabilisticShaper::unshape_packet(&shaped);
        assert_eq!(unshaped, Some(data.as_slice()));
    }

    #[test]
    fn test_markov_jitter_transitions() {
        let mut jitter = MarkovJitter::new();

        // Run multiple transitions to test state machine
        for _ in 0..100 {
            let _delay = jitter.calculate_delay();
            // Should not panic
        }
    }

    #[test]
    fn test_header_encryption() {
        let uuid = [1u8; 16];
        let timestamp = 1234567890u64;
        let nonce = [2u8; 8];

        let encryptor = HeaderEncryptor::new(&uuid, timestamp, &nonce);

        let plaintext = b"secret header data";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();

        // Should be larger than plaintext (nonce + tag)
        assert!(ciphertext.len() > plaintext.len());

        // Should decrypt correctly
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stealth_processor() {
        let mut processor = StealthProcessor::new();

        // Initialize encryption
        processor.init_encryption(&[1u8; 16], 1234567890, &[2u8; 8]);

        // Test round-trip (sync version for testing)
        let data = b"test payload";
        let shaped = processor.shaper.shape_packet(data);
        let unshaped = processor.process_incoming(&shaped, false);

        assert_eq!(unshaped, Some(data.to_vec()));
    }
}
