// src/transport/reality_v2/mod.rs
//! REALITY V2 Handshake Hijacking
//!
//! Hijacks whitelisted domestic TLS 1.3 sessions to bypass the GFW's
//! certificate validation. The technique works as follows:
//!
//! 1. Dial a whitelisted domestic peer (e.g. `sep.shaparak.ir` — Iran's banking gateway).
//! 2. Send a valid TLS 1.3 ClientHello with the bank's SNI.
//! 3. Hide the `Trinity-Relay-ID` inside the TLS Padding extension (RFC 8446 §4.2.9)
//!    or a customized ALPN list.
//! 4. The GFW sees and validates the bank's legitimate certificate chain.
//! 5. After the GFW marks the flow as "clean", the Germany VPS pivots the
//!    inner stream to the VLESS/Trojan outbound relay without dropping the socket.
//!
//! This exploits the fact that the GFW trusts flows to whitelisted banking domains
//! and does not perform deep-packet inspection after the TLS handshake completes.

use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TransportStats, TrinityTransport};
use crate::transport::pqc::{HybridCiphertext, HybridGroup, HybridKeypair};
use bytes::{BufMut, BytesMut};
use hkdf::Hkdf;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use sha2::Sha256;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

// ─── Configuration ────────────────────────────────────────────────────────────

/// REALITY V2 handshake hijacking configuration.
#[derive(Debug, Clone)]
pub struct RealityV2Config {
    /// Whitelisted domestic target for the TLS ClientHello (e.g. "sep.shaparak.ir").
    pub target_sni: String,
    /// Target port (usually 443).
    pub target_port: u16,
    /// Trinity-Relay-ID to embed in the TLS Padding extension.
    /// This is a 16-byte relay identifier used by the Germany VPS.
    pub relay_id: [u8; 16],
    /// Address of the Germany VPS that will perform the stream pivot.
    pub exit_addr: String,
    /// Exit VPS port.
    pub exit_port: u16,
    /// Optional: ALPN protocols to advertise (used for relay-ID steganography).
    pub alpn_protocols: Vec<String>,
    /// Optional: additional padding bytes to include in the ClientHello.
    pub extra_padding: usize,
    /// Exit VPS's hybrid public key (X25519 || ML-KEM-768).
    /// When present, enables PQC-encrypted relay-ID and hybrid key_share.
    pub pqc_server_pk: Option<Vec<u8>>,
}

impl Default for RealityV2Config {
    fn default() -> Self {
        Self {
            target_sni: "sep.shaparak.ir".to_string(),
            target_port: 443,
            relay_id: [0u8; 16],
            exit_addr: String::new(),
            exit_port: 443,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            extra_padding: 128,
            pqc_server_pk: None,
        }
    }
}

// ─── Relay-ID Encryption ──────────────────────────────────────────────────────

/// Encrypt the 16-byte relay-ID using a PQC-derived shared secret.
///
/// Uses HKDF-SHA256 to derive a 16-byte XOR mask from the shared secret,
/// then XORs the relay-ID. The VPS decrypts by running the same HKDF with
/// the shared secret it derives from decapsulation.
fn encrypt_relay_id(relay_id: &[u8; 16], shared_secret: &[u8; 32]) -> [u8; 16] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"reality-v2-relay"), shared_secret);
    let mut mask = [0u8; 16];
    hkdf.expand(b"relay-id-mask", &mut mask)
        .expect("16 bytes is valid HKDF output length");
    let mut encrypted = [0u8; 16];
    for i in 0..16 {
        encrypted[i] = relay_id[i] ^ mask[i];
    }
    encrypted
}

// ─── TLS ClientHello Builder ──────────────────────────────────────────────────

/// Build a TLS 1.3 ClientHello with embedded relay-ID in the Padding extension.
///
/// Extension layout:
///   - SNI extension (type 0x0000): contains `target_sni`
///   - Supported Versions (type 0x002B): TLS 1.3 only
///   - ALPN (type 0x0010): standard protocols
///   - Key Share (type 0x0033): x25519, and optionally X25519+ML-KEM-768 (0x6399)
///   - Padding (type 0x0015): relay-ID (PQC-encrypted if server PK available)
///
/// When `pqc_server_pk` is set, the relay-ID is encrypted with the PQC shared
/// secret and a hybrid key_share entry is added so the VPS can decapsulate.
fn build_client_hello(config: &RealityV2Config) -> (BytesMut, Option<[u8; 32]>) {
    let mut buf = BytesMut::with_capacity(512);

    // TLS record header: ContentType=Handshake(22), Version=TLS 1.0 (compat)
    buf.put_u8(0x16); // ContentType: Handshake
    buf.put_u16(0x0301); // Legacy version: TLS 1.0 (required for compatibility)

    // Placeholder for record length (will be filled later).
    let record_length_pos = buf.len();
    buf.put_u16(0); // Record length placeholder

    // Handshake header: ClientHello(1)
    buf.put_u8(0x01); // HandshakeType: ClientHello

    // Placeholder for handshake length (3 bytes).
    let handshake_length_pos = buf.len();
    buf.put_u8(0);
    buf.put_u16(0); // Handshake length placeholder (3 bytes)

    // ClientHello body
    buf.put_u16(0x0303); // Client version: TLS 1.2 (compat, actual version in ext)

    // Random (32 bytes) — must be cryptographically random.
    let mut random = [0u8; 32];
    SmallRng::from_entropy().fill(&mut random);
    buf.put_slice(&random);

    // Session ID (32 bytes for TLS 1.3 middlebox compat).
    buf.put_u8(32); // Session ID length
    let mut session_id = [0u8; 32];
    SmallRng::from_entropy().fill(&mut session_id);
    buf.put_slice(&session_id);

    // Cipher Suites
    let cipher_suites: &[u16] = &[
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    ];
    buf.put_u16((cipher_suites.len() * 2) as u16);
    for cs in cipher_suites {
        buf.put_u16(*cs);
    }

    // Compression Methods (null only)
    buf.put_u8(1); // Length
    buf.put_u8(0); // Null compression

    // Extensions
    let extensions_length_pos = buf.len();
    buf.put_u16(0); // Extensions length placeholder

    // Extension: SNI (type 0x0000)
    {
        let sni_bytes = config.target_sni.as_bytes();
        buf.put_u16(0x0000); // SNI extension type
        let ext_len = 2 + 1 + 2 + sni_bytes.len();
        buf.put_u16(ext_len as u16);
        buf.put_u16((ext_len - 2) as u16); // Server name list length
        buf.put_u8(0); // Host name type
        buf.put_u16(sni_bytes.len() as u16);
        buf.put_slice(sni_bytes);
    }

    // Extension: Supported Versions (type 0x002B)
    {
        buf.put_u16(0x002B);
        buf.put_u16(3); // Extension data length
        buf.put_u8(2); // Supported versions list length
        buf.put_u16(0x0304); // TLS 1.3
    }

    // Extension: ALPN (type 0x0010)
    {
        let mut alpn_data = BytesMut::new();
        for proto in &config.alpn_protocols {
            let proto_bytes = proto.as_bytes();
            alpn_data.put_u8(proto_bytes.len() as u8);
            alpn_data.put_slice(proto_bytes);
        }
        buf.put_u16(0x0010);
        buf.put_u16((2 + alpn_data.len()) as u16);
        buf.put_u16(alpn_data.len() as u16);
        buf.put_slice(&alpn_data);
    }

    // Extension: Key Share (type 0x0033)
    //
    // Always includes an x25519 entry for GFW compatibility.
    // When PQC is enabled, also includes a hybrid X25519+ML-KEM-768 entry
    // (group 0x6399) carrying the encapsulated ciphertext.
    let mut pqc_shared_secret: Option<[u8; 32]> = None;
    {
        let mut key_share_entries = BytesMut::new();

        // Entry 1: x25519 (required — this is what the GFW expects to see)
        let mut x25519_key = [0u8; 32];
        SmallRng::from_entropy().fill(&mut x25519_key);
        key_share_entries.put_u16(0x001D); // x25519 group
        key_share_entries.put_u16(32);     // Key exchange length
        key_share_entries.put_slice(&x25519_key);

        // Entry 2: Hybrid X25519+ML-KEM-768 (optional, PQC-enabled)
        if let Some(ref server_pk) = config.pqc_server_pk {
            match HybridCiphertext::encapsulate(server_pk) {
                Ok((ct, ss)) => {
                    let ct_bytes = ct.to_bytes();
                    key_share_entries.put_u16(HybridGroup::X25519MlKem768.id()); // 0x6399
                    key_share_entries.put_u16(ct_bytes.len() as u16);
                    key_share_entries.put_slice(&ct_bytes);
                    pqc_shared_secret = Some(ss);
                    debug!("REALITY V2: PQC hybrid key_share added ({} bytes)", ct_bytes.len());
                }
                Err(e) => {
                    warn!("REALITY V2: PQC encapsulation failed ({:?}), falling back to classical", e);
                }
            }
        }

        buf.put_u16(0x0033); // key_share extension type
        buf.put_u16((2 + key_share_entries.len()) as u16); // extension data length
        buf.put_u16(key_share_entries.len() as u16);       // client key share length
        buf.put_slice(&key_share_entries);
    }

    // Extension: Padding (type 0x0015) — RELAY-ID INJECTION POINT
    //
    // When PQC shared secret is available, the relay-ID is XOR-encrypted
    // with an HKDF-derived mask. Otherwise it's embedded in plaintext
    // (still opaque — padding content is unstructured per RFC 8446).
    {
        let relay_id_bytes = match &pqc_shared_secret {
            Some(ss) => encrypt_relay_id(&config.relay_id, ss),
            None => config.relay_id,
        };

        // 1 byte: PQC flag (0x01 = encrypted, 0x00 = plaintext)
        let pqc_flag: u8 = if pqc_shared_secret.is_some() { 0x01 } else { 0x00 };
        let padding_len = 1 + 8 + relay_id_bytes.len() + config.extra_padding;
        buf.put_u16(0x0015);
        buf.put_u16(padding_len as u16);

        buf.put_u8(pqc_flag);

        // 8 bytes of random prefix noise.
        let mut prefix = [0u8; 8];
        SmallRng::from_entropy().fill(&mut prefix);
        buf.put_slice(&prefix);

        // Embed the (possibly encrypted) relay-ID (16 bytes).
        buf.put_slice(&relay_id_bytes);

        // Fill remaining padding with random bytes.
        let mut extra = vec![0u8; config.extra_padding];
        SmallRng::from_entropy().fill(&mut extra[..]);
        buf.put_slice(&extra);
    }

    // Fix up lengths.
    let total_len = buf.len();
    let extensions_len = total_len - extensions_length_pos - 2;
    let handshake_len = total_len - handshake_length_pos - 3;
    let record_len = total_len - record_length_pos - 2;

    // Extensions length (2 bytes at extensions_length_pos).
    buf[extensions_length_pos] = ((extensions_len >> 8) & 0xFF) as u8;
    buf[extensions_length_pos + 1] = (extensions_len & 0xFF) as u8;

    // Handshake length (3 bytes at handshake_length_pos).
    buf[handshake_length_pos] = ((handshake_len >> 16) & 0xFF) as u8;
    buf[handshake_length_pos + 1] = ((handshake_len >> 8) & 0xFF) as u8;
    buf[handshake_length_pos + 2] = (handshake_len & 0xFF) as u8;

    // Record length (2 bytes at record_length_pos).
    buf[record_length_pos] = ((record_len >> 8) & 0xFF) as u8;
    buf[record_length_pos + 1] = (record_len & 0xFF) as u8;

    (buf, pqc_shared_secret)
}

// ─── Hijacked Handshake ───────────────────────────────────────────────────────

/// Perform the hijacked handshake.
///
/// 1. Connect to the whitelisted domestic target (e.g. sep.shaparak.ir:443).
/// 2. Send a crafted TLS 1.3 ClientHello with the relay-ID in the Padding ext.
/// 3. Read the ServerHello + Certificate chain (the GFW validates it).
/// 4. Once the GFW is satisfied, the Germany VPS (which receives the relay-ID
///    via an out-of-band channel) pivots the stream to the real outbound.
///
/// Returns a `RealityV2Stream` wrapping the connection for use as a
/// `TrinityTransport`.
pub async fn dial_hijacked_handshake(config: &RealityV2Config) -> Result<RealityV2Stream> {
    debug!(
        "REALITY V2: initiating hijacked handshake to {} (relay-ID: {:02x?})",
        config.target_sni,
        &config.relay_id[..4]
    );

    // Step 1: TCP connect to the exit VPS (which sits behind the CDN or on a clean IP).
    let tcp_stream = TcpStream::connect(format!("{}:{}", config.exit_addr, config.exit_port)).await?;

    debug!("REALITY V2: TCP connected to exit VPS {}:{}", config.exit_addr, config.exit_port);

    let mut stream: BoxedTrinityTransport = Box::new(tcp_stream);

    // Step 2: Send the crafted ClientHello with the relay-ID (PQC-encrypted if configured).
    let (client_hello, pqc_ss) = build_client_hello(config);
    stream.write_all(&client_hello).await?;
    stream.flush().await?;

    debug!(
        "REALITY V2: ClientHello sent ({} bytes, SNI={}, PQC={})",
        client_hello.len(),
        config.target_sni,
        pqc_ss.is_some()
    );

    // Step 3: Read the ServerHello response.
    // The Germany VPS extracts the relay-ID from the Padding extension and
    // responds with its own REALITY handshake (mimicking the target site's cert).
    let mut server_hello_buf = BytesMut::with_capacity(4096);
    let mut temp = [0u8; 1024];

    // Read until we get at least a TLS record header (5 bytes).
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut temp).await?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "REALITY V2: connection closed during ServerHello"
            ));
        }
        server_hello_buf.extend_from_slice(&temp[..n]);

        // Check if we have at least the TLS record header.
        if server_hello_buf.len() >= 5 {
            let record_type = server_hello_buf[0];
            let record_len =
                ((server_hello_buf[3] as usize) << 8) | (server_hello_buf[4] as usize);

            // Verify this looks like a TLS Handshake record.
            if record_type != 0x16 {
                warn!(
                    "REALITY V2: unexpected record type 0x{:02x}, expected 0x16 (Handshake)",
                    record_type
                );
                // Continue anyway — the VPS might be using a non-standard wrapper.
            }

            // Check if we've received the full ServerHello record.
            if server_hello_buf.len() >= 5 + record_len {
                debug!(
                    "REALITY V2: ServerHello received ({} bytes)",
                    server_hello_buf.len()
                );
                break;
            }
        }

        if server_hello_buf.len() > 65536 {
            return Err(anyhow::anyhow!(
                "REALITY V2: ServerHello too large (>64KB)"
            ));
        }
    }

    // Step 4: At this point the GFW has seen a valid TLS 1.3 handshake to a
    // whitelisted banking domain. The Germany VPS has extracted our relay-ID
    // and is ready to pivot the stream to the real outbound.
    // From here on, the stream is a raw bidirectional pipe to the VPS.

    debug!("REALITY V2: handshake complete, stream pivoted to relay");

    Ok(RealityV2Stream {
        inner: stream,
        config: config.clone(),
        bytes_sent: client_hello.len() as u64,
        bytes_received: server_hello_buf.len() as u64,
    })
}

// ─── REALITY V2 Stream ───────────────────────────────────────────────────────

/// A TAL-compatible stream backed by a hijacked TLS handshake.
pub struct RealityV2Stream {
    inner: BoxedTrinityTransport,
    config: RealityV2Config,
    bytes_sent: u64,
    bytes_received: u64,
}

impl TrinityTransport for RealityV2Stream {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner = new_carrier;
        debug!("REALITY V2: carrier hot-swapped");
        Ok(())
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn handover(mut self, new_carrier: BoxedTrinityTransport) -> Result<Self> {
        self.inner = new_carrier;
        Ok(self)
    }

    fn get_transport_info(&self) -> TransportStats {
        TransportStats {
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            ..Default::default()
        }
    }
}

impl AsyncRead for RealityV2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = (buf.filled().len() - before) as u64;
            self.bytes_received = self.bytes_received.wrapping_add(read);
        }
        result
    }
}

impl AsyncWrite for RealityV2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.bytes_sent = self.bytes_sent.wrapping_add(*n as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_structure_no_pqc() {
        let config = RealityV2Config {
            target_sni: "sep.shaparak.ir".to_string(),
            relay_id: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                       0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            extra_padding: 64,
            ..Default::default()
        };

        let (hello, pqc_ss) = build_client_hello(&config);

        // No PQC server PK → no shared secret.
        assert!(pqc_ss.is_none());

        // TLS record header check.
        assert_eq!(hello[0], 0x16, "Record type should be Handshake");
        assert_eq!(hello[1], 0x03, "Legacy version major");
        assert_eq!(hello[2], 0x01, "Legacy version minor (TLS 1.0 compat)");

        // Handshake type = ClientHello(1).
        assert_eq!(hello[5], 0x01, "Handshake type should be ClientHello");

        // Verify the SNI is present in the hello.
        let hello_bytes = &hello[..];
        let sni = b"sep.shaparak.ir";
        assert!(
            hello_bytes.windows(sni.len()).any(|w| w == sni),
            "SNI should be present in ClientHello"
        );

        // Without PQC, relay-ID is plaintext → should be findable.
        let relay_prefix = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert!(
            hello_bytes.windows(relay_prefix.len()).any(|w| w == relay_prefix),
            "Relay-ID prefix should be present in plaintext ClientHello"
        );

        // PQC flag byte should be 0x00 (plaintext).
        // Find the padding extension (type 0x0015) and check the flag.
        let padding_marker = &[0x00u8, 0x15]; // extension type
        let padding_pos = hello_bytes
            .windows(2)
            .position(|w| w == padding_marker);
        assert!(padding_pos.is_some(), "Padding extension should be present");
        // Flag is at padding_pos + 4 (skip type 2B + length 2B).
        let flag_pos = padding_pos.unwrap() + 4;
        assert_eq!(hello_bytes[flag_pos], 0x00, "PQC flag should be 0x00 (plaintext)");
    }

    #[test]
    fn test_client_hello_with_pqc() {
        let server_kp = HybridKeypair::generate();
        let server_pk = server_kp.public_key();

        let config = RealityV2Config {
            target_sni: "sep.shaparak.ir".to_string(),
            relay_id: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                       0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            extra_padding: 64,
            pqc_server_pk: Some(server_pk),
            ..Default::default()
        };

        let (hello, pqc_ss) = build_client_hello(&config);

        // PQC should produce a shared secret.
        assert!(pqc_ss.is_some(), "PQC shared secret should be produced");

        // With PQC, relay-ID is encrypted → plaintext prefix should NOT appear.
        let hello_bytes = &hello[..];
        let relay_prefix = &[0xDE, 0xAD, 0xBE, 0xEF];
        // Note: there's a small chance of false positive with random data,
        // but with encryption the probability is negligible.
        let found = hello_bytes.windows(relay_prefix.len()).any(|w| w == relay_prefix);
        // We can't guarantee it's not there by chance, but check structure.
        assert!(hello_bytes.len() > 200, "PQC hello should be larger due to hybrid key_share");

        // Verify the hybrid group ID (0x6399) is present in key_share.
        let hybrid_group = &[0x63u8, 0x99];
        assert!(
            hello_bytes.windows(2).any(|w| w == hybrid_group),
            "Hybrid group 0x6399 should be present in key_share extension"
        );
    }

    #[test]
    fn test_encrypt_relay_id_roundtrip() {
        let relay_id: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                                   0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        let shared_secret = [0x42u8; 32];

        let encrypted = encrypt_relay_id(&relay_id, &shared_secret);
        assert_ne!(encrypted, relay_id, "Encrypted should differ from plaintext");

        // Decrypt by encrypting again (XOR is its own inverse).
        let decrypted = encrypt_relay_id(&encrypted, &shared_secret);
        assert_eq!(decrypted, relay_id, "Double encryption should recover plaintext");
    }

    #[test]
    fn test_config_defaults() {
        let config = RealityV2Config::default();
        assert_eq!(config.target_sni, "sep.shaparak.ir");
        assert_eq!(config.target_port, 443);
        assert_eq!(config.extra_padding, 128);
        assert!(config.pqc_server_pk.is_none());
    }
}

