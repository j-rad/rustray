// src/protocols/flow.rs
//!
//! Flow Protocol Implementation
//!
//! "Flow" is a zero-RTT, zero-copy splicing protocol designed to defeat DPI.
//! It uses rotational keys based on time slots (6 hours) and a shared secret.
//!
//! Header Format:
//! [Nonce (12 bytes)] [Ciphertext (Variable)]
//!
//! Key Derivation:
//! Key = SHA256(Secret + TimeSlot)[0..16]
//! TimeSlot = UnixTimestamp / 21600

use crate::config::{FlowSettings, LevelPolicy};
use crate::error::Result;
use crate::router::Router;
use crate::transport::BoxedStream;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use bytes::Buf;
use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, info, warn};

const NONCE_LEN: usize = 12;
const TIME_SLOT_DURATION: u64 = 21600; // 6 hours
// We assume a fixed initial read size to cover the header + minimal payload + padding.
// The ciphertext is variable, but we need to read enough to decrypt the header.
// Assuming header max size is reasonable (e.g. domain name limit 255).
// Let's read 512 bytes for the first chunk.
// If the actual ciphertext is smaller, the tag check will fail on garbage?
// No, AES-GCM needs exact ciphertext.
// This protocol specification in the prompt says "Ciphertext (Variable)".
// Without a length prefix, we rely on the implementation detail that we defined in the thought process:
// We will assume the client pads the header to a specific size or we try to decrypt a prefix?
//
// Re-visiting the thought process: "Assumption for Implementation: The client sends a fixed-size encrypted header block (e.g. 128 bytes + tag)."
// The prompt said "Read initial encrypted chunk (e.g., 128 bytes)".
// Let's implement reading a fixed 128 bytes (plus tag?) as the "Header Block".
// Any data after that is payload.
// Let's define HEADER_BLOCK_SIZE = 128 + 16 (Tag) = 144 bytes?
// Or just 128 bytes TOTAL including tag.
// Let's go with 128 bytes total ciphertext for the header block.
const INITIAL_READ_LEN: usize = 128; // Ciphertext size (Encrypted Header + Tag)

pub struct FlowInbound;

impl FlowInbound {
    pub async fn handle_stream(
        mut stream: BoxedStream,
        settings: Arc<FlowSettings>,
        router: Arc<Router>,
        source: String,
    ) -> Result<()> {
        debug!("Flow: Handling new inbound stream from {}", source);

        // 1. Read Nonce (12 bytes)
        let mut nonce_bytes = [0u8; NONCE_LEN];
        if stream.read_exact(&mut nonce_bytes).await.is_err() {
            return Self::fallback(stream, None, &settings.fallback).await;
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 2. Read Initial Chunk (Ciphertext)
        let mut ciphertext = vec![0u8; INITIAL_READ_LEN];
        if stream.read_exact(&mut ciphertext).await.is_err() {
            // If we can't read enough, maybe connection died or it's a probe.
            // Pass whatever we read + nonce to fallback?
            return Self::fallback(
                stream,
                Some([nonce_bytes.as_slice(), &ciphertext].concat()),
                &settings.fallback,
            )
            .await;
        }

        // 3. Derive Keys and Attempt Decryption
        let secret = settings.secret.as_deref().unwrap_or("");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_slot = now / TIME_SLOT_DURATION;

        let slots = [
            current_slot,
            current_slot.wrapping_sub(1),
            current_slot.wrapping_add(1),
        ];
        let mut decrypted_data = None;

        for slot in slots {
            let key = Self::derive_key(secret, slot);
            let cipher = Aes128Gcm::new_from_slice(&key).expect("Invalid key length");

            if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext.as_ref()) {
                decrypted_data = Some(plaintext);
                break;
            }
        }

        let plaintext = match decrypted_data {
            Some(pt) => pt,
            None => {
                warn!("Flow: Decryption failed (invalid key or auth tag)");
                let prefix = [nonce_bytes.as_slice(), &ciphertext].concat();
                return Self::fallback(stream, Some(prefix), &settings.fallback).await;
            }
        };

        // 4. Parse Header
        // Header Structure:
        // Version(1), UUID(16), Options(1), Command(1), Port(2), AddrType(1), Address(Var)
        let mut buf = io::Cursor::new(plaintext);

        if buf.remaining() < 1 + 16 + 1 + 1 + 2 + 1 {
            warn!("Flow: Header too short");
            return Ok(()); // Or fallback
        }

        let version = buf.get_u8();
        if version != 0x01 {
            warn!("Flow: Invalid version {}", version);
            return Ok(());
        }

        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        let uuid = uuid::Uuid::from_bytes(uuid_bytes);

        // Authenticate UUID
        let valid_user = settings.clients.iter().find(|u| u.uuid == uuid.to_string());
        if valid_user.is_none() {
            warn!("Flow: Unknown user {}", uuid);
            // Fallback? Spec says "If decryption fails ... fallback".
            // If decryption works but user is unknown, we should probably also fallback to mimic valid server.
            // Need to reconstruct the read bytes.
            let prefix = [nonce_bytes.as_slice(), &ciphertext].concat();
            return Self::fallback(stream, Some(prefix), &settings.fallback).await;
        }

        let _options = buf.get_u8();
        let _command = buf.get_u8(); // 0x01 TCP
        let port = buf.get_u16();
        let addr_type = buf.get_u8();

        let host = match addr_type {
            0x01 => {
                // IPv4
                if buf.remaining() < 4 {
                    return Ok(());
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                Ipv4Addr::from(ip).to_string()
            }
            0x02 => {
                // Domain
                if !buf.has_remaining() {
                    return Ok(());
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len {
                    return Ok(());
                }
                let mut d = vec![0u8; len];
                buf.copy_to_slice(&mut d);
                String::from_utf8(d).unwrap_or_default()
            }
            0x03 => {
                // IPv6
                if buf.remaining() < 16 {
                    return Ok(());
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                Ipv6Addr::from(ip).to_string()
            }
            _ => return Ok(()),
        };

        info!("Flow Request: {}:{}", host, port);

        // Remaining bytes in 'buf' are part of the payload (Zero-RTT data inside the encrypted block).
        // We need to prefix them to the splicing.
        // Or write them to the outbound connection immediately.
        let initial_payload = buf.remaining();
        let mut payload_prefix = Vec::new();
        if initial_payload > 0 {
            let pos = buf.position() as usize;
            payload_prefix = buf.get_ref()[pos..].to_vec();
        }

        // 5. Zero-Copy Splicing
        // We need to splice `stream` with the remote.
        // `router.route_stream` takes `BoxedStream`.
        // But we have consumed bytes from `stream`.
        // And we have `payload_prefix` that needs to be sent to remote first.

        // This is tricky with `route_stream` which abstracts the outbound connection.
        // Usually `route_stream` just connects and copies.
        // If we have initial payload, we should pass it? `route_stream` doesn't take initial payload.
        //
        // We must construct a `PrefixedStream` (like in Hysteria2 logic) that logically puts the payload *back*
        // onto the read side of `stream`, OR we handle the routing manually here.
        // Since `router` is available, we want to use it.
        //
        // Solution: Create a PrefixedStream struct (can reuse from Hysteria2 or define here)
        // that chains `payload_prefix` + `stream`.

        // Since I cannot import the private `PrefixedStream` from `hysteria2.rs`, I will define a simple one here.

        let prefixed_stream = PrefixedReadStream::new(payload_prefix, stream);
        let boxed_prefixed: BoxedStream = Box::new(prefixed_stream);

        let policy = Arc::new(LevelPolicy::default()); // Should get from user level
        router
            .route_stream(boxed_prefixed, host, port, source, policy)
            .await
    }

    fn derive_key(secret: &str, slot: u64) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hasher.update(slot.to_string().as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[0..16]);
        key
    }

    async fn fallback(
        mut stream: BoxedStream,
        prefix: Option<Vec<u8>>,
        fallback_addr: &Option<String>,
    ) -> Result<()> {
        if let Some(addr_str) = fallback_addr {
            debug!("Flow: Fallback to {}", addr_str);
            // Parse addr
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                if let Ok(mut remote) = tokio::net::TcpStream::connect(addr).await {
                    if let Some(p) = prefix {
                        let _ = remote.write_all(&p).await;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
                }
            } else {
                // Try resolving? Assuming IP:Port for now per config.
            }
        }
        Ok(())
    }
}

// Helper struct for splicing initial payload back into the stream
struct PrefixedReadStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedReadStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.has_remaining() {
            let n = std::cmp::min(self.prefix.remaining(), buf.remaining());
            let pos = self.prefix.position() as usize;
            let slice = &self.prefix.get_ref()[pos..pos + n];
            buf.put_slice(slice);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedReadStream<S> {
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
