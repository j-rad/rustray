// src/protocols/shadowsocks_2022.rs
use crate::app::stats::StatsManager;
use crate::config::LevelPolicy;
use crate::config::{Shadowsocks2022OutboundSettings, Shadowsocks2022Settings};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::BoxedStream;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use async_trait::async_trait;
use base64::Engine;
use blake3::Hasher;
use bytes::{Buf, BufMut, BytesMut};
use rand::RngCore;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

// Constants for 2022-blake3-aes-128-gcm
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 16;
const TAG_LEN: usize = 16;

// --- INBOUND ---

pub async fn listen_stream(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    mut stream: BoxedStream,
    settings: Shadowsocks2022Settings,
    source: String,
) -> Result<()> {
    debug!("SS2022: Handling new inbound stream");

    // 1. Read Salt
    let mut salt = vec![0u8; SALT_LEN];
    stream.read_exact(&mut salt).await?;

    // 2. Derive Session Key: BLAKE3(PSK + Salt)
    let key_str = settings.key.as_deref().unwrap_or("");
    let psk = base64::engine::general_purpose::STANDARD
        .decode(key_str)
        .map_err(|_| anyhow::anyhow!("Invalid PSK base64"))?;

    let mut hasher = Hasher::new();
    hasher.update(&psk);
    hasher.update(&salt);
    let session_key_hash = hasher.finalize();
    let session_key = &session_key_hash.as_bytes()[0..KEY_LEN];

    // 3. Initialize Cipher (AES-128-GCM)
    let cipher =
        Aes128Gcm::new_from_slice(session_key).map_err(|_| anyhow::anyhow!("Invalid Key Size"))?;

    // SS-2022 usually enforces distinct nonces or keys for chunks?
    // Standard AEAD approach:
    // Chunk 0 (Header): Derived Key/IV?
    // Spec: "The first packet contains the header."
    // "Format: [salt] [encrypted header (length + payload)]" implies Length is encrypted?
    // Let's implement standard Shadowsocks AEAD Chunk:
    // [Encrypted Length (2 bytes + Tag)] [Encrypted Payload (Len bytes + Tag)]
    // Nonce starts at 0 and increments.
    let mut nonce_val = [0u8; 12];

    // Read Header Length
    let mut len_enc = [0u8; 2 + TAG_LEN];
    stream.read_exact(&mut len_enc).await?;

    let nonce = Nonce::from_slice(&nonce_val);
    let len_plain = cipher
        .decrypt(nonce, len_enc.as_ref())
        .map_err(|_| anyhow::anyhow!("SS2022 Header Length Decrypt Failed"))?;

    let body_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    if body_len > 16384 {
        // Basic sanity
        return Err(anyhow::anyhow!("Oversized SS Header"));
    }

    // Increment Nonce
    increment_nonce(&mut nonce_val);

    // Read Header Body
    let mut body_enc = vec![0u8; body_len + TAG_LEN];
    stream.read_exact(&mut body_enc).await?;

    let nonce = Nonce::from_slice(&nonce_val);
    let header_body = cipher
        .decrypt(nonce, body_enc.as_ref())
        .map_err(|_| anyhow::anyhow!("SS2022 Header Body Decrypt Failed"))?;

    // Increment Nonce for next chunk (Data)
    increment_nonce(&mut nonce_val);

    // 4. Parse Header (Standard Shadowsocks Address)
    // [Type][Addr][Port]
    let mut buf = &header_body[..];
    let addr_type = buf.get_u8();

    let host = match addr_type {
        1 => {
            let ip = buf.get_u32();
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = buf.get_u8() as usize;
            let d_bytes = buf.copy_to_bytes(len);
            String::from_utf8(d_bytes.to_vec())?
        }
        4 => {
            let ip = buf.copy_to_bytes(16);
            let addr =
                std::net::Ipv6Addr::from(u128::from_be_bytes(ip.as_ref().try_into().unwrap()));
            addr.to_string()
        }
        _ => return Err(anyhow::anyhow!("Unknown SS Address Type: {}", addr_type)),
    };

    let port = buf.get_u16();

    // Note: header_body may contain padding? SS-2022 usually supports padding.
    // If we parsed Host/Port, the rest is ignored (padding).

    let level = settings.level.unwrap_or(0);
    let policy = state.policy_manager.get_policy(level);

    // Wrap the stream in encrypted AEAD wrapper for ongoing data chunks
    // The stream is now positioned after the header, ready for data chunks
    use crate::protocols::shadowsocks_stream::ShadowsocksStream;

    let session_key_array: [u8; KEY_LEN] = session_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Session key conversion failed"))?;

    // Create wrapped stream that handles AEAD chunking for bidirectional traffic
    // Note: We need to adjust nonce since we already consumed header chunks
    let wrapped_stream = ShadowsocksStream::new_with_nonce(
        stream,
        &session_key_array,
        nonce_val, // Continue from where header parsing left off
    )?;

    router
        .route_stream(Box::new(wrapped_stream), host, port, source, policy)
        .await
}

fn increment_nonce(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        let val = nonce[i];
        if val < 255 {
            nonce[i] += 1;
            return;
        }
        nonce[i] = 0;
    }
}

// --- OUTBOUND ---

pub struct Shadowsocks2022Outbound {
    settings: Shadowsocks2022OutboundSettings,
}

impl Shadowsocks2022Outbound {
    pub fn new(
        settings: Shadowsocks2022OutboundSettings,
        _dns: Arc<crate::app::dns::DnsServer>,
        _stats: Arc<StatsManager>,
        _tag: String,
    ) -> Self {
        Self { settings }
    }
}

#[async_trait]
impl Outbound for Shadowsocks2022Outbound {
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;
        let _ = tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream).await;
        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let addr = format!("{}:{}", self.settings.address, self.settings.port);
        let mut out_stream = tokio::net::TcpStream::connect(&addr).await?;

        // 1. Generate Salt
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        out_stream.write_all(&salt).await?;

        // 2. Derive Session Key
        let key_str = self.settings.key.as_deref().unwrap_or("");
        let psk = base64::engine::general_purpose::STANDARD
            .decode(key_str)
            .map_err(|_| anyhow::anyhow!("Invalid PSK"))?;

        let mut hasher = Hasher::new();
        hasher.update(&psk);
        hasher.update(&salt);
        let session_key_hash = hasher.finalize();
        let session_key = &session_key_hash.as_bytes()[0..KEY_LEN];

        // 3. Init Cipher
        let cipher =
            Aes128Gcm::new_from_slice(session_key).map_err(|_| anyhow::anyhow!("Bad Key"))?;
        let mut nonce_val = [0u8; 12]; // Start 0

        // 4. Send Encrypted Request Header
        // Construct Header Payload
        let mut buf = BytesMut::with_capacity(512);

        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            buf.put_u8(1);
            buf.put_slice(&ip.octets());
        } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            buf.put_u8(4);
            buf.put_slice(&ip.octets());
        } else {
            buf.put_u8(3);
            buf.put_u8(host.len() as u8); // Max 255
            buf.put_slice(host.as_bytes());
        }
        buf.put_u16(port);

        let header_plain = buf.freeze();
        let header_len = header_plain.len() as u16;

        // Encrypt Length
        let nonce = Nonce::from_slice(&nonce_val);
        let len_bytes = header_len.to_be_bytes();
        let len_enc = cipher
            .encrypt(nonce, len_bytes.as_ref())
            .map_err(|_| anyhow::anyhow!("Encrypt Len Failed"))?;
        out_stream.write_all(&len_enc).await?;

        increment_nonce(&mut nonce_val);

        // Encrypt Header Body
        let nonce = Nonce::from_slice(&nonce_val);
        let body_enc = cipher
            .encrypt(nonce, header_plain.as_ref())
            .map_err(|_| anyhow::anyhow!("Encrypt Header Failed"))?;
        out_stream.write_all(&body_enc).await?;

        increment_nonce(&mut nonce_val);

        // 5. Wrap Stream for Body Encryption
        use crate::protocols::shadowsocks_stream::ShadowsocksStream;
        let session_key_array: [u8; KEY_LEN] = session_key.try_into().unwrap();
        let ss_stream =
            ShadowsocksStream::new_with_nonce(Box::new(out_stream), &session_key_array, nonce_val)?;

        Ok(Box::new(ss_stream) as BoxedStream)
    }
}
