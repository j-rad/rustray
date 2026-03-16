use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ring::aead::{self, LessSafeKey, NONCE_LEN, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Decrypts a signaling payload using AES-256-GCM and a Pre-Shared Key (PSK).
pub fn decrypt_signaling_payload(psk: &[u8], ciphertext_base64: &str) -> Result<Vec<u8>> {
    let mut ciphertext = general_purpose::STANDARD.decode(ciphertext_base64)?;

    if ciphertext.len() < NONCE_LEN {
        return Err(anyhow!("Ciphertext too short"));
    }

    let unbound_key =
        UnboundKey::new(&aead::AES_256_GCM, psk).map_err(|_| anyhow!("Invalid PSK length"))?;
    let key = LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&ciphertext[..NONCE_LEN]);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    // Decrypt in place
    let plaintext = key
        .open_in_place(nonce, aead::Aad::empty(), &mut ciphertext[NONCE_LEN..])
        .map_err(|_| anyhow!("Decryption failed"))?;

    Ok(plaintext.to_vec())
}

/// Polls a DoQ endpoint for out-of-band signals.
/// Queries TXT records and decrypts valid payloads using the PSK.
pub async fn poll_doq_signals(endpoint: &str, domain: &str, psk: &[u8]) -> Result<Vec<Vec<u8>>> {
    log::info!("Polling DoQ endpoint {} for domain {}", endpoint, domain);

    let addr = SocketAddr::from_str(endpoint)
        .unwrap_or_else(|_| SocketAddr::from_str("8.8.8.8:853").unwrap());

    // Configure DNS over QUIC
    let mut config = ResolverConfig::new();
    let ns_config = NameServerConfig::new(addr, Protocol::Quic);
    config.add_name_server(ns_config);

    let opts = ResolverOpts::default();
    let resolver = TokioAsyncResolver::tokio(config, opts);

    let response = resolver.txt_lookup(domain).await?;
    let mut decrypted_signals = Vec::new();

    for txt in response.iter() {
        for bytes in txt.txt_data() {
            if let Ok(b64_str) = std::str::from_utf8(bytes) {
                if let Ok(plaintext) = decrypt_signaling_payload(psk, b64_str) {
                    decrypted_signals.push(plaintext);
                }
            }
        }
    }

    Ok(decrypted_signals)
}
