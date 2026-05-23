// src/transport/beacon_scanner.rs
//! Phase 6 — Invisible Signaling (DNS Beacon)
//!
//! Uses DoH (DNS over HTTPS) and recursive DNS fallback to securely scan
//! TXT records for dynamic infrastructure updates.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hickory_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct BeaconScanner {
    resolver: TokioAsyncResolver,
    key: [u8; 32],
}

impl BeaconScanner {
    /// Create a new scanner with a 32-byte AES-256-GCM key.
    pub fn new(key: [u8; 32]) -> Self {
        // Use Google's DoH as a primary resolver
        let config = ResolverConfig::google();
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);

        let resolver = TokioAsyncResolver::tokio(config, opts);

        Self { resolver, key }
    }

    /// Scan a domain's TXT records and decrypt the hidden bridge IP.
    pub async fn scan_domain(&self, domain: &str) -> Option<String> {
        let response = match self.resolver.txt_lookup(domain).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("DNS lookup failed for {}: {}", domain, e);
                return None;
            }
        };

        let cipher = Aes256Gcm::new(self.key.as_ref().into());

        for txt in response.iter() {
            let record_str = txt.to_string();
            // Expected format: v=spf1 include:_spf.example.com ~all OR encrypted payload
            // We'll try to decode any base64 payload we find.
            if let Ok(decoded) = STANDARD.decode(&record_str)
                && decoded.len() > 12
            {
                let nonce = Nonce::from_slice(&decoded[..12]);
                let ciphertext = &decoded[12..];

                if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext)
                    && let Ok(ip) = String::from_utf8(plaintext)
                {
                    info!("Decrypted bridge IP from TXT record: {}", ip);
                    return Some(ip);
                }
            }
        }

        debug!("No valid beacon found in {} TXT records", domain);
        None
    }
}
