use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use ring::aead::{self, LessSafeKey, NONCE_LEN, UnboundKey};
use std::net::SocketAddr;
use std::str::FromStr;

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
            if let Ok(b64_str) = std::str::from_utf8(bytes)
                && let Ok(plaintext) = decrypt_signaling_payload(psk, b64_str) {
                    decrypted_signals.push(plaintext);
                }
        }
    }

    Ok(decrypted_signals)
}

// ============================================================================
// SIGNALING CLIENT
// ============================================================================

/// A signaling domain with its DoQ endpoint.
#[derive(Debug, Clone)]
pub struct SignalingDomain {
    /// The domain to query TXT records from (e.g., `_rustray.signal.example.com`).
    pub domain: String,
    /// The DoQ endpoint (e.g., `8.8.8.8:853`).
    pub endpoint: String,
}

/// Persistent signaling client that periodically polls multiple obfuscated
/// domains for encrypted configuration updates (bridge IPs, key rotation,
/// kill signals).
///
/// The client rotates through domains to avoid single-point censorship and
/// gracefully rejects corrupted or ISP-modified TXT records without panicking.
pub struct SignalingClient {
    /// Pre-shared key for AES-256-GCM decryption.
    psk: Vec<u8>,
    /// Pool of signaling domains to poll.
    domains: Vec<SignalingDomain>,
    /// Poll interval.
    poll_interval: std::time::Duration,
    /// Current domain rotation index.
    domain_idx: std::sync::atomic::AtomicUsize,
    /// Total successful polls.
    successful_polls: std::sync::atomic::AtomicU64,
    /// Total failed polls (network errors, corrupted records).
    failed_polls: std::sync::atomic::AtomicU64,
}

impl SignalingClient {
    /// Create a new signaling client.
    pub fn new(
        psk: Vec<u8>,
        domains: Vec<SignalingDomain>,
        poll_interval: std::time::Duration,
    ) -> Self {
        Self {
            psk,
            domains,
            poll_interval,
            domain_idx: std::sync::atomic::AtomicUsize::new(0),
            successful_polls: std::sync::atomic::AtomicU64::new(0),
            failed_polls: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Select the next domain (round-robin rotation).
    fn next_domain(&self) -> &SignalingDomain {
        if self.domains.is_empty() {
            panic!("SignalingClient requires at least one domain");
        }
        let idx = self
            .domain_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        &self.domains[idx % self.domains.len()]
    }

    /// Poll a single domain and return decrypted bridge IP addresses.
    ///
    /// Gracefully handles:
    /// - Network timeouts (returns empty vec)
    /// - ISP-modified/poisoned TXT records (decryption fails, skipped)
    /// - Corrupted base64 (decode fails, skipped)
    /// - Empty responses (returns empty vec)
    pub async fn poll_once(&self) -> Vec<String> {
        let domain = self.next_domain();
        let timeout_duration = std::time::Duration::from_secs(10);

        let result = tokio::time::timeout(
            timeout_duration,
            poll_doq_signals(&domain.endpoint, &domain.domain, &self.psk),
        )
        .await;

        match result {
            Ok(Ok(signals)) => {
                self.successful_polls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Parse decrypted signals as newline-separated bridge IP list
                let mut bridge_ips = Vec::new();
                for signal in signals {
                    if let Ok(text) = String::from_utf8(signal) {
                        for line in text.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() && Self::is_valid_bridge_entry(trimmed) {
                                bridge_ips.push(trimmed.to_string());
                            }
                        }
                    }
                }
                bridge_ips
            }
            Ok(Err(_)) | Err(_) => {
                self.failed_polls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Vec::new()
            }
        }
    }

    /// Spawn a background polling task that invokes `on_update` with new bridge IPs.
    pub fn spawn_poll_loop(
        self: std::sync::Arc<Self>,
        on_update: impl Fn(Vec<String>) + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let interval = self.poll_interval;
        tokio::spawn(async move {
            loop {
                let bridges = self.poll_once().await;
                if !bridges.is_empty() {
                    on_update(bridges);
                }
                tokio::time::sleep(interval).await;
            }
        })
    }

    /// Validate that a bridge entry looks like a valid IP:port or hostname:port.
    fn is_valid_bridge_entry(entry: &str) -> bool {
        // Must contain a colon (host:port format)
        if !entry.contains(':') {
            return false;
        }
        // Must not contain suspicious characters (ISP injection markers)
        if entry.contains('<') || entry.contains('>') || entry.contains(';') {
            return false;
        }
        // Port part must be numeric
        if let Some(port_str) = entry.rsplit(':').next() {
            port_str.parse::<u16>().is_ok()
        } else {
            false
        }
    }

    /// Get total successful polls.
    pub fn successful_polls(&self) -> u64 {
        self.successful_polls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total failed polls.
    pub fn failed_polls(&self) -> u64 {
        self.failed_polls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_signaling_payload_invalid_psk() {
        let bad_psk = vec![0u8; 16]; // Too short for AES-256
        let result = decrypt_signaling_payload(&bad_psk, "dGVzdA==");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_signaling_payload_too_short() {
        let psk = vec![0u8; 32];
        // Base64 of 4 bytes (< NONCE_LEN)
        let result = decrypt_signaling_payload(&psk, "AQIDBA==");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_signaling_payload_invalid_base64() {
        let psk = vec![0u8; 32];
        let result = decrypt_signaling_payload(&psk, "!!!not_base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_bridge_entry() {
        assert!(SignalingClient::is_valid_bridge_entry("192.168.1.1:443"));
        assert!(SignalingClient::is_valid_bridge_entry(
            "proxy.example.com:8443"
        ));
        assert!(SignalingClient::is_valid_bridge_entry("[::1]:443"));
        assert!(!SignalingClient::is_valid_bridge_entry("no-port"));
        assert!(!SignalingClient::is_valid_bridge_entry("<script>:443"));
        assert!(!SignalingClient::is_valid_bridge_entry("host:notaport"));
    }

    #[test]
    fn test_signaling_client_domain_rotation() {
        let client = SignalingClient::new(
            vec![0u8; 32],
            vec![
                SignalingDomain {
                    domain: "a.example.com".to_string(),
                    endpoint: "8.8.8.8:853".to_string(),
                },
                SignalingDomain {
                    domain: "b.example.com".to_string(),
                    endpoint: "8.8.4.4:853".to_string(),
                },
            ],
            std::time::Duration::from_secs(300),
        );

        let d1 = client.next_domain().domain.clone();
        let d2 = client.next_domain().domain.clone();
        let d3 = client.next_domain().domain.clone();

        assert_eq!(d1, "a.example.com");
        assert_eq!(d2, "b.example.com");
        assert_eq!(d3, "a.example.com"); // wraps
    }

    #[test]
    fn test_signaling_client_counters() {
        let client = SignalingClient::new(
            vec![0u8; 32],
            vec![SignalingDomain {
                domain: "test.example.com".to_string(),
                endpoint: "8.8.8.8:853".to_string(),
            }],
            std::time::Duration::from_secs(60),
        );
        assert_eq!(client.successful_polls(), 0);
        assert_eq!(client.failed_polls(), 0);
    }
}
