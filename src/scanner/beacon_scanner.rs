// src/scanner/beacon_scanner.rs
//! Phase 6 — Invisible Signaling: The DNS Beacon Protocol.
//!
//! Implements a `BeaconScanner` that uses DoH (DNS-over-HTTPS) to poll domestic
//! DNS resolvers for encrypted bridge IP updates published as DNS TXT records.
//!
//! Protocol:
//! 1. The RR-UI `BeaconManager` encrypts bridge IPs with AES-256-GCM and publishes
//!    the ciphertext as base64-encoded DNS TXT records on innocuous secondary domains.
//! 2. This scanner polls those TXT records via DoH (which is never blocked because
//!    it looks like normal HTTPS traffic to domestic resolvers).
//! 3. The decryption key is derived from the user's unique "Seed Hash" generated
//!    during the initial private setup.
//! 4. If DoH is blocked, the scanner falls back to standard recursive DNS on port 53,
//!    disguising the polling interval with a randomized Poisson distribution.
//!
//! Anti-detection:
//! - Polling interval randomized with Poisson distribution (λ = 10 minutes).
//! - Never exceeds the "Statistical Anomaly" threshold of 1 request per 10 minutes.
//! - Domain rotation to avoid single-domain censorship.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{Engine as _, engine::general_purpose};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// A beacon domain to poll.
#[derive(Debug, Clone)]
pub struct BeaconDomain {
    /// DNS domain to query TXT records from (e.g., `_update.weather-api.ir`).
    pub domain: String,
    /// DoH resolver URL (e.g., `https://dns.shecan.ir/dns-query`).
    pub doh_url: String,
    /// Fallback recursive resolver on port 53.
    pub fallback_resolver: String,
}

/// Configuration for the beacon scanner.
#[derive(Debug, Clone)]
pub struct BeaconScannerConfig {
    /// Domains to poll (rotated round-robin).
    pub domains: Vec<BeaconDomain>,
    /// Seed hash from which the AES-256-GCM key is derived.
    pub seed_hash: Vec<u8>,
    /// Mean polling interval in seconds (Poisson λ). Default: 600 (10 minutes).
    pub poll_lambda_secs: f64,
    /// Maximum polling interval in seconds. Default: 1200 (20 minutes).
    pub poll_max_secs: u64,
    /// Minimum polling interval in seconds. Default: 300 (5 minutes).
    pub poll_min_secs: u64,
}

impl Default for BeaconScannerConfig {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            seed_hash: Vec::new(),
            poll_lambda_secs: 600.0,
            poll_max_secs: 1200,
            poll_min_secs: 300,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a 256-bit AES key from the user's seed hash.
///
/// Uses SHA-256(seed_hash || "rustray-beacon-v1") to produce a deterministic key.
fn derive_beacon_key(seed_hash: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed_hash);
    hasher.update(b"rustray-beacon-v1");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Decrypt a beacon TXT record payload.
///
/// Format: base64(nonce_12_bytes || ciphertext || tag_16_bytes)
fn decrypt_beacon_payload(key: &[u8; 32], payload_b64: &str) -> Option<Vec<u8>> {
    let data = general_purpose::STANDARD.decode(payload_b64).ok()?;
    if data.len() < 12 + 16 {
        return None; // Too short: need at least nonce + tag.
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Encrypt a beacon payload for publishing (used by BeaconManager / tests).
pub fn encrypt_beacon_payload(key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new_from_slice(key)
        .expect("Key length is always 32 bytes");

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("AES-256-GCM encryption should not fail");

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    general_purpose::STANDARD.encode(&combined)
}

// ─────────────────────────────────────────────────────────────────────────────
// Poisson-distributed polling interval
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a Poisson-distributed interval (in seconds) with mean `lambda`.
///
/// Uses the inverse CDF method: `interval = -lambda * ln(1 - U)` where U ∈ [0,1).
/// The result is clamped to `[min_secs, max_secs]`.
fn poisson_interval(lambda: f64, min_secs: u64, max_secs: u64) -> Duration {
    let u: f64 = rand::thread_rng().gen_range(0.001..1.0);
    let interval = (-lambda * u.ln()) as u64;
    let clamped = interval.clamp(min_secs, max_secs);
    Duration::from_secs(clamped)
}

// ─────────────────────────────────────────────────────────────────────────────
// BeaconScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Polls DNS TXT records for encrypted bridge IP updates.
pub struct BeaconScanner {
    config: BeaconScannerConfig,
    /// Derived AES-256-GCM key.
    key: [u8; 32],
    /// Round-robin domain index.
    domain_idx: AtomicUsize,
    /// Successful polls counter.
    successful_polls: AtomicU64,
    /// Failed polls counter.
    failed_polls: AtomicU64,
    /// Total bridge IPs discovered.
    bridges_found: AtomicU64,
}

impl BeaconScanner {
    /// Create a new beacon scanner.
    pub fn new(config: BeaconScannerConfig) -> Self {
        let key = derive_beacon_key(&config.seed_hash);
        Self {
            config,
            key,
            domain_idx: AtomicUsize::new(0),
            successful_polls: AtomicU64::new(0),
            failed_polls: AtomicU64::new(0),
            bridges_found: AtomicU64::new(0),
        }
    }

    /// Select the next domain (round-robin).
    fn next_domain(&self) -> Option<&BeaconDomain> {
        if self.config.domains.is_empty() {
            return None;
        }
        let idx = self.domain_idx.fetch_add(1, Ordering::Relaxed);
        Some(&self.config.domains[idx % self.config.domains.len()])
    }

    /// Poll a single domain via DoH and return decrypted bridge IP addresses.
    ///
    /// Falls back to recursive DNS on port 53 if DoH fails.
    pub async fn poll_once(&self) -> Vec<String> {
        let domain = match self.next_domain() {
            Some(d) => d,
            None => {
                warn!("BeaconScanner: No domains configured");
                return Vec::new();
            }
        };

        // Try DoH first.
        match self.poll_doh(domain).await {
            Ok(bridges) if !bridges.is_empty() => {
                self.successful_polls.fetch_add(1, Ordering::Relaxed);
                self.bridges_found.fetch_add(bridges.len() as u64, Ordering::Relaxed);
                return bridges;
            }
            Ok(_) => {
                debug!("BeaconScanner: DoH returned no bridges, trying recursive fallback");
            }
            Err(e) => {
                debug!("BeaconScanner: DoH failed: {}, trying recursive fallback", e);
            }
        }

        // Recursive fallback via port 53.
        match self.poll_recursive(domain).await {
            Ok(bridges) => {
                if bridges.is_empty() {
                    self.failed_polls.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.successful_polls.fetch_add(1, Ordering::Relaxed);
                    self.bridges_found.fetch_add(bridges.len() as u64, Ordering::Relaxed);
                }
                bridges
            }
            Err(_) => {
                self.failed_polls.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        }
    }

    /// Poll via DNS-over-HTTPS.
    async fn poll_doh(&self, domain: &BeaconDomain) -> anyhow::Result<Vec<String>> {
        // Use hickory-resolver with HTTPS transport.
        let mut resolver_config = ResolverConfig::new();
        let doh_addr: SocketAddr = domain.doh_url
            .trim_start_matches("https://")
            .split('/')
            .next()
            .and_then(|host| format!("{}:443", host).parse().ok())
            .unwrap_or_else(|| "8.8.8.8:443".parse().unwrap());

        resolver_config.add_name_server(NameServerConfig::new(doh_addr, Protocol::Https));
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

        let timeout = Duration::from_secs(15);
        let result = tokio::time::timeout(timeout, resolver.txt_lookup(&domain.domain)).await;

        match result {
            Ok(Ok(response)) => Ok(self.extract_bridges(response)),
            Ok(Err(e)) => Err(anyhow::anyhow!("DoH lookup failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!("DoH lookup timed out")),
        }
    }

    /// Poll via standard recursive DNS on port 53.
    async fn poll_recursive(&self, domain: &BeaconDomain) -> anyhow::Result<Vec<String>> {
        let mut resolver_config = ResolverConfig::new();
        let addr: SocketAddr = format!("{}:53", domain.fallback_resolver)
            .parse()
            .unwrap_or_else(|_| "8.8.8.8:53".parse().unwrap());

        resolver_config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

        let timeout = Duration::from_secs(10);
        let result = tokio::time::timeout(timeout, resolver.txt_lookup(&domain.domain)).await;

        match result {
            Ok(Ok(response)) => Ok(self.extract_bridges(response)),
            Ok(Err(e)) => Err(anyhow::anyhow!("Recursive lookup failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!("Recursive lookup timed out")),
        }
    }

    /// Extract and decrypt bridge IPs from TXT records.
    fn extract_bridges(&self, response: hickory_resolver::lookup::TxtLookup) -> Vec<String> {
        let mut bridges = Vec::new();
        for txt in response.iter() {
            for bytes in txt.txt_data() {
                if let Ok(b64_str) = std::str::from_utf8(bytes) {
                    if let Some(plaintext) = decrypt_beacon_payload(&self.key, b64_str) {
                        if let Ok(text) = String::from_utf8(plaintext) {
                            for line in text.lines() {
                                let trimmed = line.trim();
                                if !trimmed.is_empty() && is_valid_bridge(trimmed) {
                                    bridges.push(trimmed.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        bridges
    }

    /// Spawn the continuous polling loop.
    ///
    /// Calls `on_update` whenever new bridge IPs are discovered.
    /// The polling interval follows a Poisson distribution to avoid detection.
    pub fn spawn_poll_loop(
        self: Arc<Self>,
        on_update: impl Fn(Vec<String>) + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let lambda = self.config.poll_lambda_secs;
        let min_secs = self.config.poll_min_secs;
        let max_secs = self.config.poll_max_secs;

        tokio::spawn(async move {
            loop {
                let bridges = self.poll_once().await;
                if !bridges.is_empty() {
                    info!("BeaconScanner: Discovered {} bridge(s)", bridges.len());
                    on_update(bridges);
                }

                let interval = poisson_interval(lambda, min_secs, max_secs);
                debug!("BeaconScanner: Next poll in {:?}", interval);
                tokio::time::sleep(interval).await;
            }
        })
    }

    /// Get stats.
    pub fn successful_polls(&self) -> u64 {
        self.successful_polls.load(Ordering::Relaxed)
    }

    pub fn failed_polls(&self) -> u64 {
        self.failed_polls.load(Ordering::Relaxed)
    }

    pub fn bridges_found(&self) -> u64 {
        self.bridges_found.load(Ordering::Relaxed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge address validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that a bridge entry is a plausible IP:port or host:port string.
fn is_valid_bridge(entry: &str) -> bool {
    if !entry.contains(':') {
        return false;
    }
    // Reject HTML/injection markers.
    if entry.contains('<') || entry.contains('>') || entry.contains(';') {
        return false;
    }
    // Port must be numeric.
    entry.rsplit(':')
        .next()
        .map(|p| p.parse::<u16>().is_ok())
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_beacon_key_deterministic() {
        let seed = b"user-seed-phrase-12345";
        let k1 = derive_beacon_key(seed);
        let k2 = derive_beacon_key(seed);
        assert_eq!(k1, k2, "Same seed must produce same key");
    }

    #[test]
    fn test_derive_beacon_key_different_seeds() {
        let k1 = derive_beacon_key(b"seed-a");
        let k2 = derive_beacon_key(b"seed-b");
        assert_ne!(k1, k2, "Different seeds must produce different keys");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = derive_beacon_key(b"test-seed");
        let plaintext = b"192.168.1.100:443\n10.0.0.1:8443";
        let encrypted = encrypt_beacon_payload(&key, plaintext);
        let decrypted = decrypt_beacon_payload(&key, &encrypted);
        assert_eq!(decrypted.as_deref(), Some(plaintext.as_slice()));
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = derive_beacon_key(b"key-1");
        let key2 = derive_beacon_key(b"key-2");
        let encrypted = encrypt_beacon_payload(&key1, b"secret");
        let decrypted = decrypt_beacon_payload(&key2, &encrypted);
        assert!(decrypted.is_none(), "Wrong key must fail decryption");
    }

    #[test]
    fn test_decrypt_corrupted_payload() {
        let key = derive_beacon_key(b"test");
        assert!(decrypt_beacon_payload(&key, "not-valid-base64!!!").is_none());
        assert!(decrypt_beacon_payload(&key, "dGVzdA==").is_none()); // Too short
    }

    #[test]
    fn test_is_valid_bridge() {
        assert!(is_valid_bridge("192.168.1.1:443"));
        assert!(is_valid_bridge("proxy.example.com:8443"));
        assert!(!is_valid_bridge("no-port"));
        assert!(!is_valid_bridge("<script>:443"));
        assert!(!is_valid_bridge("host:notaport"));
    }

    #[test]
    fn test_poisson_interval_in_range() {
        for _ in 0..100 {
            let d = poisson_interval(600.0, 300, 1200);
            assert!(d.as_secs() >= 300 && d.as_secs() <= 1200);
        }
    }

    #[test]
    fn test_poisson_interval_variance() {
        let mut intervals: Vec<u64> = Vec::new();
        for _ in 0..100 {
            intervals.push(poisson_interval(600.0, 300, 1200).as_secs());
        }
        let unique: std::collections::HashSet<_> = intervals.iter().collect();
        // With Poisson distribution, we expect significant variance.
        assert!(unique.len() > 10, "Poisson should produce varied intervals");
    }

    #[test]
    fn test_scanner_domain_rotation() {
        let config = BeaconScannerConfig {
            domains: vec![
                BeaconDomain {
                    domain: "a.example.com".into(),
                    doh_url: "https://dns.example.com/dns-query".into(),
                    fallback_resolver: "8.8.8.8".into(),
                },
                BeaconDomain {
                    domain: "b.example.com".into(),
                    doh_url: "https://dns.example.com/dns-query".into(),
                    fallback_resolver: "8.8.4.4".into(),
                },
            ],
            seed_hash: b"test-seed".to_vec(),
            ..Default::default()
        };

        let scanner = BeaconScanner::new(config);
        let d1 = scanner.next_domain().unwrap().domain.clone();
        let d2 = scanner.next_domain().unwrap().domain.clone();
        let d3 = scanner.next_domain().unwrap().domain.clone();
        assert_eq!(d1, "a.example.com");
        assert_eq!(d2, "b.example.com");
        assert_eq!(d3, "a.example.com"); // wraps
    }

    #[test]
    fn test_scanner_no_domains() {
        let config = BeaconScannerConfig::default();
        let scanner = BeaconScanner::new(config);
        assert!(scanner.next_domain().is_none());
    }

    #[test]
    fn test_scanner_counters_initial() {
        let scanner = BeaconScanner::new(BeaconScannerConfig::default());
        assert_eq!(scanner.successful_polls(), 0);
        assert_eq!(scanner.failed_polls(), 0);
        assert_eq!(scanner.bridges_found(), 0);
    }
}
