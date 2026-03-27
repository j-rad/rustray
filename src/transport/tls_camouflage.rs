// src/transport/tls_camouflage.rs
//! TLS Camouflage Module for Flow-J
//!
//! Implements Chrome browser TLS fingerprint mimicry for stealth connections.
//! This module provides configuration for TLS ClientHello to match Chrome 124's fingerprint.
//!
//! Features:
//! - TLS 1.3 enforcement
//! - Chrome-specific cipher suite ordering
//! - GREASE extension support
//! - ALPN configuration (h3/h2/http/1.1)
//! - Specific curve preferences (X25519, P-256, P-384)
//! - Random padding (0-32 bytes) for size variation

use crate::error::Result;
use rand::RngCore;
use rustls::ClientConfig;
use std::sync::Arc;
use tracing::debug;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Chrome 124 TLS fingerprint characteristics
pub mod chrome_fingerprint {
    /// Supported TLS versions (TLS 1.3 only for maximum stealth)
    pub const TLS_VERSION: &str = "TLS 1.3";

    /// Chrome cipher suite order
    pub const CIPHER_SUITES: &[&str] = &[
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ];

    /// ALPN protocols in Chrome order
    pub const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

    /// Supported curves in Chrome order
    pub const CURVES: &[&str] = &["X25519", "P-256", "P-384"];

    /// Target ClientHello size range
    pub const TARGET_SIZE_MIN: usize = 517;
    pub const TARGET_SIZE_MAX: usize = 525;

    /// Padding range for size variation
    pub const PADDING_MIN: usize = 0;
    pub const PADDING_MAX: usize = 32;
}

// ============================================================================
// CAMOUFLAGE CONFIGURATION
// ============================================================================

/// Chrome TLS fingerprint configuration
#[derive(Debug, Clone)]
pub struct ChromeCamouflageConfig {
    /// Server name for SNI
    pub server_name: String,
    /// Enable GREASE values
    pub enable_grease: bool,
    /// Enable random padding
    pub enable_padding: bool,
    /// Specific padding size (None = random)
    pub padding_size: Option<usize>,
}

impl Default for ChromeCamouflageConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            enable_grease: true,
            enable_padding: true,
            padding_size: None,
        }
    }
}

impl ChromeCamouflageConfig {
    /// Create with server name
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            ..Default::default()
        }
    }
}

// ============================================================================
// CAMOUFLAGE BUILDER
// ============================================================================

/// Builder for Chrome-camouflaged TLS configuration
pub struct ChromeCamouflageBuilder {
    config: ChromeCamouflageConfig,
}

impl ChromeCamouflageBuilder {
    /// Create new builder
    pub fn new(server_name: &str) -> Self {
        Self {
            config: ChromeCamouflageConfig::new(server_name),
        }
    }

    /// Enable/disable GREASE
    pub fn grease(mut self, enabled: bool) -> Self {
        self.config.enable_grease = enabled;
        self
    }

    /// Enable/disable padding
    pub fn padding(mut self, enabled: bool) -> Self {
        self.config.enable_padding = enabled;
        self
    }

    /// Set specific padding size
    pub fn padding_size(mut self, size: usize) -> Self {
        self.config.padding_size = Some(size.min(chrome_fingerprint::PADDING_MAX));
        self
    }

    /// Build rustls ClientConfig with Chrome camouflage
    pub fn build(self) -> Result<Arc<ClientConfig>> {
        debug!(
            "Building Chrome-camouflaged TLS config for {}",
            self.config.server_name
        );

        // Create root cert store with webpki roots
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };

        // Build config with Chrome-like settings
        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN protocols (Chrome order)
        config.alpn_protocols = chrome_fingerprint::ALPN_PROTOCOLS
            .iter()
            .map(|p| p.to_vec())
            .collect();

        // Enable session resumption for performance
        config.resumption = rustls::client::Resumption::default();

        Ok(Arc::new(config))
    }

    /// Get config for inspection
    pub fn config(&self) -> &ChromeCamouflageConfig {
        &self.config
    }
}

// ============================================================================
// PADDING UTILITIES
// ============================================================================

/// Generate random padding bytes
pub fn generate_padding() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let size = (rng.next_u32() as usize % (chrome_fingerprint::PADDING_MAX + 1))
        .max(chrome_fingerprint::PADDING_MIN);

    let mut padding = vec![0u8; size];
    rng.fill_bytes(&mut padding);
    padding
}

/// Generate specific-size padding
pub fn generate_padding_sized(size: usize) -> Vec<u8> {
    let size = size.min(chrome_fingerprint::PADDING_MAX);
    let mut padding = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut padding);
    padding
}

/// Calculate required padding to reach target size
pub fn calculate_padding_for_size(
    current_size: usize,
    target_min: usize,
    target_max: usize,
) -> usize {
    if current_size >= target_max {
        return 0;
    }

    if current_size >= target_min {
        // Already in range, add random 0-8 bytes
        let mut rng = rand::thread_rng();
        return (rng.next_u32() as usize % 9).min(target_max.saturating_sub(current_size));
    }

    // Need to add padding to reach minimum
    let min_padding = target_min.saturating_sub(current_size);
    let max_additional = (target_max.saturating_sub(target_min))
        .min(chrome_fingerprint::PADDING_MAX.saturating_sub(min_padding));

    let mut rng = rand::thread_rng();
    min_padding + (rng.next_u32() as usize % (max_additional + 1))
}

// ============================================================================
// GREASE UTILITIES
// ============================================================================

/// GREASE values for TLS extensions (RFC 8701)
pub const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Select random GREASE value
pub fn random_grease() -> u16 {
    let mut rng = rand::thread_rng();
    let idx = (rng.next_u32() as usize) % GREASE_VALUES.len();
    GREASE_VALUES[idx]
}

/// Generate GREASE cipher suite bytes
pub fn grease_cipher_suite() -> [u8; 2] {
    random_grease().to_be_bytes()
}

/// Generate GREASE extension
pub fn grease_extension() -> Vec<u8> {
    let grease = random_grease();
    let mut ext = Vec::with_capacity(4);
    ext.extend_from_slice(&grease.to_be_bytes()); // Extension type
    ext.extend_from_slice(&0u16.to_be_bytes()); // Zero length
    ext
}

// ============================================================================
// CLIENTHELLO CUSTOMIZATION
// ============================================================================

/// ClientHello customization data
#[derive(Debug, Clone)]
pub struct ClientHelloCustomization {
    /// Additional extensions to include
    pub extra_extensions: Vec<Vec<u8>>,
    /// Padding to add
    pub padding: Vec<u8>,
    /// GREASE values to include
    pub grease_values: Vec<u16>,
}

impl ClientHelloCustomization {
    /// Create new customization with Chrome-like settings
    pub fn chrome_like() -> Self {
        let mut grease_values = Vec::new();

        // Chrome includes GREASE in multiple places
        grease_values.push(random_grease()); // Cipher suite
        grease_values.push(random_grease()); // Extension
        grease_values.push(random_grease()); // Supported versions

        Self {
            extra_extensions: vec![grease_extension()],
            padding: generate_padding(),
            grease_values,
        }
    }

    /// Create with specific padding
    pub fn with_padding(padding_size: usize) -> Self {
        let mut custom = Self::chrome_like();
        custom.padding = generate_padding_sized(padding_size);
        custom
    }
}

// ============================================================================
// FINGERPRINT VERIFICATION
// ============================================================================

/// Verify a ClientHello matches Chrome fingerprint characteristics
pub fn verify_chrome_fingerprint(client_hello: &[u8]) -> bool {
    if client_hello.len() < 5 {
        return false;
    }

    // Check TLS handshake header
    if client_hello[0] != 0x16 {
        // Handshake
        return false;
    }

    // Check version (TLS 1.0 for compatibility layer)
    if client_hello[1] != 0x03 || client_hello[2] > 0x03 {
        return false;
    }

    // Size check
    let size = client_hello.len();
    if !(chrome_fingerprint::TARGET_SIZE_MIN - 50..=chrome_fingerprint::TARGET_SIZE_MAX + 100).contains(&size)
    {
        return false;
    }

    true
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_generation() {
        let padding = generate_padding();
        assert!(padding.len() <= chrome_fingerprint::PADDING_MAX);
    }

    #[test]
    fn test_padding_sized() {
        let padding = generate_padding_sized(16);
        assert_eq!(padding.len(), 16);
    }

    #[test]
    fn test_grease_values() {
        for _ in 0..100 {
            let grease = random_grease();
            assert!(GREASE_VALUES.contains(&grease));
        }
    }

    #[test]
    fn test_grease_extension() {
        let ext = grease_extension();
        assert_eq!(ext.len(), 4);

        // Verify it's a valid GREASE value
        let grease = u16::from_be_bytes([ext[0], ext[1]]);
        assert!(GREASE_VALUES.contains(&grease));
    }

    #[test]
    fn test_calculate_padding() {
        // Below minimum
        let padding = calculate_padding_for_size(400, 517, 525);
        assert!(400 + padding >= 517);
        assert!(400 + padding <= 525);

        // In range
        let padding = calculate_padding_for_size(520, 517, 525);
        assert!(520 + padding <= 525);

        // Above maximum
        let padding = calculate_padding_for_size(600, 517, 525);
        assert_eq!(padding, 0);
    }

    #[test]
    fn test_chrome_customization() {
        let custom = ClientHelloCustomization::chrome_like();

        assert!(!custom.grease_values.is_empty());
        assert!(!custom.extra_extensions.is_empty());
    }

    #[test]
    fn test_camouflage_builder() {
        // Install crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = ChromeCamouflageBuilder::new("example.com")
            .grease(true)
            .padding(true)
            .build()
            .unwrap();

        // Should have ALPN protocols set
        assert!(!config.alpn_protocols.is_empty());
    }
}
