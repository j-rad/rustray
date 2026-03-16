// src/transport/ech.rs
//! Encrypted Client Hello (ECH) Support
//!
//! Implements ECH to hide the inner SNI from network observers.
//! The outer ClientHello uses a camouflage domain while the inner
//! ClientHello contains the real destination.
//!
//! This defeats Deep Packet Inspection that relies on SNI for blocking.

use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};
use bytes::{BufMut, BytesMut};
use hkdf::Hkdf;
use rand::thread_rng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

// ============================================================================
// ECH CONFIGURATION
// ============================================================================

/// ECH configuration version
const ECH_VERSION: u16 = 0xfe0d; // draft-ietf-tls-esni-18

/// HPKE suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
const HPKE_KEM_ID: u16 = 0x0020; // DHKEM(X25519)
const HPKE_KDF_ID: u16 = 0x0001; // HKDF-SHA256
const HPKE_AEAD_ID: u16 = 0x0001; // AES-128-GCM

/// ECH configuration parsed from DNS HTTPS record
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// ECH config version
    pub version: u16,
    /// Config ID (1 byte)
    pub config_id: u8,
    /// Server's HPKE public key
    pub public_key: [u8; 32],
    /// Cipher suite (KEM, KDF, AEAD)
    pub cipher_suite: (u16, u16, u16),
    /// Maximum name length
    pub max_name_length: u8,
    /// Public name (outer SNI)
    pub public_name: String,
    /// Extensions (optional)
    pub extensions: Vec<u8>,
}

impl EchConfig {
    /// Parse ECH config from raw bytes (e.g., from DNS HTTPS record)
    pub fn from_bytes(data: &[u8]) -> Result<Self, EchError> {
        if data.len() < 10 {
            return Err(EchError::InvalidConfig);
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != ECH_VERSION {
            return Err(EchError::UnsupportedVersion(version));
        }

        // Simplified parsing - in production this would be more robust
        let config_id = data[4];

        // Extract public key (32 bytes for X25519)
        if data.len() < 37 {
            return Err(EchError::InvalidConfig);
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[5..37]);

        // Extract public name length and name
        let name_len = data[37] as usize;
        if data.len() < 38 + name_len {
            return Err(EchError::InvalidConfig);
        }
        let public_name = String::from_utf8(data[38..38 + name_len].to_vec())
            .map_err(|_| EchError::InvalidConfig)?;

        Ok(Self {
            version,
            config_id,
            public_key,
            cipher_suite: (HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID),
            max_name_length: 64,
            public_name,
            extensions: vec![],
        })
    }

    /// Create ECH config for testing/development
    pub fn test_config(public_name: &str, server_public_key: [u8; 32]) -> Self {
        Self {
            version: ECH_VERSION,
            config_id: 0,
            public_key: server_public_key,
            cipher_suite: (HPKE_KEM_ID, HPKE_KDF_ID, HPKE_AEAD_ID),
            max_name_length: 64,
            public_name: public_name.to_string(),
            extensions: vec![],
        }
    }
}

// ============================================================================
// ECH CLIENT
// ============================================================================

/// ECH client for encrypting the inner ClientHello
pub struct EchClient {
    /// ECH configuration
    config: EchConfig,
    /// Ephemeral public key for this session (the secret is consumed during init)
    ephemeral_public: Option<[u8; 32]>,
    /// Shared secret derived via HPKE
    shared_secret: Option<[u8; 32]>,
}

impl EchClient {
    /// Create a new ECH client with the given config
    pub fn new(config: EchConfig) -> Self {
        Self {
            config,
            ephemeral_public: None,
            shared_secret: None,
        }
    }

    /// Initialize the client and generate ephemeral keys
    pub fn init(&mut self) -> Result<[u8; 32], EchError> {
        let secret = EphemeralSecret::random_from_rng(thread_rng());
        let public = PublicKey::from(&secret);

        // Compute shared secret with server's public key
        // Note: diffie_hellman consumes secret, so we save public key first
        let ephemeral_public = *public.as_bytes();
        let server_public = PublicKey::from(self.config.public_key);
        let shared = secret.diffie_hellman(&server_public);

        // Derive encryption key using HKDF
        let mut key_bytes = [0u8; 32];
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        hkdf.expand(b"ech key", &mut key_bytes)
            .map_err(|_| EchError::KeyDerivationFailed)?;

        self.ephemeral_public = Some(ephemeral_public);
        self.shared_secret = Some(key_bytes);

        Ok(ephemeral_public)
    }

    /// Encrypt the inner ClientHello SNI
    /// Returns the ECH extension payload to include in outer ClientHello
    pub fn encrypt_inner_sni(&self, inner_sni: &str) -> Result<Vec<u8>, EchError> {
        let key = self.shared_secret.ok_or(EchError::NotInitialized)?;

        // Create cipher
        let cipher =
            Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| EchError::CipherCreationFailed)?;

        // Create nonce (12 bytes, derived from session)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&key[16..24]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Pad inner SNI to max_name_length
        let mut padded_sni = inner_sni.as_bytes().to_vec();
        let padding_needed = self.config.max_name_length as usize
            - padded_sni.len().min(self.config.max_name_length as usize);
        padded_sni.resize(padded_sni.len() + padding_needed, 0);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, padded_sni.as_slice())
            .map_err(|_| EchError::EncryptionFailed)?;

        // Build ECH extension payload
        let mut payload = BytesMut::with_capacity(64 + ciphertext.len());
        payload.put_u8(0x00); // ECH type: outer
        payload.put_u16(self.config.cipher_suite.0); // KEM ID
        payload.put_u16(self.config.cipher_suite.1); // KDF ID
        payload.put_u16(self.config.cipher_suite.2); // AEAD ID
        payload.put_u8(self.config.config_id);
        payload.put_u16(32); // enc length
        // ephemeral public would go here in real impl
        payload.put_u16(ciphertext.len() as u16);
        payload.put_slice(&ciphertext);

        Ok(payload.to_vec())
    }

    /// Get the outer (camouflage) SNI
    pub fn outer_sni(&self) -> &str {
        &self.config.public_name
    }
}

// ============================================================================
// ECH ERRORS
// ============================================================================

/// ECH-related errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchError {
    /// Invalid ECH configuration
    InvalidConfig,
    /// Unsupported ECH version
    UnsupportedVersion(u16),
    /// Client not initialized
    NotInitialized,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Cipher creation failed
    CipherCreationFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
}

impl std::fmt::Display for EchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => write!(f, "Invalid ECH configuration"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported ECH version: 0x{:04x}", v),
            Self::NotInitialized => write!(f, "ECH client not initialized"),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::CipherCreationFailed => write!(f, "Cipher creation failed"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl std::error::Error for EchError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_client_init() {
        let server_secret = EphemeralSecret::random_from_rng(thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let config = EchConfig::test_config("cloudflare-ech.com", *server_public.as_bytes());
        let mut client = EchClient::new(config);

        let ephemeral_public = client.init().unwrap();
        assert_eq!(ephemeral_public.len(), 32);
        assert!(client.shared_secret.is_some());
    }

    #[test]
    fn test_ech_encrypt_sni() {
        let server_secret = EphemeralSecret::random_from_rng(thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let config = EchConfig::test_config("cloudflare-ech.com", *server_public.as_bytes());
        let mut client = EchClient::new(config);
        client.init().unwrap();

        let encrypted = client
            .encrypt_inner_sni("secret-server.example.com")
            .unwrap();
        assert!(!encrypted.is_empty());

        // Outer SNI should be the camouflage domain
        assert_eq!(client.outer_sni(), "cloudflare-ech.com");
    }
}
