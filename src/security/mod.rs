// src/security/mod.rs
//! Security utilities for rustray

pub mod pii_filter;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Derive encryption key from device-specific data
pub fn derive_device_key() -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Use machine ID or other device-specific data
    #[cfg(target_os = "linux")]
    {
        if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        }
    }

    #[cfg(target_os = "android")]
    {
        // On Android, use Android ID or other device identifier
        hasher.update(b"android_device_specific_data");
    }

    #[cfg(target_os = "ios")]
    {
        // On iOS, use identifierForVendor or similar
        hasher.update(b"ios_device_specific_data");
    }

    // Fallback for other platforms
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "ios")))]
    {
        hasher.update(b"fallback_device_key");
    }

    hasher.finalize().into()
}

/// Encrypt sensitive config data
pub fn encrypt_config(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = derive_device_key();
    let cipher = Aes256Gcm::new(&key.into());

    // Use a fixed nonce for config encryption (not ideal for general use, but acceptable for local config)
    // In production, you might want to store the nonce separately
    let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))
}

/// Decrypt sensitive config data
pub fn decrypt_config(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = derive_device_key();
    let cipher = Aes256Gcm::new(&key.into());

    let nonce = Nonce::from_slice(b"unique nonce");

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

/// Save encrypted config to file
pub fn save_encrypted_config(path: &Path, data: &[u8]) -> Result<(), String> {
    let encrypted = encrypt_config(data)?;
    fs::write(path, encrypted).map_err(|e| format!("Failed to write config: {}", e))
}

/// Load and decrypt config from file
pub fn load_encrypted_config(path: &Path) -> Result<Vec<u8>, String> {
    let encrypted = fs::read(path).map_err(|e| format!("Failed to read config: {}", e))?;
    decrypt_config(&encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let plaintext = b"sensitive_data_12345";
        let encrypted = encrypt_config(plaintext).unwrap();
        let decrypted = decrypt_config(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_device_key_deterministic() {
        let key1 = derive_device_key();
        let key2 = derive_device_key();

        assert_eq!(key1, key2, "Device key should be deterministic");
    }
}
