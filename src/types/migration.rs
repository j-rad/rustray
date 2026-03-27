//! Migration and Backup/Restore Utilities
//!
//! Provides encrypted backup/restore functionality and v2rayNG subscription import.

use crate::types::{ServerConfig, Subscription};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::error::Error;

/// Ray configuration backup format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBackup {
    /// Backup format version
    pub version: u32,
    /// Timestamp of backup creation (Unix timestamp)
    pub created_at: u64,
    /// List of server configurations
    pub servers: Vec<ServerConfig>,
    /// List of subscriptions
    pub subscriptions: Vec<Subscription>,
    /// Application settings (key-value pairs)
    #[serde(default)]
    pub settings: std::collections::HashMap<String, serde_json::Value>,
}

impl ConfigBackup {
    /// Create a new backup with current timestamp
    pub fn new(
        servers: Vec<ServerConfig>,
        subscriptions: Vec<Subscription>,
        settings: std::collections::HashMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            version: 1,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            servers,
            subscriptions,
            settings,
        }
    }

    /// Export backup to encrypted JSON
    ///
    /// # Arguments
    ///
    /// * `password` - Password for encryption (will be hashed to derive key)
    ///
    /// # Returns
    ///
    /// Base64-encoded encrypted backup data
    pub fn export_encrypted(&self, password: &str) -> Result<String, Box<dyn Error>> {
        // Serialize to JSON
        let json = serde_json::to_string(self)?;

        // Derive encryption key from password using PBKDF2
        let key = derive_key(password)?;

        // Generate random nonce
        let nonce_bytes = generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt data
        let cipher = Aes256Gcm::new(&key.into());
        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Combine nonce + ciphertext
        let mut output = nonce_bytes.to_vec();
        output.extend_from_slice(&ciphertext);

        // Encode to base64
        Ok(BASE64.encode(&output))
    }

    /// Import backup from encrypted JSON
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - Base64-encoded encrypted backup
    /// * `password` - Password for decryption
    pub fn import_encrypted(encrypted_data: &str, password: &str) -> Result<Self, Box<dyn Error>> {
        // Decode from base64
        let data = BASE64
            .decode(encrypted_data)
            .map_err(|e| format!("Invalid base64: {}", e))?;

        if data.len() < 12 {
            return Err("Invalid encrypted data: too short".into());
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Derive decryption key
        let key = derive_key(password)?;

        // Decrypt data
        let cipher = Aes256Gcm::new(&key.into());
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed (wrong password?): {}", e))?;

        // Deserialize from JSON
        let backup: ConfigBackup = serde_json::from_slice(&plaintext)?;

        Ok(backup)
    }

    /// Export backup to unencrypted JSON (for debugging)
    pub fn export_json(&self) -> Result<String, Box<dyn Error>> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Import backup from unencrypted JSON
    pub fn import_json(json: &str) -> Result<Self, Box<dyn Error>> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Import v2rayNG subscription format
///
/// Parses v2rayNG-style subscription links (base64-encoded list of server URIs)
///
/// # Arguments
///
/// * `subscription_data` - Base64-encoded subscription data
///
/// # Returns
///
/// Vector of parsed server configurations
pub fn import_v2rayng_subscription(
    subscription_data: &str,
) -> Result<Vec<ServerConfig>, Box<dyn Error>> {
    // Decode base64
    let decoded = BASE64
        .decode(subscription_data.trim())
        .map_err(|e| format!("Invalid base64 subscription: {}", e))?;

    let content =
        String::from_utf8(decoded).map_err(|e| format!("Invalid UTF-8 in subscription: {}", e))?;

    // Split by newlines and parse each URI
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse using the existing parser
        match crate::types::parser::parse_share_link(line) {
            Ok(server) => servers.push(server),
            Err(e) => {
                log::warn!("Failed to parse subscription line '{}': {}", line, e);
            }
        }
    }

    Ok(servers)
}

/// Import servers from clipboard or text file
///
/// Supports multiple formats:
/// - Individual server URIs (vless://, vmess://, trojan://, ss://)
/// - v2rayNG subscription format (base64-encoded)
/// - Ray JSON backup
///
/// # Arguments
///
/// * `text` - Text content to parse
///
/// # Returns
///
/// Vector of parsed server configurations
pub fn import_from_text(text: &str) -> Result<Vec<ServerConfig>, Box<dyn Error>> {
    let text = text.trim();

    // Try parsing as JSON backup first
    if text.starts_with('{')
        && let Ok(backup) = ConfigBackup::import_json(text) {
            return Ok(backup.servers);
        }

    // Try parsing as base64 subscription
    if !text.contains('\n') && text.len() > 100
        && let Ok(servers) = import_v2rayng_subscription(text)
            && !servers.is_empty() {
                return Ok(servers);
            }

    // Parse as individual URIs
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match crate::types::parser::parse_share_link(line) {
            Ok(server) => servers.push(server),
            Err(e) => {
                log::warn!("Failed to parse line '{}': {}", line, e);
            }
        }
    }

    if servers.is_empty() {
        return Err("No valid servers found in text".into());
    }

    Ok(servers)
}

/// Derive encryption key from password using PBKDF2
fn derive_key(password: &str) -> Result<[u8; 32], Box<dyn Error>> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Use a fixed salt for simplicity (in production, store salt with backup)
    let salt = b"ray-backup-salt-v1";
    let mut key = [0u8; 32];

    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);

    Ok(key)
}

/// Generate random nonce for AES-GCM
fn generate_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_encryption() {
        let backup = ConfigBackup::new(vec![], vec![], Default::default());

        let encrypted = backup.export_encrypted("test-password").unwrap();
        let decrypted = ConfigBackup::import_encrypted(&encrypted, "test-password").unwrap();

        assert_eq!(backup.version, decrypted.version);
        assert_eq!(backup.servers.len(), decrypted.servers.len());
    }

    #[test]
    fn test_wrong_password() {
        let backup = ConfigBackup::new(vec![], vec![], Default::default());

        let encrypted = backup.export_encrypted("correct-password").unwrap();
        let result = ConfigBackup::import_encrypted(&encrypted, "wrong-password");

        assert!(result.is_err());
    }

    #[test]
    fn test_json_export() {
        let backup = ConfigBackup::new(vec![], vec![], Default::default());

        let json = backup.export_json().unwrap();
        let imported = ConfigBackup::import_json(&json).unwrap();

        assert_eq!(backup.version, imported.version);
    }
}
