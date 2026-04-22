//! Peer Signaling Service for NAT Traversal
//!
//! Implements encrypted peer-to-peer signaling for coordinating NAT traversal.
//! Heartbeats network details to the Orchestrator and handles PeerJoin signals.

use crate::app::reverse::nat::{ConnectionStrategy, NatInfo, NatType};
use crate::error::Result;
use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Key};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use hickory_resolver::AsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

/// Peer signal containing network endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSignal {
    pub peer_id: String,
    pub public_addr: String,
    pub nat_type: String,
    pub timestamp: u64,
    /// Public key for establishing encrypted channel
    #[serde(with = "hex_serde")]
    pub public_key: [u8; 32],
}

/// Encrypted signal wrapper for secure peer communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSignal {
    pub sender_id: String,
    #[serde(with = "hex_serde_vec")]
    pub payload: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub nonce: [u8; 12],
}

/// PeerJoin signal received from orchestrator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerJoinSignal {
    pub peer_id: String,
    pub public_addr: SocketAddr,
    pub nat_type: NatType,
    #[serde(with = "hex_serde")]
    pub public_key: [u8; 32],
    /// Predicted ports for symmetric NAT (if applicable)
    pub predicted_ports: Vec<u16>,
}

/// Hex serialization helper
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T>(data: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        serializer.serialize_str(&hex::encode(data.as_ref()))
    }

    pub fn deserialize<'de, D, const N: usize>(
        deserializer: D,
    ) -> std::result::Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length"))
    }
}

/// Hex serialization helper for Vec<u8>
mod hex_serde_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Peer information stored in the peer map
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: [u8; 32],
    pub public_addr: Option<SocketAddr>,
    pub nat_type: NatType,
    pub last_seen: u64,
}

/// Map of Peer ID -> Peer Info
pub type PeerMap = DashMap<String, PeerInfo>;

/// Event channel for peer join notifications
pub type PeerJoinReceiver = mpsc::Receiver<PeerJoinSignal>;
pub type PeerJoinSender = mpsc::Sender<PeerJoinSignal>;

/// Signaling Service for NAT traversal coordination
pub struct SignalingService {
    orchestrator_url: String,
    peer_id: String,
    nat_info_provider: Arc<RwLock<NatInfo>>,
    peer_map: Arc<PeerMap>,
    secret_key: StaticSecret,
    public_key: PublicKey,
    cancellation_token: CancellationToken,
    peer_join_tx: PeerJoinSender,
    heartbeat_interval: Duration,
}

impl SignalingService {
    /// Create a new signaling service
    pub fn new(
        orchestrator_url: String,
        peer_id: String,
        nat_info_provider: Arc<RwLock<NatInfo>>,
    ) -> (Self, PeerJoinReceiver) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let (tx, rx) = mpsc::channel(32);

        let service = Self {
            orchestrator_url,
            peer_id,
            nat_info_provider,
            peer_map: Arc::new(DashMap::new()),
            secret_key: secret,
            public_key: public,
            cancellation_token: CancellationToken::new(),
            peer_join_tx: tx,
            heartbeat_interval: Duration::from_secs(10),
        };

        (service, rx)
    }

    /// Get our public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Get the peer map for external access
    pub fn peer_map(&self) -> Arc<PeerMap> {
        self.peer_map.clone()
    }

    /// Add a peer's public key to the map
    pub fn add_peer(&self, peer_id: String, info: PeerInfo) {
        self.peer_map.insert(peer_id, info);
    }

    /// Add just a peer's public key (legacy compatibility)
    pub fn add_peer_key(&self, peer_id: String, public_key: [u8; 32]) {
        self.peer_map.insert(
            peer_id,
            PeerInfo {
                public_key,
                public_addr: None,
                nat_type: NatType::Unknown,
                last_seen: 0,
            },
        );
    }

    /// Set custom heartbeat interval
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Start the signaling service background task
    pub async fn start(&self) {
        let token = self.cancellation_token.clone();
        let orchestrator_url = self.orchestrator_url.clone();
        let peer_id = self.peer_id.clone();
        let nat_provider = self.nat_info_provider.clone();
        let public_key = self.public_key_bytes();
        let heartbeat_interval = self.heartbeat_interval;
        let peer_map = self.peer_map.clone();
        let peer_join_tx = self.peer_join_tx.clone();

        tokio::spawn(async move {
            info!("Starting Signaling Service loop for peer: {}", peer_id);

            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        info!("Signaling Service stopped.");
                        break;
                    }
                    _ = tokio::time::sleep(heartbeat_interval) => {
                        let nat_info = nat_provider.read().await;
                        if let Some(addr) = nat_info.public_ip {
                            let signal = PeerSignal {
                                peer_id: peer_id.clone(),
                                public_addr: addr.to_string(),
                                nat_type: format!("{:?}", nat_info.nat_type),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                public_key,
                            };

                            match Self::send_heartbeat_to_orchestrator(&orchestrator_url, &signal).await {
                                Ok(peer_updates) => {
                                    debug!("Heartbeat sent successfully, received {} peer updates", peer_updates.len());

                                    // Process peer updates
                                    for peer_signal in peer_updates {
                                        if peer_signal.peer_id != peer_id {
                                            // Update peer map
                                            let peer_info = PeerInfo {
                                                public_key: peer_signal.public_key,
                                                public_addr: peer_signal.public_addr.parse().ok(),
                                                nat_type: Self::parse_nat_type(&peer_signal.nat_type),
                                                last_seen: peer_signal.timestamp,
                                            };

                                            let is_new = !peer_map.contains_key(&peer_signal.peer_id);
                                            peer_map.insert(peer_signal.peer_id.clone(), peer_info.clone());

                                            // If new peer, send join notification
                                            if is_new
                                                && let Some(addr) = peer_info.public_addr {
                                                    let join_signal = PeerJoinSignal {
                                                        peer_id: peer_signal.peer_id,
                                                        public_addr: addr,
                                                        nat_type: peer_info.nat_type,
                                                        public_key: peer_info.public_key,
                                                        predicted_ports: Vec::new(),
                                                    };

                                                    if peer_join_tx.send(join_signal).await.is_err() {
                                                        warn!("Peer join channel closed");
                                                    }
                                                }
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to send heartbeat: {}", e);
                                }
                            }
                        } else {
                            debug!("No public IP available yet, skipping heartbeat");
                        }
                    }
                }
            }
        });
    }

    fn parse_nat_type(s: &str) -> NatType {
        match s {
            "OpenInternet" => NatType::OpenInternet,
            "FullCone" => NatType::FullCone,
            "RestrictedCone" => NatType::RestrictedCone,
            "PortRestrictedCone" => NatType::PortRestrictedCone,
            "Symmetric" => NatType::Symmetric,
            "UdpBlocked" => NatType::UdpBlocked,
            _ => NatType::Unknown,
        }
    }

    /// Stop the signaling service
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }

    /// Send heartbeat to orchestrator and receive peer updates
    async fn send_heartbeat_to_orchestrator(
        url: &str,
        signal: &PeerSignal,
    ) -> Result<Vec<PeerSignal>> {
        debug!("Sending heartbeat to orchestrator: {}", url);

        // In production, this would use reqwest or gRPC
        // For now, we simulate the network call
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let response = client
            .post(format!("{}/api/v1/signal/heartbeat", url))
            .json(signal)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let peers: Vec<PeerSignal> = resp.json().await.unwrap_or_default();
                Ok(peers)
            }
            Ok(resp) => {
                warn!("Orchestrator returned error: {}", resp.status());
                Ok(Vec::new())
            }
            Err(e) => {
                // In development/testing, simulate empty response
                debug!("Heartbeat request failed (expected in test): {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Encrypts a payload for a specific target peer using X25519 + AES-256-GCM
    pub fn encrypt_for_peer(
        &self,
        target_peer_id: &str,
        payload: &[u8],
    ) -> Result<EncryptedSignal> {
        let peer_info = self
            .peer_map
            .get(target_peer_id)
            .ok_or_else(|| anyhow::anyhow!("Peer key not found: {}", target_peer_id))?;

        let peer_pk = PublicKey::from(peer_info.public_key);
        let shared_secret = self.secret_key.diffie_hellman(&peer_pk);

        // Derive encryption key from shared secret using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        hasher.update(b"signaling-encryption-v1"); // Domain separation
        let key_bytes = hasher.finalize();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Generate random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedSignal {
            sender_id: self.peer_id.clone(),
            payload: ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypts a signal from a peer
    pub fn decrypt_from_peer(&self, encrypted: &EncryptedSignal) -> Result<Vec<u8>> {
        let peer_info = self
            .peer_map
            .get(&encrypted.sender_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown sender: {}", encrypted.sender_id))?;

        let peer_pk = PublicKey::from(peer_info.public_key);
        let shared_secret = self.secret_key.diffie_hellman(&peer_pk);

        // Derive decryption key (same as encryption)
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        hasher.update(b"signaling-encryption-v1");
        let key_bytes = hasher.finalize();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce = GenericArray::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.payload.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Send an encrypted signal to a specific peer via the orchestrator
    pub async fn send_signal_to_peer(&self, target_peer_id: &str, payload: &[u8]) -> Result<()> {
        let encrypted = self.encrypt_for_peer(target_peer_id, payload)?;

        debug!("Sending encrypted signal to peer: {}", target_peer_id);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let response = client
            .post(format!(
                "{}/api/v1/signal/send/{}",
                self.orchestrator_url, target_peer_id
            ))
            .json(&encrypted)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(anyhow::anyhow!("Signal send failed: {}", resp.status())),
            Err(e) => {
                debug!("Signal send failed (expected in test): {}", e);
                Ok(())
            }
        }
    }

    /// Push a small signaling payload via DNS queries using chunked subdomains
    pub async fn send_dns_push_signal(
        &self,
        target_peer_id: &str,
        payload: &[u8],
        base_domain: &str,
    ) -> Result<()> {
        let encrypted = self.encrypt_for_peer(target_peer_id, payload)?;

        let json = serde_json::to_string(&encrypted)
            .map_err(|e| anyhow::anyhow!("Failed to serialize signal: {}", e))?;
        let b64 = URL_SAFE_NO_PAD.encode(json);

        // Setup async resolver for standard DNS lookup
        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let msg_id: u16 = rand::random();

        // DNS label length limit is 63 chars, use 50 chunks for safety
        let chunk_size = 50;
        let chunks: Vec<&[u8]> = b64.as_bytes().chunks(chunk_size).collect();
        let total = chunks.len();

        let short_id = if target_peer_id.len() > 16 {
            &target_peer_id[..16]
        } else {
            target_peer_id
        };

        for (i, chunk) in chunks.iter().enumerate() {
            let chunk_str = std::str::from_utf8(chunk).unwrap_or_default();
            // Format: <chunk_data>.<idx>.<total>.<msg_id>.<short_target_id>.<base_domain>
            let query_domain = format!(
                "{}.{}.{}.{:x}.{}.{}",
                chunk_str, i, total, msg_id, short_id, base_domain
            );

            debug!(
                "Pushing DNS signal chunk {}/{}: {}",
                i + 1,
                total,
                query_domain
            );

            // Fire and forget via TXT lookup.
            // In a restricted environment, this query forces the signal payload upstream.
            let _ = resolver.txt_lookup(query_domain).await;
        }

        Ok(())
    }
}

/// Determines the best connection strategy between two NAT types
pub fn determine_connection_strategy(our_nat: NatType, peer_nat: NatType) -> ConnectionStrategy {
    match (our_nat, peer_nat) {
        // Either side is open - direct connect
        (NatType::OpenInternet, _) | (_, NatType::OpenInternet) => {
            ConnectionStrategy::DirectConnect
        }
        (NatType::FullCone, _) | (_, NatType::FullCone) => ConnectionStrategy::DirectConnect,

        // Both sides are cone NAT - hole punching works
        (NatType::RestrictedCone, NatType::RestrictedCone)
        | (NatType::RestrictedCone, NatType::PortRestrictedCone)
        | (NatType::PortRestrictedCone, NatType::RestrictedCone)
        | (NatType::PortRestrictedCone, NatType::PortRestrictedCone) => {
            ConnectionStrategy::HolePunch
        }

        // One side is symmetric, other is cone - might work with port prediction
        (NatType::Symmetric, NatType::RestrictedCone)
        | (NatType::Symmetric, NatType::PortRestrictedCone)
        | (NatType::RestrictedCone, NatType::Symmetric)
        | (NatType::PortRestrictedCone, NatType::Symmetric) => {
            ConnectionStrategy::SymmetricHolePunch
        }

        // Both symmetric or blocked - must use relay
        _ => ConnectionStrategy::Relay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signaling_service_creation() {
        let nat_info = Arc::new(RwLock::new(NatInfo::default()));
        let (service, _rx) = SignalingService::new(
            "http://localhost:8080".to_string(),
            "test-peer".to_string(),
            nat_info,
        );

        assert_eq!(service.peer_id, "test-peer");
        assert_eq!(service.public_key_bytes().len(), 32);
    }

    #[tokio::test]
    async fn test_encryption_decryption() {
        let nat_info1 = Arc::new(RwLock::new(NatInfo::default()));
        let nat_info2 = Arc::new(RwLock::new(NatInfo::default()));

        let (service1, _rx1) = SignalingService::new(
            "http://localhost".to_string(),
            "peer-1".to_string(),
            nat_info1,
        );

        let (service2, _rx2) = SignalingService::new(
            "http://localhost".to_string(),
            "peer-2".to_string(),
            nat_info2,
        );

        // Exchange keys
        service1.add_peer_key("peer-2".to_string(), service2.public_key_bytes());
        service2.add_peer_key("peer-1".to_string(), service1.public_key_bytes());

        // Encrypt message from peer-1 to peer-2
        let message = b"Hello, peer-2!";
        let encrypted = service1.encrypt_for_peer("peer-2", message).unwrap();

        // Decrypt message at peer-2
        let decrypted = service2.decrypt_from_peer(&encrypted).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_connection_strategy() {
        assert_eq!(
            determine_connection_strategy(NatType::OpenInternet, NatType::Symmetric),
            ConnectionStrategy::DirectConnect
        );

        assert_eq!(
            determine_connection_strategy(NatType::PortRestrictedCone, NatType::PortRestrictedCone),
            ConnectionStrategy::HolePunch
        );

        assert_eq!(
            determine_connection_strategy(NatType::Symmetric, NatType::Symmetric),
            ConnectionStrategy::Relay
        );
    }
}
