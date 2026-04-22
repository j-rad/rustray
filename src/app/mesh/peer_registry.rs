// src/app/mesh/peer_registry.rs
//! Decentralised Peer Registry
//!
//! A DHT-inspired rendezvous store that works without a central directory.
//!
//! Design sketch:
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │  PeerGossip task                             │
//! │  ┌──────────┐      HMAC-SHA256              │
//! │  │ local    │──── PeerAnnouncement ────────►│
//! │  │ keypair  │                               │  MQTT meta topic
//! │  └──────────┘◄─── PeerAnnouncement ─────────│
//! └──────────────────────────────────────────────┘
//!              │
//!              ▼
//!       PeerRegistry (in-memory, TTL=5 min)
//!              │
//!              ▼
//!       find_live_peers() → Vec<PeerEntry> sorted by last_seen
//! ```
//!
//! Wire format of `PeerAnnouncement` (130 bytes total):
//! ```text
//! [peer_id   32 B]  — Ed25519 public key
//! [addr      18 B]  — 16-byte IPv6 (or v4-in-v6) + 2-byte port, big-endian
//! [timestamp  8 B]  — Unix seconds, big-endian u64
//! [nonce      8 B]  — Proof-of-work nonce
//! [signature 64 B]  — Ed25519 signature over (peer_id || addr || timestamp || nonce)
//! ```

use ring::signature::{self, KeyPair};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Encoded announcement size in bytes.
pub const ANNOUNCEMENT_SIZE: usize = 130;

/// Time-to-live: entries older than this are pruned from the registry.
pub const PEER_TTL: Duration = Duration::from_secs(300);

/// How often the local node re-announces itself.
pub const GOSSIP_INTERVAL: Duration = Duration::from_secs(60);

// ============================================================================
// PEER ANNOUNCEMENT
// ============================================================================

/// Authenticated wire advertisement for a single peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAnnouncement {
    /// 32-byte Ed25519 public key.
    pub peer_id: [u8; 32],
    /// Socket address of the peer's REALITY / VLESS listener.
    pub addr: SocketAddr,
    /// Unix timestamp at which the announcement was created (seconds).
    pub timestamp: u64,
    /// 8-byte nonce for Proof of Work.
    pub nonce: u64,
    /// 64-byte Ed25519 signature over `peer_id || encoded_addr || timestamp || nonce`.
    pub signature: [u8; 64],
}

impl PeerAnnouncement {
    /// Create, sign, and mine a fresh announcement.
    pub fn new(key_pair: &signature::Ed25519KeyPair, addr: SocketAddr) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(key_pair.public_key().as_ref());

        let mut ann = Self {
            peer_id,
            addr,
            timestamp,
            nonce: 0,
            signature: [0u8; 64],
        };

        ann.mine(key_pair);
        ann
    }

    /// Serialise to the 130-byte wire format.
    pub fn to_bytes(&self) -> [u8; ANNOUNCEMENT_SIZE] {
        let mut out = [0u8; ANNOUNCEMENT_SIZE];
        out[..32].copy_from_slice(&self.peer_id);
        let addr_bytes = encode_addr(self.addr);
        out[32..50].copy_from_slice(&addr_bytes);
        out[50..58].copy_from_slice(&self.timestamp.to_be_bytes());
        out[58..66].copy_from_slice(&self.nonce.to_be_bytes());
        out[66..130].copy_from_slice(&self.signature);
        out
    }

    /// Deserialise from the 130-byte wire format.
    ///
    /// Does **not** verify the signature or PoW — call [`verify`](Self::verify) separately.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != ANNOUNCEMENT_SIZE {
            return None;
        }
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(&b[..32]);

        let addr = decode_addr(&b[32..50])?;

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&b[50..58]);
        let timestamp = u64::from_be_bytes(ts_bytes);

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&b[58..66]);
        let nonce = u64::from_be_bytes(nonce_bytes);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&b[66..130]);

        Some(Self {
            peer_id,
            addr,
            timestamp,
            nonce,
            signature,
        })
    }

    /// Verify the signature, PoW, and check the timestamp is not stale or in the future.
    pub fn verify(&self) -> bool {
        // Validate timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age = now.saturating_sub(self.timestamp);
        let skew = self.timestamp.saturating_sub(now);
        if age > PEER_TTL.as_secs() || skew > 30 {
            return false;
        }

        // Validate PoW
        let hash = self.compute_full_hash();
        if !Self::check_pow(&hash) {
            return false;
        }

        // Validate signature
        let msg = self.signing_bytes();
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, self.peer_id);
        public_key.verify(&msg, &self.signature).is_ok()
    }

    // ------------------------------------------------------------------ priv

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 18 + 8 + 8);
        bytes.extend_from_slice(&self.peer_id);
        bytes.extend_from_slice(&encode_addr(self.addr));
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes
    }

    fn compute_full_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }

    fn check_pow(hash: &[u8; 32]) -> bool {
        #[cfg(test)]
        return hash[0] == 0 && (hash[1] & 0xF0) == 0; // 12 leading zero bits

        #[cfg(not(test))]
        return hash[0] == 0 && hash[1] == 0 && (hash[2] & 0xF0) == 0; // 20 leading zero bits
    }

    fn mine(&mut self, key_pair: &signature::Ed25519KeyPair) {
        loop {
            // Sign the current nonce
            let msg = self.signing_bytes();
            self.signature.copy_from_slice(key_pair.sign(&msg).as_ref());

            let hash = self.compute_full_hash();
            if Self::check_pow(&hash) {
                break;
            }
            self.nonce = self.nonce.wrapping_add(1);
        }
    }
}

// ============================================================================
// PEER REGISTRY
// ============================================================================

/// A live peer entry in the registry.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub peer_id: [u8; 32],
    pub addr: SocketAddr,
    /// Wall-clock instant of the last valid announcement from this peer.
    pub last_seen: SystemTime,
    pub via: Option<[u8; 32]>,
}

/// In-memory peer registry with TTL-based expiry.
///
/// Thread-safe via `Arc<RwLock>`.
#[derive(Clone, Default)]
pub struct PeerRegistry {
    inner: Arc<RwLock<HashMap<[u8; 32], PeerEntry>>>,
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update an entry from a verified [`PeerAnnouncement`].
    ///
    /// Callers **must** have called [`PeerAnnouncement::verify`] before this.
    pub async fn upsert(&self, ann: &PeerAnnouncement) {
        let mut map = self.inner.write().await;
        let entry = map.entry(ann.peer_id).or_insert_with(|| PeerEntry {
            peer_id: ann.peer_id,
            addr: ann.addr,
            last_seen: SystemTime::UNIX_EPOCH,
            via: None,
        });

        // Always update addr and last_seen.
        entry.addr = ann.addr;
        entry.last_seen = SystemTime::now();
        entry.via = None; // Reset if it was a bridged route, direct announcement is better.
        debug!(
            "peer_registry: upserted peer {:?}",
            hex::encode(ann.peer_id)
        );
    }

    /// Upsert from mDNS discovery (no signature verified yet).
    pub async fn upsert_raw(&self, peer_id: [u8; 32], addr: SocketAddr) {
        let mut map = self.inner.write().await;
        let entry = map.entry(peer_id).or_insert_with(|| PeerEntry {
            peer_id,
            addr,
            last_seen: SystemTime::now(),
            via: None,
        });
        entry.addr = addr;
        entry.last_seen = SystemTime::now();
        debug!(
            "peer_registry: upserted raw peer {:?}",
            hex::encode(peer_id)
        );
    }

    /// Return all peers seen within `PEER_TTL`, sorted newest-first.
    pub async fn find_live_peers(&self) -> Vec<PeerEntry> {
        let map = self.inner.read().await;
        let cutoff = SystemTime::now()
            .checked_sub(PEER_TTL)
            .unwrap_or(UNIX_EPOCH);

        let mut peers: Vec<PeerEntry> = map
            .values()
            .filter(|e| e.last_seen >= cutoff)
            .cloned()
            .collect();

        // Newest first.
        peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        peers
    }

    /// Remove all entries older than `PEER_TTL`.
    pub async fn prune_stale(&self) {
        let mut map = self.inner.write().await;
        let cutoff = SystemTime::now()
            .checked_sub(PEER_TTL)
            .unwrap_or(UNIX_EPOCH);
        let before = map.len();
        map.retain(|_, e| e.last_seen >= cutoff);
        let removed = before - map.len();
        if removed > 0 {
            debug!("peer_registry: pruned {removed} stale entries");
        }
    }

    /// Number of live entries (for metrics).
    pub async fn live_count(&self) -> usize {
        self.find_live_peers().await.len()
    }
}

// ============================================================================
// PEER GOSSIP
// ============================================================================

/// Gossip configuration for the local node.
pub struct GossipConfig {
    /// 32-byte peer identity of this node.
    pub local_peer_id: [u8; 32],
    /// Address to advertise to other peers.
    pub listener_addr: SocketAddr,
    /// PKCS#8 encoded Ed25519 keypair for signing gossip.
    pub keypair_pkcs8: Vec<u8>,
    /// MQTT broker hostname or IP
    pub broker_host: String,
    /// MQTT broker port
    pub broker_port: u16,
}

impl GossipConfig {
    /// Generate a random peer ID/Keypair from OS entropy.
    pub fn new_random_id(listener_addr: SocketAddr, broker_host: String, broker_port: u16) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .unwrap()
            .as_ref()
            .to_vec();

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let mut peer_id = [0u8; 32];
        peer_id.copy_from_slice(key_pair.public_key().as_ref());

        Self {
            local_peer_id: peer_id,
            listener_addr,
            keypair_pkcs8: pkcs8,
            broker_host,
            broker_port,
        }
    }
}

/// Drives periodic gossip: re-announces the local node and processes incoming
/// announcements received over the MQTT meta-topic.
///
/// Spawn via [`PeerGossip::run`].
pub struct PeerGossip {
    config: GossipConfig,
    registry: PeerRegistry,
}

impl PeerGossip {
    /// Create a gossip driver attached to `registry`.
    pub fn new(config: GossipConfig, registry: PeerRegistry) -> Self {
        Self { config, registry }
    }

    /// Build a fresh signed announcement for the local node.
    pub fn local_announcement(&self) -> PeerAnnouncement {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(&self.config.keypair_pkcs8).unwrap();
        PeerAnnouncement::new(&key_pair, self.config.listener_addr)
    }

    /// Serialise the local announcement to bytes, ready to publish.
    pub fn local_announcement_bytes(&self) -> [u8; ANNOUNCEMENT_SIZE] {
        self.local_announcement().to_bytes()
    }

    /// Process a raw announcement received over MQTT.
    ///
    /// Deserialises, verifies the HMAC + timestamp, and upserts into the
    /// registry.  Silently drops invalid or replayed announcements.
    pub async fn ingest_raw(&self, raw: &[u8]) {
        match PeerAnnouncement::from_bytes(raw) {
            None => {
                warn!(
                    "peer_gossip: received malformed announcement ({} B)",
                    raw.len()
                );
            }
            Some(ann) => {
                if ann.peer_id == self.config.local_peer_id {
                    // Ignore our own announcements echoed back by the broker.
                    return;
                }
                if ann.verify() {
                    self.registry.upsert(&ann).await;
                } else {
                    warn!(
                        "peer_gossip: signature/PoW/timestamp verification failed for peer {:?}",
                        hex::encode(ann.peer_id)
                    );
                }
            }
        }
    }

    /// Periodic maintenance: prune stale registry entries.
    ///
    /// Call this at the same cadence as [`GOSSIP_INTERVAL`].
    pub async fn prune(&self) {
        self.registry.prune_stale().await;
    }

    /// MQTT meta-topic for a given epoch bucket.
    ///
    /// Epoch = Unix seconds ÷ `GOSSIP_INTERVAL`.  Both sides compute the same
    /// value independently, so no extra synchronisation is needed.
    pub fn meta_topic_for_epoch(epoch: u64) -> String {
        format!("meta/ring/{epoch}")
    }

    /// Current gossip epoch.
    pub fn current_epoch() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / GOSSIP_INTERVAL.as_secs()
    }

    /// Run the background gossip loop: connect to MQTT broker, publish local announcement,
    /// and subscribe to remote announcements.
    pub async fn run(self) {
        let mut mqttoptions = MqttOptions::new(
            format!(
                "rustray-gossip-{}",
                hex::encode(&self.config.local_peer_id[..4])
            ),
            &self.config.broker_host,
            self.config.broker_port,
        );
        mqttoptions.set_keep_alive(Duration::from_secs(10));

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
        let mut current_sub_epoch = 0;

        loop {
            let epoch = Self::current_epoch();

            // Re-subscribe if epoch changed
            if epoch != current_sub_epoch {
                let topic = Self::meta_topic_for_epoch(epoch);
                if let Err(e) = client.subscribe(&topic, QoS::AtMostOnce).await {
                    error!("peer_gossip: Failed to subscribe to epoch {}: {}", epoch, e);
                } else {
                    debug!("peer_gossip: subscribed to epoch topic: {}", topic);
                    current_sub_epoch = epoch;
                }
            }

            // Publish local announcement
            let topic = Self::meta_topic_for_epoch(epoch);
            let payload = self.local_announcement_bytes().to_vec();
            if let Err(e) = client.publish(topic, QoS::AtMostOnce, false, payload).await {
                warn!("peer_gossip: failed to publish announcement: {}", e);
            }

            // Prune stale entries
            self.prune().await;

            // Wait for incoming MQTT events, interrupting after GOSSIP_INTERVAL to republish
            match tokio::time::timeout(GOSSIP_INTERVAL, async {
                loop {
                    match eventloop.poll().await {
                        Ok(Event::Incoming(Packet::Publish(p))) => {
                            self.ingest_raw(&p.payload).await;
                        }
                        Ok(_) => {} // Ignore other events
                        Err(e) => {
                            warn!("peer_gossip: MQTT error: {:?}", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            })
            .await
            {
                Ok(_) => {} // Should theoretically not be reachable normally
                Err(_) => {
                    // Timeout passed (GOSSIP_INTERVAL elapsed), loop repeats
                }
            }
        }
    }
}

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

/// Encode a `SocketAddr` as 18 bytes: 16-byte IPv6 (v4-mapped for IPv4) + 2-byte port BE.
fn encode_addr(addr: SocketAddr) -> [u8; 18] {
    let mut out = [0u8; 18];
    let (ip16, port) = match addr {
        SocketAddr::V4(v4) => {
            let mapped = v4.ip().to_ipv6_mapped();
            (mapped.octets(), v4.port())
        }
        SocketAddr::V6(v6) => (v6.ip().octets(), v6.port()),
    };
    out[..16].copy_from_slice(&ip16);
    out[16..18].copy_from_slice(&port.to_be_bytes());
    out
}

/// Decode the 18-byte address encoding back to a `SocketAddr`.
fn decode_addr(b: &[u8]) -> Option<SocketAddr> {
    if b.len() != 18 {
        return None;
    }
    let mut ip6 = [0u8; 16];
    ip6.copy_from_slice(&b[..16]);
    let port = u16::from_be_bytes([b[16], b[17]]);
    let addr6 = std::net::Ipv6Addr::from(ip6);
    if let Some(v4) = addr6.to_ipv4_mapped() {
        Some(SocketAddr::from((v4, port)))
    } else {
        Some(SocketAddr::from((addr6, port)))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), port)
    }

    fn make_keypair() -> signature::Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .unwrap()
            .as_ref()
            .to_vec();
        signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap()
    }

    // ------------------------------------------------------------------
    // Wire format
    // ------------------------------------------------------------------

    #[test]
    fn test_announcement_round_trip() {
        let key_pair = make_keypair();
        let addr = make_addr(4433);

        let ann = PeerAnnouncement::new(&key_pair, addr);
        let bytes = ann.to_bytes();
        let ann2 = PeerAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(ann.peer_id, ann2.peer_id);
        assert_eq!(ann.addr, ann2.addr);
        assert_eq!(ann.timestamp, ann2.timestamp);
        assert_eq!(ann.nonce, ann2.nonce);
        assert_eq!(ann.signature, ann2.signature);
    }

    // ------------------------------------------------------------------
    // Signature and PoW verification
    // ------------------------------------------------------------------

    #[test]
    fn test_peer_announcement_signature_and_pow_valid() {
        let key_pair = make_keypair();
        let ann = PeerAnnouncement::new(&key_pair, make_addr(443));
        assert!(ann.verify(), "fresh announcement must pass verification");
    }

    #[test]
    fn test_peer_announcement_invalid_pow_or_signature() {
        let key_pair = make_keypair();
        let mut ann = PeerAnnouncement::new(&key_pair, make_addr(443));

        // Tamper with the address.
        ann.addr = make_addr(9999);

        assert!(
            !ann.verify(),
            "tampered announcement must fail verification"
        );
    }

    #[test]
    fn test_peer_announcement_wrong_signature() {
        let key_pair = make_keypair();
        let mut ann = PeerAnnouncement::new(&key_pair, make_addr(443));

        let wrong_key_pair = make_keypair();
        // Replace signature with wrong one
        let msg = ann.signing_bytes();
        ann.signature
            .copy_from_slice(wrong_key_pair.sign(&msg).as_ref());

        assert!(!ann.verify(), "wrong signature must fail verification");
    }

    // ------------------------------------------------------------------
    // PeerRegistry
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_peer_registry_live_peers_sorted() {
        let registry = PeerRegistry::new();

        // Insert two peers with different last_seen times by manipulating entries directly.
        // We use two distinct peer_ids.
        let older_id = [0x01u8; 32];
        let newer_id = [0x02u8; 32];

        let older_entry = PeerEntry {
            peer_id: older_id,
            addr: make_addr(1000),
            last_seen: SystemTime::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap(),
            via: None,
        };
        let newer_entry = PeerEntry {
            peer_id: newer_id,
            addr: make_addr(2000),
            last_seen: SystemTime::now(),
            via: None,
        };

        {
            let mut map = registry.inner.write().await;
            map.insert(older_id, older_entry);
            map.insert(newer_id, newer_entry);
        }

        let peers = registry.find_live_peers().await;
        assert_eq!(peers.len(), 2, "both entries should be live");
        assert_eq!(peers[0].peer_id, newer_id, "newer entry must rank first");
        assert_eq!(peers[1].peer_id, older_id);

        // Verify payload signature is irrelevant for the registry's sort (it only checks last_seen).
    }

    #[tokio::test]
    async fn test_peer_registry_ttl_expiry() {
        let registry = PeerRegistry::new();

        // Insert an entry with last_seen 6 minutes ago (past TTL).
        let stale_id = [0xDEu8; 32];
        {
            let mut map = registry.inner.write().await;
            map.insert(
                stale_id,
                PeerEntry {
                    peer_id: stale_id,
                    addr: make_addr(4433),
                    last_seen: SystemTime::now()
                        .checked_sub(Duration::from_secs(360))
                        .unwrap(),
                    via: None,
                },
            );
        }

        // find_live_peers filters by TTL — entry must be absent.
        let live = registry.find_live_peers().await;
        assert!(
            live.is_empty(),
            "stale entry must not appear in find_live_peers"
        );

        // Prune must also remove it from the backing map.
        registry.prune_stale().await;
        let map = registry.inner.read().await;
        assert!(
            !map.contains_key(&stale_id),
            "prune_stale must evict stale entry"
        );
    }

    #[tokio::test]
    async fn test_gossip_ingest_valid() {
        let registry = PeerRegistry::new();
        let config = GossipConfig::new_random_id(make_addr(7777), "localhost".to_string(), 1883);
        let gossip = PeerGossip::new(config, registry.clone());

        // A second peer announces itself.
        let other_key_pair = make_keypair();
        let mut other_id = [0u8; 32];
        other_id.copy_from_slice(other_key_pair.public_key().as_ref());
        let ann = PeerAnnouncement::new(&other_key_pair, make_addr(8888));
        gossip.ingest_raw(&ann.to_bytes()).await;

        let live = registry.find_live_peers().await;
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].peer_id, other_id);
    }

    #[tokio::test]
    async fn test_gossip_ingest_rejects_own_announcement() {
        let registry = PeerRegistry::new();
        let config = GossipConfig::new_random_id(make_addr(7777), "localhost".to_string(), 1883);
        let _local_id = config.local_peer_id;

        // Setup local_key_pair identical to config to sign announcement
        let local_key_pair = signature::Ed25519KeyPair::from_pkcs8(&config.keypair_pkcs8).unwrap();
        let gossip = PeerGossip::new(config, registry.clone());

        // Ingest our own announcement (as if echoed back by the broker).
        let ann = PeerAnnouncement::new(&local_key_pair, make_addr(7777));
        gossip.ingest_raw(&ann.to_bytes()).await;

        // Must not be added to the registry.
        let live = registry.find_live_peers().await;
        assert!(live.is_empty(), "own echoed announcement must be ignored");
    }
}
