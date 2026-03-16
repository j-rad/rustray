use crate::app::mesh::peer_registry::{GossipConfig, PeerAnnouncement, PeerRegistry};
use base64::{Engine as _, engine::general_purpose};
use log::{debug, info, warn};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use ring::aead::{self, LessSafeKey, NONCE_LEN, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

const MDNS_SERVICE_TYPE: &str = "_rustray._udp.local.";

/// Handles mDNS local peer discovery and maintains the Kademlia DHT routing table.
pub struct DiscoveryManager {
    registry: PeerRegistry,
    config: GossipConfig,
    mdns_daemon: Option<ServiceDaemon>,
    kademlia: Arc<RwLock<KademliaTable>>,
}

impl DiscoveryManager {
    pub fn new(config: GossipConfig, registry: PeerRegistry) -> Self {
        let local_id = config.local_peer_id;
        Self {
            registry,
            config,
            mdns_daemon: None,
            kademlia: Arc::new(RwLock::new(KademliaTable::new(local_id))),
        }
    }

    /// Starts mDNS broadcast and listening
    pub fn start_mdns(&mut self) -> Result<(), String> {
        let mdns =
            ServiceDaemon::new().map_err(|e| format!("Failed to start mDNS daemon: {}", e))?;
        self.mdns_daemon = Some(mdns.clone());

        // We use our peer ID as the instance name.
        let instance_name = hex::encode(self.config.local_peer_id);

        // Host IP and port
        let ip = match self.config.listener_addr.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.to_string(),
        };
        let port = self.config.listener_addr.port();

        // Create properties map
        let mut properties = HashMap::new();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(&self.config.keypair_pkcs8).unwrap();
        let ann = PeerAnnouncement::new(&key_pair, self.config.listener_addr);
        let mut ann_bytes = ann.to_bytes().to_vec();

        // Encrypt using AEAD with a static mesh PSK
        let psk = b"12345678901234567890123456789012"; // 32 bytes
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, psk).unwrap();
        let key = LessSafeKey::new(unbound_key);

        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ann_bytes)
            .unwrap();

        let mut payload = nonce_bytes.to_vec();
        payload.extend_from_slice(&ann_bytes);
        let b64 = general_purpose::STANDARD.encode(&payload);

        properties.insert("mesh_ann".to_string(), b64);
        properties.insert("version".to_string(), "1.1".to_string());

        let my_info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &instance_name,
            &format!("{}.local.", instance_name),
            ip,
            port,
            Some(properties),
        )
        .map_err(|e| format!("Failed to create ServiceInfo: {:?}", e))?;

        mdns.register(my_info)
            .map_err(|e| format!("Failed to register mDNS: {:?}", e))?;
        info!(
            "mDNS: Registered local node {} on {}",
            instance_name, self.config.listener_addr
        );

        let receiver = mdns
            .browse(MDNS_SERVICE_TYPE)
            .map_err(|e| format!("mDNS browse failed: {:?}", e))?;

        let registry = self.registry.clone();
        let kademlia = self.kademlia.clone();
        let local_id = self.config.local_peer_id;

        tokio::spawn(async move {
            info!("mDNS browser task started");
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let remote_name = info.get_fullname();
                        // Get IP and Port
                        let ips = info.get_addresses();
                        if ips.is_empty() {
                            continue;
                        }
                        let ip_str = ips.iter().next().unwrap().to_string();
                        let ip: IpAddr = match ip_str.parse() {
                            Ok(addr) => addr,
                            Err(_) => continue,
                        };
                        let port = info.get_port();
                        let addr = SocketAddr::new(ip, port);

                        // Get peer ID from properties
                        let mesh_ann_str = match info.get_property_val_str("mesh_ann") {
                            Some(v) => v,
                            None => continue,
                        };

                        let payload = match general_purpose::STANDARD.decode(mesh_ann_str) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        if payload.len() < NONCE_LEN {
                            continue;
                        }

                        let psk = b"12345678901234567890123456789012"; // 32 bytes
                        let unbound_key = match UnboundKey::new(&aead::AES_256_GCM, psk) {
                            Ok(k) => k,
                            Err(_) => continue,
                        };
                        let key = LessSafeKey::new(unbound_key);

                        let mut nonce_bytes = [0u8; NONCE_LEN];
                        nonce_bytes.copy_from_slice(&payload[..NONCE_LEN]);
                        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

                        let mut ciphertext = payload[NONCE_LEN..].to_vec();
                        let plaintext =
                            match key.open_in_place(nonce, aead::Aad::empty(), &mut ciphertext) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };

                        let ann = match PeerAnnouncement::from_bytes(plaintext) {
                            Some(a) => a,
                            None => continue,
                        };

                        if ann.peer_id == local_id {
                            continue; // Skip self
                        }

                        if !ann.verify() {
                            warn!("mDNS: Peer announcement verification failed");
                            continue;
                        }

                        let peer_id_bytes = ann.peer_id;
                        // Use verified addr from announcement instead of potentially spoofed mDNS addr
                        let addr = ann.addr;

                        debug!(
                            "mDNS: Discovered peer {} at {}",
                            hex::encode(peer_id_bytes),
                            addr
                        );

                        // Update registry and DHT
                        registry.upsert(&ann).await;
                        kademlia.write().await.add_node(peer_id_bytes, addr);
                    }
                    ServiceEvent::ServiceRemoved(_, _fullname) => {
                        // Node left, DHT prune will catch it eventually, or we could remove it here
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    pub fn get_kademlia(&self) -> Arc<RwLock<KademliaTable>> {
        self.kademlia.clone()
    }
}

// ============================================================================
// LIGHTWEIGHT KADEMLIA DHT ROUTING TABLE
// ============================================================================

const BUCKET_SIZE: usize = 20;

#[derive(Clone, Debug)]
pub struct RouteEntry {
    pub peer_id: [u8; 32],
    pub addr: SocketAddr,
    pub last_seen: SystemTime,
}

pub struct KademliaTable {
    local_id: [u8; 32],
    // 256 buckets, mapping XOR distance (number of leading zeros) to a list of RouteEntries
    buckets: Vec<Vec<RouteEntry>>,
}

impl KademliaTable {
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            local_id,
            buckets: vec![Vec::new(); 256],
        }
    }

    /// Calculate XOR distance and return number of leading zero bits
    fn bucket_index(local: &[u8; 32], remote: &[u8; 32]) -> usize {
        for i in 0..32 {
            let xor = local[i] ^ remote[i];
            if xor != 0 {
                // Number of leading zeros in this byte + leading zeros of previous bytes
                return (i * 8) + xor.leading_zeros() as usize;
            }
        }
        255
    }

    pub fn add_node(&mut self, peer_id: [u8; 32], addr: SocketAddr) {
        if peer_id == self.local_id {
            return;
        }
        let idx = Self::bucket_index(&self.local_id, &peer_id);
        let bucket = &mut self.buckets[idx];

        // If exists, update
        if let Some(entry) = bucket.iter_mut().find(|e| e.peer_id == peer_id) {
            entry.addr = addr;
            entry.last_seen = SystemTime::now();
            return;
        }

        // Add if space
        if bucket.len() < BUCKET_SIZE {
            bucket.push(RouteEntry {
                peer_id,
                addr,
                last_seen: SystemTime::now(),
            });
        } else {
            // Simplistic: replace the oldest if the new one is fresher?
            // In a real DHT we'd ping the oldest.
            // Here we just replace the oldest entry.
            bucket.sort_by_key(|e| e.last_seen);
            bucket[0] = RouteEntry {
                peer_id,
                addr,
                last_seen: SystemTime::now(),
            };
        }
    }

    pub fn find_closest_peers(&self, target: &[u8; 32], count: usize) -> Vec<RouteEntry> {
        let mut all_peers: Vec<&RouteEntry> = self.buckets.iter().flat_map(|b| b.iter()).collect();
        all_peers.sort_by_key(|e| {
            let mut xor_dist = [0u8; 32];
            for i in 0..32 {
                xor_dist[i] = target[i] ^ e.peer_id[i];
            }
            xor_dist // Lexicographical sort corresponds to numerical sort
        });

        all_peers.into_iter().take(count).cloned().collect()
    }
}
