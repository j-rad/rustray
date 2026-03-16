// src/app/dns/fakedns.rs
use crate::config::FakeDnsConfig;
use ipnetwork::Ipv4Network;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

#[derive(Debug, Serialize, Deserialize)]
struct FakeDnsState {
    version: u32,
    mappings: Vec<(String, Ipv4Addr)>,
    current_index: u64,
}

#[derive(Debug, Clone)]
pub struct FakeDns {
    inner: Arc<FakeDnsInner>,
}

#[derive(Debug)]
struct FakeDnsInner {
    // LRU cache: domain -> IP
    mapping: Mutex<LruCache<String, Ipv4Addr>>,
    // Reverse mapping: IP -> domain (for quick lookup)
    reverse_mapping: Mutex<HashMap<Ipv4Addr, String>>,
    ip_pool: Ipv4Network,
    pool_size: u64,
    current_index: AtomicU64,
    persist_path: Option<String>,
}

impl FakeDns {
    pub fn new(config: FakeDnsConfig) -> anyhow::Result<Self> {
        let ip_pool = Ipv4Network::from_str(&config.ip_pool)?;
        let max_entries = NonZeroUsize::new(config.max_entries)
            .ok_or_else(|| anyhow::anyhow!("max_entries must be > 0"))?;

        let inner = Arc::new(FakeDnsInner {
            mapping: Mutex::new(LruCache::new(max_entries)),
            reverse_mapping: Mutex::new(HashMap::new()),
            ip_pool,
            pool_size: config.pool_size as u64,
            current_index: AtomicU64::new(0),
            persist_path: config.persist_path.clone(),
        });

        let fakedns = Self { inner };

        // Load persisted state if available
        if let Some(path) = &config.persist_path {
            if Path::new(path).exists() {
                if let Err(e) = fakedns.load_state(path) {
                    warn!("FakeDNS: Failed to load state from {}: {}", path, e);
                }
            }
        }

        Ok(fakedns)
    }

    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.inner.ip_pool.contains(ipv4),
            _ => false,
        }
    }

    pub fn get_domain_from_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                if self.inner.ip_pool.contains(ipv4) {
                    self.inner
                        .reverse_mapping
                        .lock()
                        .unwrap()
                        .get(&ipv4)
                        .cloned()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn get_fake_ip(&self, host: &str) -> Ipv4Addr {
        // Check if already mapped
        {
            let mut mapping = self.inner.mapping.lock().unwrap();
            if let Some(ip) = mapping.get(host) {
                return *ip;
            }
        }

        // Allocate new IP
        let index = self.inner.current_index.fetch_add(1, Ordering::Relaxed) % self.inner.pool_size;

        // Calculate IP from network + index
        let network_u32: u32 = self.inner.ip_pool.ip().into();
        let ip_u32 = network_u32 + (index as u32);
        let ip = Ipv4Addr::from(ip_u32);

        // Store mappings
        {
            let mut mapping = self.inner.mapping.lock().unwrap();
            let mut reverse = self.inner.reverse_mapping.lock().unwrap();

            // If LRU evicts an entry, we need to clean up reverse mapping
            if let Some((evicted_domain, evicted_ip)) = mapping.push(host.to_string(), ip) {
                reverse.remove(&evicted_ip);
                debug!(
                    "FakeDNS: Evicted {} -> {} (LRU full)",
                    evicted_domain, evicted_ip
                );
            }

            // If IP was reused (wraparound), remove old domain mapping
            if let Some(old_domain) = reverse.insert(ip, host.to_string()) {
                mapping.pop(&old_domain);
            }
        }

        debug!("FakeDNS: Allocated {} -> {}", host, ip);
        ip
    }

    /// Save current state to disk
    pub fn save_state(&self, path: &str) -> anyhow::Result<()> {
        let mapping = self.inner.mapping.lock().unwrap();
        let current_index = self.inner.current_index.load(Ordering::Relaxed);

        let state = FakeDnsState {
            version: 1,
            mappings: mapping.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            current_index,
        };

        let json = serde_json::to_string_pretty(&state)?;
        fs::write(path, json)?;
        info!(
            "FakeDNS: Saved {} mappings to {}",
            state.mappings.len(),
            path
        );
        Ok(())
    }

    /// Load state from disk
    pub fn load_state(&self, path: &str) -> anyhow::Result<()> {
        let json = fs::read_to_string(path)?;
        let state: FakeDnsState = serde_json::from_str(&json)?;

        if state.version != 1 {
            return Err(anyhow::anyhow!(
                "Unsupported FakeDNS state version: {}",
                state.version
            ));
        }

        let mut mapping = self.inner.mapping.lock().unwrap();
        let mut reverse = self.inner.reverse_mapping.lock().unwrap();

        for (domain, ip) in state.mappings {
            mapping.put(domain.clone(), ip);
            reverse.insert(ip, domain);
        }

        self.inner
            .current_index
            .store(state.current_index, Ordering::Relaxed);

        info!("FakeDNS: Loaded {} mappings from {}", mapping.len(), path);
        Ok(())
    }

    /// Get current cache statistics
    pub fn stats(&self) -> (usize, usize) {
        let mapping = self.inner.mapping.lock().unwrap();
        (mapping.len(), mapping.cap().get())
    }

    /// Trigger manual save if persistence is enabled
    pub fn persist(&self) -> anyhow::Result<()> {
        if let Some(path) = &self.inner.persist_path {
            self.save_state(path)?;
        }
        Ok(())
    }
}
