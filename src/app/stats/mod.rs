// src/app/stats/mod.rs
use crate::app::dns::DnsServer;
use crate::app::policy::PolicyManager;
use crate::config::{Config, Inbound, Outbound};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

static GLOBAL_STATS_MANAGER: OnceLock<Arc<StatsManager>> = OnceLock::new();

#[derive(Clone, Debug)]
pub enum ConfigEvent {
    InboundAdded(Inbound),
    InboundRemoved(String), // Tag
    OutboundAdded(Outbound),
    OutboundRemoved(String), // Tag
    FullReload,              // New event for full reload
}

/// Tracks online IPs for a user/inbound with timestamp
#[derive(Clone, Debug)]
pub struct OnlineIpEntry {
    pub ip: String,
    pub last_seen: Instant,
}

use arc_swap::ArcSwap;

pub use crate::types::{ConnectionMetrics, DpiState};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorStats {
    pub last_latency: u64,
    pub avg_latency: u64,
    pub jitter: u64,
    pub success_rate: f64,
    pub total_success: u64,
    pub total_fail: u64,
}

#[derive(Clone)]
pub struct StatsManager {
    pub config: Arc<ArcSwap<Config>>,
    pub policy_manager: Arc<PolicyManager>,
    pub dns_server: Arc<DnsServer>,
    pub counters: DashMap<String, Arc<AtomicU64>>,
    /// Tracks online IPs per user/inbound: key = "user:email" or "inbound:tag", value = list of IPs
    pub online_ips: DashMap<String, Vec<OnlineIpEntry>>,
    /// High-frequency metrics for active connections
    pub connection_metrics: DashMap<String, VecDeque<ConnectionMetrics>>,
    /// Background monitor stats per outbound tag
    pub outbound_stats: DashMap<String, MonitorStats>,
    pub config_event_tx: broadcast::Sender<ConfigEvent>,
}

use std::collections::VecDeque;
const MAX_METRIC_SAMPLES: usize = 100;

impl StatsManager {
    pub fn new(mut config: Config, dns_server: Arc<DnsServer>) -> Self {
        let policy_config = config.policy.take().unwrap_or_default();
        let policy_manager = Arc::new(PolicyManager::new(policy_config));
        let (tx, _) = broadcast::channel(16);

        let instance = Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            policy_manager,
            dns_server,
            counters: DashMap::new(),
            online_ips: DashMap::new(),
            connection_metrics: DashMap::new(),
            outbound_stats: DashMap::new(),
            config_event_tx: tx,
        };
        let _ = GLOBAL_STATS_MANAGER.set(Arc::new(instance.clone()));
        instance
    }

    pub fn global() -> Option<Arc<Self>> {
        GLOBAL_STATS_MANAGER.get().cloned()
    }

    pub fn update_config(&self, new_config: Config) {
        self.config.store(Arc::new(new_config));
        // Notify subscribers (e.g. Router) to reload
        let _ = self.config_event_tx.send(ConfigEvent::FullReload);
    }

    pub fn get_counter(&self, name: &str) -> Arc<AtomicU64> {
        self.counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone()
    }

    pub fn get_stats(&self, name: &str) -> u64 {
        self.counters
            .get(name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Record an IP address for a user or inbound
    pub fn record_online_ip(&self, key: &str, ip: String) {
        let now = Instant::now();
        let entry = OnlineIpEntry {
            ip: ip.clone(),
            last_seen: now,
        };

        self.online_ips
            .entry(key.to_string())
            .or_insert_with(Vec::new)
            .push(entry);

        // Cleanup old entries (older than 5 minutes)
        let timeout = Duration::from_secs(300);
        if let Some(mut ips) = self.online_ips.get_mut(key) {
            ips.retain(|e| now.duration_since(e.last_seen) < timeout);
            // Deduplicate by IP
            let mut seen = std::collections::HashSet::new();
            ips.retain(|e| seen.insert(e.ip.clone()));
        }
    }

    /// Get online IPs for a user/inbound with counts
    pub fn get_online_ips(&self, key: &str) -> HashMap<String, i64> {
        let timeout = Duration::from_secs(300);
        let now = Instant::now();

        if let Some(ips) = self.online_ips.get(key) {
            let mut result = HashMap::new();
            for entry in ips.iter() {
                if now.duration_since(entry.last_seen) < timeout {
                    *result.entry(entry.ip.clone()).or_insert(0) += 1;
                }
            }
            result
        } else {
            HashMap::new()
        }
    }

    /// Update metrics for a connection
    pub fn update_connection_metrics(&self, conn_id: &str, rtt: u64, cwnd: u64, dpi: DpiState) {
        let metrics = ConnectionMetrics {
            rtt_ms: rtt,
            cwnd_bytes: cwnd,
            dpi_state: dpi,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        let mut queue = self
            .connection_metrics
            .entry(conn_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(MAX_METRIC_SAMPLES));

        if queue.len() >= MAX_METRIC_SAMPLES {
            queue.pop_front();
        }
        queue.push_back(metrics);
    }

    /// Update historical metrics for a connection
    pub fn get_connection_metrics(&self, conn_id: &str) -> Vec<ConnectionMetrics> {
        self.connection_metrics
            .get(conn_id)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn update_outbound_monitor(&self, tag: &str, success: bool, latency: u64) {
        let mut stats = self
            .outbound_stats
            .entry(tag.to_string())
            .or_insert(MonitorStats {
                last_latency: 0,
                avg_latency: 0,
                jitter: 0,
                success_rate: 1.0,
                total_success: 0,
                total_fail: 0,
            });

        if success {
            if stats.avg_latency == 0 {
                stats.avg_latency = latency;
            } else {
                // EMA alpha = 0.2
                let diff = latency.abs_diff(stats.avg_latency);
                stats.jitter = (stats.jitter as f64 * 0.8 + diff as f64 * 0.2) as u64;
                stats.avg_latency = (stats.avg_latency as f64 * 0.8 + latency as f64 * 0.2) as u64;
            }
            stats.last_latency = latency;
        }

        // Success rate: simple EMA with alpha = 0.1
        let s = if success { 1.0 } else { 0.0 };
        stats.success_rate = stats.success_rate * 0.9 + s * 0.1;
    }
}
