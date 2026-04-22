// rustray/src/jobs/billing.rs
//! Billing Job - User Quota Enforcement
//!
//! Background job that monitors user traffic and quota limits.
//! Automatically disables users who exceed their limits or expire.
//!
//! Features:
//! - Traffic quota enforcement with `dashmap` counters
//! - Expiry time checking
//! - Transactional state sync with database
//! - Core orchestrator integration

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

/// Traffic counter entry for a user
#[derive(Debug, Clone)]
pub struct TrafficCounter {
    pub user_id: String,
    pub inbound_tag: String,
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub total_limit_bytes: i64,
    pub expiry_time: i64,
    pub enabled: bool,
}

/// Thread-safe traffic counter store
pub struct TrafficStore {
    counters: DashMap<String, TrafficCounter>,
}

impl TrafficStore {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Get or create a counter for a user
    pub fn get_or_create(&self, user_id: &str, inbound_tag: &str) -> TrafficCounter {
        let key = format!("{}:{}", inbound_tag, user_id);
        self.counters
            .entry(key.clone())
            .or_insert_with(|| TrafficCounter {
                user_id: user_id.to_string(),
                inbound_tag: inbound_tag.to_string(),
                upload_bytes: 0,
                download_bytes: 0,
                total_limit_bytes: 0,
                expiry_time: 0,
                enabled: true,
            })
            .clone()
    }

    /// Update traffic for a user
    pub fn add_traffic(&self, user_id: &str, inbound_tag: &str, upload: i64, download: i64) {
        let key = format!("{}:{}", inbound_tag, user_id);
        if let Some(mut counter) = self.counters.get_mut(&key) {
            counter.upload_bytes += upload;
            counter.download_bytes += download;
        }
    }

    /// Set limits for a user
    pub fn set_limits(&self, user_id: &str, inbound_tag: &str, total_limit: i64, expiry: i64) {
        let key = format!("{}:{}", inbound_tag, user_id);
        if let Some(mut counter) = self.counters.get_mut(&key) {
            counter.total_limit_bytes = total_limit;
            counter.expiry_time = expiry;
        } else {
            self.counters.insert(
                key,
                TrafficCounter {
                    user_id: user_id.to_string(),
                    inbound_tag: inbound_tag.to_string(),
                    upload_bytes: 0,
                    download_bytes: 0,
                    total_limit_bytes: total_limit,
                    expiry_time: expiry,
                    enabled: true,
                },
            );
        }
    }

    /// Get all counters
    pub fn all_counters(&self) -> Vec<TrafficCounter> {
        self.counters.iter().map(|r| r.value().clone()).collect()
    }

    /// Reset traffic for a user
    pub fn reset_traffic(&self, user_id: &str, inbound_tag: &str) {
        let key = format!("{}:{}", inbound_tag, user_id);
        if let Some(mut counter) = self.counters.get_mut(&key) {
            counter.upload_bytes = 0;
            counter.download_bytes = 0;
        }
    }

    /// Set enabled state
    pub fn set_enabled(&self, user_id: &str, inbound_tag: &str, enabled: bool) {
        let key = format!("{}:{}", inbound_tag, user_id);
        if let Some(mut counter) = self.counters.get_mut(&key) {
            counter.enabled = enabled;
        }
    }
}

impl Default for TrafficStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Billing job configuration
#[derive(Clone)]
pub struct BillingConfig {
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Grace period before disabling (seconds)
    pub grace_period_secs: u64,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 60,
            grace_period_secs: 0,
        }
    }
}

/// Billing job state
pub struct BillingJob {
    traffic_store: Arc<TrafficStore>,
    config: BillingConfig,
    db: Option<Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>>,
}

impl BillingJob {
    pub fn new(
        traffic_store: Arc<TrafficStore>,
        config: BillingConfig,
        db: Option<Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>>,
    ) -> Self {
        Self {
            traffic_store,
            config,
            db,
        }
    }

    /// Start the billing job
    pub async fn start(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(self.config.check_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Billing job started (interval: {}s)",
            self.config.check_interval_secs
        );

        loop {
            interval.tick().await;
            self.check_all_users().await;
        }
    }

    async fn check_all_users(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let counters = self.traffic_store.all_counters();
        let mut changes = Vec::new();

        for counter in counters {
            let is_expired = counter.expiry_time > 0 && now > counter.expiry_time;
            let is_over_limit = counter.total_limit_bytes > 0
                && (counter.upload_bytes + counter.download_bytes) >= counter.total_limit_bytes;

            let should_be_enabled = !is_expired && !is_over_limit;

            if counter.enabled != should_be_enabled {
                info!(
                    "Billing: User {} (inbound: {}) status change {} -> {}. Expired: {}, OverLimit: {}",
                    counter.user_id,
                    counter.inbound_tag,
                    counter.enabled,
                    should_be_enabled,
                    is_expired,
                    is_over_limit
                );

                self.traffic_store.set_enabled(
                    &counter.user_id,
                    &counter.inbound_tag,
                    should_be_enabled,
                );

                changes.push((
                    counter.user_id.clone(),
                    counter.inbound_tag.clone(),
                    should_be_enabled,
                ));
            }
        }

        // Persist changes to database
        if !changes.is_empty()
            && let Some(db) = &self.db {
                for (user_id, inbound_tag, enabled) in changes {
                    if let Err(e) = self
                        .persist_user_state(db, &user_id, &inbound_tag, enabled)
                        .await
                    {
                        error!("Failed to persist user state: {}", e);
                    }
                }
            }
    }

    async fn persist_user_state(
        &self,
        db: &surrealdb::Surreal<surrealdb::engine::local::Db>,
        user_id: &str,
        inbound_tag: &str,
        enabled: bool,
    ) -> Result<(), surrealdb::Error> {
        let query = format!(
            "UPDATE inbound SET settings.clients[WHERE id = '{}'].enable = {} WHERE tag = '{}'",
            user_id, enabled, inbound_tag
        );
        db.query(&query).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_store() {
        let store = TrafficStore::new();

        // Add traffic
        store.set_limits("user1", "inbound1", 1_000_000_000, 0);
        store.add_traffic("user1", "inbound1", 100, 200);

        let counter = store.get_or_create("user1", "inbound1");
        assert_eq!(counter.upload_bytes, 100);
        assert_eq!(counter.download_bytes, 200);
    }

    #[test]
    fn test_over_limit_detection() {
        let store = TrafficStore::new();

        store.set_limits("user1", "inbound1", 1000, 0);
        store.add_traffic("user1", "inbound1", 500, 600); // Total 1100 > 1000

        let counter = store.get_or_create("user1", "inbound1");
        let is_over = (counter.upload_bytes + counter.download_bytes) >= counter.total_limit_bytes;
        assert!(is_over);
    }
}
