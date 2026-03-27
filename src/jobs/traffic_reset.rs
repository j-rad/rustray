// rustray/src/jobs/traffic_reset.rs
//! Traffic Reset Job
//!
//! Periodically resets user traffic counters based on configurable schedules.
//! Supports monthly, weekly, and custom interval resets.

use crate::jobs::billing::TrafficStore;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::info;

/// Reset schedule configuration
#[derive(Clone, Debug)]
#[derive(Default)]
pub enum ResetSchedule {
    /// Reset on the first of each month
    #[default]
    Monthly,
    /// Reset every N days
    Days(u32),
    /// Reset every N hours
    Hours(u32),
    /// Never auto-reset
    Never,
}


/// Traffic reset job configuration
#[derive(Clone, Debug)]
pub struct TrafficResetConfig {
    /// Reset schedule
    pub schedule: ResetSchedule,
    /// Check interval for monthly resets
    pub check_interval_secs: u64,
}

impl Default for TrafficResetConfig {
    fn default() -> Self {
        Self {
            schedule: ResetSchedule::Monthly,
            check_interval_secs: 3600, // Check hourly for monthly resets
        }
    }
}

/// Traffic reset job
pub struct TrafficResetJob {
    traffic_store: Arc<TrafficStore>,
    config: TrafficResetConfig,
    db: Option<Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>>,
}

impl TrafficResetJob {
    pub fn new(
        traffic_store: Arc<TrafficStore>,
        config: TrafficResetConfig,
        db: Option<Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>>,
    ) -> Self {
        Self {
            traffic_store,
            config,
            db,
        }
    }

    /// Start the traffic reset job
    pub async fn start(self: Arc<Self>) {
        match self.config.schedule {
            ResetSchedule::Never => {
                info!("Traffic reset is disabled");
            }
            ResetSchedule::Days(days) => {
                self.run_interval(Duration::from_secs(days as u64 * 86400))
                    .await;
            }
            ResetSchedule::Hours(hours) => {
                self.run_interval(Duration::from_secs(hours as u64 * 3600))
                    .await;
            }
            ResetSchedule::Monthly => {
                self.run_monthly().await;
            }
        }
    }

    async fn run_interval(self: Arc<Self>, reset_interval: Duration) {
        let mut timer = interval(reset_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!("Traffic reset job started (interval: {:?})", reset_interval);

        // Skip the first immediate tick
        timer.tick().await;

        loop {
            timer.tick().await;
            self.reset_all_traffic().await;
        }
    }

    async fn run_monthly(self: Arc<Self>) {
        let mut check_timer = interval(Duration::from_secs(self.config.check_interval_secs));
        check_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!("Traffic reset job started (monthly schedule)");

        let mut last_reset_day = 0u64;

        loop {
            check_timer.tick().await;

            // Get current time
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Simple day-of-month approximation
            let day_of_month = ((now / 86400) % 31) + 1;

            if day_of_month == 1 && last_reset_day != 1 {
                info!("Monthly traffic reset triggered");
                self.reset_all_traffic().await;
                last_reset_day = 1;
            } else if day_of_month != 1 {
                last_reset_day = day_of_month;
            }
        }
    }

    async fn reset_all_traffic(&self) {
        info!("Resetting all user traffic counters");

        let counters = self.traffic_store.all_counters();
        for counter in counters {
            self.traffic_store
                .reset_traffic(&counter.user_id, &counter.inbound_tag);
        }

        // Persist to database
        if let Some(db) = &self.db
            && let Err(e) = self.persist_reset(db).await {
                tracing::error!("Failed to persist traffic reset: {}", e);
            }

        info!("Traffic reset complete");
    }

    async fn persist_reset(
        &self,
        db: &surrealdb::Surreal<surrealdb::engine::local::Db>,
    ) -> Result<(), surrealdb::Error> {
        // Reset all client traffic in all inbounds
        db.query("UPDATE inbound SET settings.clients[*].up = 0, settings.clients[*].down = 0")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::billing::TrafficStore;

    #[test]
    fn test_reset_schedule_default() {
        let schedule = ResetSchedule::default();
        assert!(matches!(schedule, ResetSchedule::Monthly));
    }

    #[test]
    fn test_traffic_reset() {
        let store = Arc::new(TrafficStore::new());
        store.set_limits("user1", "inbound1", 1_000_000_000, 0);
        store.add_traffic("user1", "inbound1", 1000, 2000);

        // Verify traffic added
        let counter = store.get_or_create("user1", "inbound1");
        assert_eq!(counter.upload_bytes, 1000);

        // Reset
        store.reset_traffic("user1", "inbound1");

        // Verify reset
        let counter = store.get_or_create("user1", "inbound1");
        assert_eq!(counter.upload_bytes, 0);
        assert_eq!(counter.download_bytes, 0);
    }
}
