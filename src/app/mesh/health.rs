// src/app/mesh/health.rs
//! Mesh Health Monitor for Auto-Failover
//!
//! Periodic task that analyzes connection metrics (RTT, packet loss, DPI status)
//! and triggers routing updates (failover) when quality degrades.

use crate::app::stats::{DpiState, StatsManager};
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

pub struct MeshHealthMonitor {
    stats_manager: Arc<StatsManager>,
    check_interval: Duration,
}

impl MeshHealthMonitor {
    pub fn new(stats_manager: Arc<StatsManager>, check_interval_secs: u64) -> Self {
        Self {
            stats_manager,
            check_interval: Duration::from_secs(check_interval_secs),
        }
    }

    pub async fn run(self) {
        let mut interval = interval(self.check_interval);
        info!(
            "MeshHealthMonitor started with interval {:?}",
            self.check_interval
        );

        loop {
            interval.tick().await;
            self.check_health().await;
        }
    }

    async fn check_health(&self) {
        debug!("Performing mesh health check...");

        // 1. Analyze Connection Metrics
        // We look for patterns of degradation: high RTT, Throttling, or Resets.
        let mut degraded_outbounds = Vec::new();

        for entry in self.stats_manager.connection_metrics.iter() {
            let conn_id = entry.key();
            let metrics = entry.value();

            if metrics.is_empty() {
                continue;
            }

            // check last 5 samples
            let recent_samples = metrics.iter().rev().take(5);
            let mut avg_rtt = 0;
            let mut count = 0;
            let mut throttle_detected = false;

            for m in recent_samples {
                avg_rtt += m.rtt_ms;
                count += 1;
                if matches!(m.dpi_state, DpiState::Throttled | DpiState::ResetDetected) {
                    throttle_detected = true;
                }
            }

            if count > 0 {
                avg_rtt /= count;
            }

            // Thresholds for failover:
            // RTT > 1000ms consistently OR DPI detected throttling/resets
            if avg_rtt > 1000 || throttle_detected {
                warn!(
                    "Connection {} is DEGRADED (RTT: {}ms, DPI: {:?})",
                    conn_id, avg_rtt, throttle_detected
                );
                degraded_outbounds.push(conn_id.clone());
            }
        }

        if !degraded_outbounds.is_empty() {
            self.trigger_failover(degraded_outbounds).await;
        }
    }

    async fn trigger_failover(&self, degraded_ids: Vec<String>) {
        info!(
            "Triggering failover for {} degraded paths",
            degraded_ids.len()
        );

        // Failover Logic:
        // In a real system, we would:
        // 1. Mark the specific outbound as "low priority" or "failed".
        // 2. Update the RoutingRule to prefer a different outbound tag.
        // 3. Hot-reload the config using engine.apply_routing_config.

        // For Phase 10 implementation, we simulate the config update.
        let current_config = self.stats_manager.config.load().clone();
        let mut new_config = (*current_config).clone();

        // Simple failover: if we have multiple outbounds, swap the order of the one matching the degraded path?
        // Or just notify the user/UI for now if it's an interactive failover.
        // Proactive failover:
        if let Some(outbounds) = new_config.outbounds.as_mut() {
            // Placeholder: implement actual priority shuffling here
            debug!("Mock failover: Shuffling outbounds priority");
            outbounds.rotate_left(1);
        }

        self.stats_manager.update_config(new_config);
        info!("Failover routing update applied.");
    }
}
