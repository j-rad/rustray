// rustray/src/jobs/watchdog.rs
//! Watchdog Job - Core Health Monitoring
//!
//! Monitors the health of the core engine and performs auto-restart
//! on failures with exponential backoff.
//!
//! Features:
//! - Health check polling
//! - Exponential backoff with jitter
//! - Maximum retry limits
//! - Integration with logging system

use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};

/// Health status of a monitored component
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Trait for components that can be monitored
pub trait Monitored: Send + Sync {
    /// Check if the component is healthy
    fn is_healthy(&self) -> bool;

    /// Attempt to restart the component
    fn restart(&self) -> Result<(), String>;

    /// Get the component name
    fn name(&self) -> &str;
}

/// Watchdog configuration
#[derive(Clone, Debug)]
pub struct WatchdogConfig {
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Maximum backoff time in seconds
    pub max_backoff_secs: u64,
    /// Maximum consecutive failures before giving up (0 = never give up)
    pub max_failures: u32,
    /// Initial delay before starting checks
    pub initial_delay_secs: u64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 1,
            max_backoff_secs: 30,
            max_failures: 0, // Never give up
            initial_delay_secs: 2,
        }
    }
}

/// Watchdog state
pub struct WatchdogState {
    failures: u32,
    last_healthy: Option<std::time::Instant>,
    status: HealthStatus,
}

/// Generic watchdog for any monitored component
pub struct Watchdog<T: Monitored> {
    component: Arc<T>,
    config: WatchdogConfig,
    state: Mutex<WatchdogState>,
}

impl<T: Monitored + 'static> Watchdog<T> {
    pub fn new(component: Arc<T>, config: WatchdogConfig) -> Self {
        Self {
            component,
            config,
            state: Mutex::new(WatchdogState {
                failures: 0,
                last_healthy: None,
                status: HealthStatus::Unknown,
            }),
        }
    }

    /// Start the watchdog
    pub async fn start(self: Arc<Self>) {
        let name = self.component.name().to_string();
        info!("Starting watchdog for '{}'", name);

        // Initial delay
        sleep(Duration::from_secs(self.config.initial_delay_secs)).await;

        let mut check_interval = interval(Duration::from_secs(self.config.check_interval_secs));
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            check_interval.tick().await;
            self.check_and_restart().await;
        }
    }

    async fn check_and_restart(&self) {
        let is_healthy = self.component.is_healthy();
        let mut state = self.state.lock().await;

        if is_healthy {
            if state.status == HealthStatus::Unhealthy {
                info!("'{}' recovered and is now healthy", self.component.name());
            }
            state.status = HealthStatus::Healthy;
            state.last_healthy = Some(std::time::Instant::now());
            state.failures = 0;
            return;
        }

        // Component is unhealthy
        state.failures += 1;
        state.status = HealthStatus::Unhealthy;

        warn!(
            "'{}' is not running. Failure count: {}. Attempting restart...",
            self.component.name(),
            state.failures
        );

        // Check max failures
        if self.config.max_failures > 0 && state.failures > self.config.max_failures {
            error!(
                "'{}' exceeded maximum failures ({}). Giving up.",
                self.component.name(),
                self.config.max_failures
            );
            return;
        }

        // Calculate backoff with jitter
        let backoff = self.calculate_backoff(state.failures);
        drop(state); // Release lock before sleeping

        warn!(
            "Backoff: waiting {:?} before restart attempt #{}",
            backoff,
            self.state.lock().await.failures
        );
        sleep(backoff).await;

        // Attempt restart
        match self.component.restart() {
            Ok(()) => {
                info!("Successfully restarted '{}'", self.component.name());
                // Note: we don't reset failures here - let the next health check confirm
            }
            Err(e) => {
                error!("Failed to restart '{}': {}", self.component.name(), e);
            }
        }
    }

    fn calculate_backoff(&self, failures: u32) -> Duration {
        // Exponential backoff: 2^min(failures, 6) seconds
        let expo = 1u64
            .checked_shl(std::cmp::min(failures, 6) as u32)
            .unwrap_or(self.config.max_backoff_secs);
        let backoff_secs = std::cmp::min(self.config.max_backoff_secs, expo);

        // Add jitter: 0-1000ms
        let jitter_ms = rand::thread_rng().gen_range(0..1000);

        Duration::from_secs(backoff_secs) + Duration::from_millis(jitter_ms)
    }

    /// Get current status
    pub async fn status(&self) -> HealthStatus {
        self.state.lock().await.status
    }

    /// Get failure count
    pub async fn failure_count(&self) -> u32 {
        self.state.lock().await.failures
    }
}

// ============================================================================
// Engine Adapter for Watchdog
// ============================================================================

use crate::ffi::EngineManager;

/// Adapter to make EngineManager work with the watchdog
pub struct EngineMonitor {
    engine: Arc<EngineManager>,
}

impl EngineMonitor {
    pub fn new(engine: Arc<EngineManager>) -> Self {
        Self { engine }
    }
}

impl Monitored for EngineMonitor {
    fn is_healthy(&self) -> bool {
        // Check engine state by examining the stats JSON
        let stats = self.engine.get_stats_json();
        // If we get valid JSON with connection_state > 0, engine is running
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stats) {
            parsed
                .get("connection_state")
                .and_then(|v| v.as_u64())
                .map(|state| state > 0)
                .unwrap_or(false)
        } else {
            false
        }
    }

    fn restart(&self) -> Result<(), String> {
        // Note: In production, config should be stored and used for restart
        Err("Engine restart requires stored configuration".to_string())
    }

    fn name(&self) -> &str {
        "RustrayEngine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockComponent {
        healthy: std::sync::atomic::AtomicBool,
        name: String,
    }

    impl MockComponent {
        fn new(name: &str, healthy: bool) -> Self {
            Self {
                healthy: std::sync::atomic::AtomicBool::new(healthy),
                name: name.to_string(),
            }
        }

        fn set_healthy(&self, healthy: bool) {
            self.healthy
                .store(healthy, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Monitored for MockComponent {
        fn is_healthy(&self) -> bool {
            self.healthy.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn restart(&self) -> Result<(), String> {
            self.set_healthy(true);
            Ok(())
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_backoff_calculation() {
        let component = Arc::new(MockComponent::new("test", true));
        let watchdog = Watchdog::new(component, WatchdogConfig::default());

        let backoff1 = watchdog.calculate_backoff(1);
        let backoff2 = watchdog.calculate_backoff(2);
        let backoff3 = watchdog.calculate_backoff(3);

        // Verify exponential growth (ignoring jitter)
        assert!(backoff1.as_secs() >= 2);
        assert!(backoff2.as_secs() >= 4);
        assert!(backoff3.as_secs() >= 8);
    }
}
