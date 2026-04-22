// src/orchestrator/manager.rs
//! Orchestrator Manager
//!
//! Manages the active transport, monitors health, and performs hot-swap
//! failover when the active transport degrades. Buffers up to 5MB of
//! in-flight data during transitions to prevent data loss.

use crate::orchestrator::probe::{AsyncStream, NamedTransport, ProbeConfig, TransportProber};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use tracing::{debug, info, warn};

/// Maximum buffer size during failover (5 MiB)
const FAILOVER_BUFFER_SIZE: usize = 5 * 1024 * 1024;

/// Orchestrator configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrchestratorConfig {
    /// Probe configuration
    #[serde(default)]
    pub probe: ProbeConfig,
    /// Health check interval in milliseconds
    #[serde(default = "default_health_interval_ms")]
    pub health_interval_ms: u64,
    /// Number of consecutive failures before triggering failover
    #[serde(default = "default_failover_threshold")]
    pub failover_threshold: u32,
}

fn default_health_interval_ms() -> u64 {
    10000
}

fn default_failover_threshold() -> u32 {
    3
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            probe: ProbeConfig::default(),
            health_interval_ms: default_health_interval_ms(),
            failover_threshold: default_failover_threshold(),
        }
    }
}

/// Active transport state.
struct ActiveTransport {
    name: String,
    /// Active connection
    stream: Box<dyn AsyncStream + Unpin + Send>,
    connected_at: Instant,
    /// Last fallback initiationt,
    consecutive_failures: u32,
}

/// The Orchestrator manages transport lifecycle and failover.
pub struct Orchestrator {
    config: OrchestratorConfig,
    active: Arc<Mutex<Option<ActiveTransport>>>,
    /// Buffer for data during failover
    failover_buf: Arc<Mutex<VecDeque<u8>>>,
    /// Notify when a new transport is available
    transport_ready: Arc<Notify>,
    prober: TransportProber,
}

impl Orchestrator {
    pub fn new(config: OrchestratorConfig) -> Self {
        let prober = TransportProber::new(config.probe.clone());
        Self {
            config,
            active: Arc::new(Mutex::new(None)),
            failover_buf: Arc::new(Mutex::new(VecDeque::with_capacity(FAILOVER_BUFFER_SIZE))),
            transport_ready: Arc::new(Notify::new()),
            prober,
        }
    }

    /// Initialize by racing all transports and selecting the best one.
    pub async fn initialize(
        &self,
        transports: &[NamedTransport],
    ) -> io::Result<()> {
        let result: (String, Box<dyn AsyncStream + Unpin + Send>, Duration) = self
            .prober
            .race(transports)
            .await
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionRefused, "All transports failed")
            })?;

        let (name, stream, latency) = result;
        info!("Orchestrator: selected '{}' (latency: {:?})", name, latency);

        let mut active = self.active.lock().await;
        *active = Some(ActiveTransport {
            name,
            stream,
            connected_at: Instant::now(),
            consecutive_failures: 0,
        });

        self.transport_ready.notify_waiters();
        Ok(())
    }

    /// Perform a hot-swap failover to a new transport.
    pub async fn failover(
        &self,
        transports: &[NamedTransport],
    ) -> io::Result<()> {
        warn!("Orchestrator: initiating failover...");

        // 1. Race new transports
        let result: (String, Box<dyn AsyncStream + Unpin + Send>, Duration) = self
            .prober
            .race(transports)
            .await
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionRefused, "All failover transports failed")
            })?;

        let (name, stream, latency) = result;
        info!(
            "Orchestrator: failover to '{}' (latency: {:?})",
            name, latency
        );

        // 2. Swap the active transport
        let mut active = self.active.lock().await;
        *active = Some(ActiveTransport {
            name,
            stream,
            connected_at: Instant::now(),
            consecutive_failures: 0,
        });

        // 3. Drain failover buffer into new transport
        let mut buf = self.failover_buf.lock().await;
        if !buf.is_empty() {
            let drained: Vec<u8> = buf.drain(..).collect();
            if let Some(ref mut transport) = *active {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = transport.stream.write_all(&drained).await {
                    warn!("Orchestrator: failed to drain buffer to new transport: {}", e);
                } else {
                    debug!(
                        "Orchestrator: drained {} bytes to new transport",
                        drained.len()
                    );
                }
            }
        }

        self.transport_ready.notify_waiters();
        Ok(())
    }

    /// Record a transport-level write failure and trigger failover if threshold met.
    pub async fn record_failure(&self) -> bool {
        let mut active = self.active.lock().await;
        if let Some(ref mut transport) = *active {
            transport.consecutive_failures += 1;
            if transport.consecutive_failures >= self.config.failover_threshold {
                warn!(
                    "Orchestrator: transport '{}' exceeded failure threshold ({})",
                    transport.name, transport.consecutive_failures
                );
                return true; // Caller should trigger failover
            }
        }
        false
    }

    /// Buffer data during a failover transition.
    pub async fn buffer_data(&self, data: &[u8]) -> io::Result<()> {
        let mut buf = self.failover_buf.lock().await;
        if buf.len() + data.len() > FAILOVER_BUFFER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "Failover buffer full",
            ));
        }
        buf.extend(data);
        Ok(())
    }

    /// Get current active transport name.
    pub async fn active_transport_name(&self) -> Option<String> {
        let active = self.active.lock().await;
        active.as_ref().map(|t| t.name.clone())
    }
}
