// src/orchestrator/probe.rs
//! Transport Prober
//!
//! Races multiple transport connection attempts and selects the first
//! successful one, with configurable timeout and priority ordering.

use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Trait combining AsyncRead and AsyncWrite for trait objects.
pub trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncStream for T {}

/// Result of a transport probe.
#[derive(Debug)]
pub struct ProbeResult {
    /// Transport name
    pub name: String,
    /// Whether the probe succeeded
    pub success: bool,
    /// Latency to establish the connection
    pub latency: Duration,
    /// Error message if failed
    pub error: Option<String>,
}

/// Transport probe configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeConfig {
    /// Timeout per transport probe attempt
    #[serde(default = "default_probe_timeout_ms")]
    pub timeout_ms: u64,
    /// Number of parallel probes to run
    #[serde(default = "default_parallel_probes")]
    pub parallel_probes: usize,
    /// Minimum interval between probe cycles
    #[serde(default = "default_probe_interval_ms")]
    pub interval_ms: u64,
}

fn default_probe_timeout_ms() -> u64 {
    5000
}

fn default_parallel_probes() -> usize {
    3
}

fn default_probe_interval_ms() -> u64 {
    30000
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_probe_timeout_ms(),
            parallel_probes: default_parallel_probes(),
            interval_ms: default_probe_interval_ms(),
        }
    }
}

/// A function type that attempts to connect a transport and returns a boxed stream.
pub type TransportConnectFn = Box<
    dyn Fn() -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = io::Result<
                            Box<dyn AsyncStream + Unpin + Send>,
                        >,
                    > + Send,
            >,
        > + Send
        + Sync,
>;

/// Named transport with its connection factory.
pub struct NamedTransport {
    pub name: String,
    pub priority: u32,
    pub connect: TransportConnectFn,
}

/// Prober that races multiple transports and returns the winner.
pub struct TransportProber {
    config: ProbeConfig,
}

impl TransportProber {
    pub fn new(config: ProbeConfig) -> Self {
        Self { config }
    }

    /// Race all transports and return the first successful connection.
    pub async fn race(
        &self,
        transports: &[NamedTransport],
    ) -> Option<(
        String,
        Box<dyn AsyncStream + Unpin + Send>,
        Duration,
    )> {
        if transports.is_empty() {
            return None;
        }

        let probe_timeout = Duration::from_millis(self.config.timeout_ms);

        // Build futures for each transport
        let mut handles = Vec::with_capacity(transports.len());

        for transport in transports {
            let name = transport.name.clone();
            let fut = (transport.connect)();
            let timeout_dur = probe_timeout;

            handles.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                match timeout(timeout_dur, fut).await {
                    Ok(Ok(stream)) => {
                        let latency = start.elapsed();
                        info!("Transport '{}' connected in {:?}", name, latency);
                        Some((name, stream, latency))
                    }
                    Ok(Err(e)) => {
                        debug!("Transport '{}' failed: {}", name, e);
                        None
                    }
                    Err(_) => {
                        warn!("Transport '{}' timed out after {:?}", name, timeout_dur);
                        None
                    }
                }
            }));
        }

        // Wait for first success
        let results = futures::future::join_all(handles).await;

        // Sort by latency and return first success
        let mut successes: Vec<_> = results
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        successes.sort_by_key(|(_, _, latency)| *latency);
        successes.into_iter().next()
    }

    /// Probe a single transport and return the result.
    pub async fn probe_single(
        &self,
        transport: &NamedTransport,
    ) -> ProbeResult {
        let probe_timeout = Duration::from_millis(self.config.timeout_ms);
        let start = std::time::Instant::now();

        match timeout(probe_timeout, (transport.connect)()).await {
            Ok(Ok(_stream)) => ProbeResult {
                name: transport.name.clone(),
                success: true,
                latency: start.elapsed(),
                error: None,
            },
            Ok(Err(e)) => {
                let e: io::Error = e;
                ProbeResult {
                    name: transport.name.clone(),
                    success: false,
                    latency: start.elapsed(),
                    error: Some(e.to_string()),
                }
            },
            Err(_) => ProbeResult {
                name: transport.name.clone(),
                success: false,
                latency: start.elapsed(),
                error: Some("Timeout".to_string()),
            },
        }
    }
}
