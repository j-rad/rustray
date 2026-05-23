// src/ui/heatmap.rs
//! Fleet Intelligence ISP Heatmap
//!
//! Processes `ProbeResult` telemetry streamed from every node in the fleet
//! and produces:
//!  - Per-ISP health classifications (Green / Yellow / Red)
//!  - World-map retransmission ratio overlays for localised throttling detection
//!
//! The data structures produced here are serialised to JSON and consumed
//! directly by the War Room WebSocket endpoint in `rr-ui`.

use crate::orchestrator::probe::ProbeResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Colour-coded ISP health status, ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IspHealth {
    /// Latency within nominal band, loss < 1 %.
    Green,
    /// Elevated latency or loss between 1–5 %; monitor closely.
    Yellow,
    /// Persistent loss > 5 % or all probes timed out; rotate signatures.
    Red,
    /// Not enough probe samples to determine status yet.
    Unknown,
}

/// Aggregate telemetry for a single ISP provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspTelemetry {
    /// Provider name as reported by ASN look-up (e.g. "Irancell", "MCI").
    pub provider: String,
    /// Canonical ASN string, e.g. "AS43754".
    pub asn: String,
    /// Colour-coded health bucket.
    pub health: IspHealth,
    /// Mean latency across all successful probes in the last window.
    pub mean_latency_ms: f64,
    /// Fraction of probes that timed out or returned an error (0.0 – 1.0).
    pub loss_ratio: f64,
    /// Total number of probes observed in the current window.
    pub sample_count: u64,
    /// Unix timestamp (seconds) of the last update.
    pub last_updated_secs: u64,
    /// SHA-256 of this record — used for consistency verification.
    pub record_hash: String,
}

impl IspTelemetry {
    fn compute_hash(&self) -> String {
        let canonical = format!(
            "{}:{}:{:.6}:{:.6}:{}",
            self.provider, self.asn, self.mean_latency_ms, self.loss_ratio, self.last_updated_secs
        );
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        hex::encode(h.finalize())
    }
}

/// A single geographic node report — feeds the world-map overlay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMapPoint {
    /// Unique node identifier.
    pub node_id: String,
    /// ISO-3166-1 alpha-2 country code.
    pub country_code: String,
    /// Approximate latitude (degrees).
    pub lat: f64,
    /// Approximate longitude (degrees).
    pub lon: f64,
    /// Provider / ISP name.
    pub provider: String,
    /// TCP retransmission ratio measured at this node (0.0 – 1.0).
    pub retransmit_ratio: f64,
    /// Health bucket derived from retransmit ratio.
    pub health: IspHealth,
}

/// Full heatmap snapshot — serialised to the War Room WebSocket every tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapSnapshot {
    /// Unix timestamp of this snapshot.
    pub timestamp_secs: u64,
    /// Per-ISP aggregate telemetry.
    pub isp_telemetry: Vec<IspTelemetry>,
    /// Per-node geographic points for the world-map overlay.
    pub map_points: Vec<NodeMapPoint>,
    /// SHA-256 of all `record_hash` fields concatenated — used by `verify_consistency`.
    pub aggregate_hash: String,
}

// ---------------------------------------------------------------------------
// Raw probe sample ingestion
// ---------------------------------------------------------------------------

/// Raw probe sample emitted by transport workers and fed into the heatmap engine.
#[derive(Debug, Clone)]
pub struct ProbeSample {
    /// Node that performed the probe.
    pub node_id: String,
    pub country_code: String,
    pub lat: f64,
    pub lon: f64,
    /// Provider name (e.g. "Irancell").
    pub provider: String,
    /// ASN string (e.g. "AS43754").
    pub asn: String,
    /// Underlying probe result.
    pub result: ProbeResult,
    /// TCP retransmit ratio sampled concurrently with the probe.
    pub retransmit_ratio: f64,
}

// ---------------------------------------------------------------------------
// Accumulator (rolling window per provider)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct ProviderAccumulator {
    total_latency_ms: f64,
    success_count: u64,
    failure_count: u64,
    retransmit_sum: f64,
    last_updated_secs: u64,
}

impl ProviderAccumulator {
    fn ingest(&mut self, sample: &ProbeSample) {
        if sample.result.success {
            self.total_latency_ms += sample.result.latency.as_secs_f64() * 1000.0;
            self.success_count += 1;
        } else {
            self.failure_count += 1;
        }
        self.retransmit_sum += sample.retransmit_ratio;
        self.last_updated_secs = unix_secs();
    }

    fn sample_count(&self) -> u64 {
        self.success_count + self.failure_count
    }

    fn mean_latency_ms(&self) -> f64 {
        if self.success_count == 0 {
            0.0
        } else {
            self.total_latency_ms / self.success_count as f64
        }
    }

    fn loss_ratio(&self) -> f64 {
        let total = self.sample_count();
        if total == 0 {
            return 0.0;
        }
        self.failure_count as f64 / total as f64
    }

    fn health(&self) -> IspHealth {
        if self.sample_count() < 3 {
            return IspHealth::Unknown;
        }
        let loss = self.loss_ratio();
        let latency = self.mean_latency_ms();
        if loss > 0.05 || latency > 800.0 {
            IspHealth::Red
        } else if loss > 0.01 || latency > 400.0 {
            IspHealth::Yellow
        } else {
            IspHealth::Green
        }
    }
}

// ---------------------------------------------------------------------------
// HeatmapEngine — the main public API
// ---------------------------------------------------------------------------

/// Central heatmap engine.
///
/// Accepts `ProbeSample` events from any number of concurrent node reporters
/// and publishes a fresh `HeatmapSnapshot` every `tick_interval`.
pub struct HeatmapEngine {
    /// Per-provider rolling accumulators.
    accumulators: Arc<RwLock<HashMap<String, (String, ProviderAccumulator)>>>,
    /// Per-node latest points for the map overlay.
    node_points: Arc<RwLock<HashMap<String, NodeMapPoint>>>,
    /// Broadcast channel — War Room WebSocket subscribes here.
    snapshot_tx: broadcast::Sender<HeatmapSnapshot>,
    tick_interval: Duration,
}

impl HeatmapEngine {
    /// Create a new engine with the given snapshot publish interval.
    pub fn new(tick_interval: Duration) -> Self {
        let (snapshot_tx, _) = broadcast::channel(64);
        Self {
            accumulators: Arc::new(RwLock::new(HashMap::new())),
            node_points: Arc::new(RwLock::new(HashMap::new())),
            snapshot_tx,
            tick_interval,
        }
    }

    /// Subscribe to real-time snapshot events (used by the War Room WS handler).
    pub fn subscribe(&self) -> broadcast::Receiver<HeatmapSnapshot> {
        self.snapshot_tx.subscribe()
    }

    /// Ingest a raw probe sample from a fleet node.
    pub async fn ingest(&self, sample: ProbeSample) {
        debug!(
            "HeatmapEngine: sample from node={} provider={} success={} latency={:?} retx={}",
            sample.node_id,
            sample.provider,
            sample.result.success,
            sample.result.latency,
            sample.retransmit_ratio
        );

        // Update provider accumulator.
        {
            let mut acc = self.accumulators.write().await;
            let entry = acc
                .entry(sample.asn.clone())
                .or_insert_with(|| (sample.provider.clone(), ProviderAccumulator::default()));
            entry.1.ingest(&sample);
        }

        // Update node map point.
        {
            let health = node_health_from_retransmit(sample.retransmit_ratio);
            let mut points = self.node_points.write().await;
            points.insert(
                sample.node_id.clone(),
                NodeMapPoint {
                    node_id: sample.node_id,
                    country_code: sample.country_code,
                    lat: sample.lat,
                    lon: sample.lon,
                    provider: sample.provider,
                    retransmit_ratio: sample.retransmit_ratio,
                    health,
                },
            );
        }
    }

    /// Spawn the background publish task.  Call once at startup.
    pub fn spawn_publisher(self: Arc<Self>) {
        let engine = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(engine.tick_interval);
            loop {
                ticker.tick().await;
                let snapshot = engine.build_snapshot().await;
                let sub_count = engine.snapshot_tx.receiver_count();
                if sub_count > 0 {
                    let _ = engine.snapshot_tx.send(snapshot);
                }
            }
        });
    }

    /// Analyze per-ISP probe results and return colour-coded telemetry.
    ///
    /// This is the `analyze_isp_health` function from the spec, exposed as
    /// a standalone method so the War Room can poll it on-demand.
    pub async fn analyze_isp_health(&self) -> Vec<IspTelemetry> {
        let acc = self.accumulators.read().await;
        let mut out = Vec::with_capacity(acc.len());
        for (asn, (provider, a)) in acc.iter() {
            let health = a.health();
            let mean_latency_ms = a.mean_latency_ms();
            let loss_ratio = a.loss_ratio();
            let last_updated_secs = a.last_updated_secs;

            info!(
                "ISP Health: {} ({}) — {:?}, latency={:.1}ms, loss={:.2}%",
                provider,
                asn,
                health,
                mean_latency_ms,
                loss_ratio * 100.0
            );

            let mut tel = IspTelemetry {
                provider: provider.clone(),
                asn: asn.clone(),
                health,
                mean_latency_ms,
                loss_ratio,
                sample_count: a.sample_count(),
                last_updated_secs,
                record_hash: String::new(),
            };
            tel.record_hash = tel.compute_hash();
            out.push(tel);
        }
        // Sort by health severity (Red first), then by provider name.
        out.sort_by(|a, b| {
            health_ord(a.health)
                .cmp(&health_ord(b.health))
                .then_with(|| a.provider.cmp(&b.provider))
        });
        out
    }

    /// Build world-map overlay data showing retransmission ratios per node.
    ///
    /// This is the `visualize_loss_ratios` function from the spec.
    pub async fn visualize_loss_ratios(&self) -> Vec<NodeMapPoint> {
        let points = self.node_points.read().await;
        let mut out: Vec<NodeMapPoint> = points.values().cloned().collect();
        // Sort by retransmit ratio descending — worst nodes first.
        out.sort_by(|a, b| {
            b.retransmit_ratio
                .partial_cmp(&a.retransmit_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    async fn build_snapshot(&self) -> HeatmapSnapshot {
        let isp_telemetry = self.analyze_isp_health().await;
        let map_points = self.visualize_loss_ratios().await;

        // Aggregate hash = SHA-256 of all individual record hashes.
        let mut agg_hasher = Sha256::new();
        for tel in &isp_telemetry {
            agg_hasher.update(tel.record_hash.as_bytes());
        }
        let aggregate_hash = hex::encode(agg_hasher.finalize());

        HeatmapSnapshot {
            timestamp_secs: unix_secs(),
            isp_telemetry,
            map_points,
            aggregate_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn health_ord(h: IspHealth) -> u8 {
    match h {
        IspHealth::Red => 0,
        IspHealth::Yellow => 1,
        IspHealth::Unknown => 2,
        IspHealth::Green => 3,
    }
}

fn node_health_from_retransmit(ratio: f64) -> IspHealth {
    if ratio > 0.05 {
        IspHealth::Red
    } else if ratio > 0.01 {
        IspHealth::Yellow
    } else {
        IspHealth::Green
    }
}

// ---------------------------------------------------------------------------
// Dioxus UI Components
// ---------------------------------------------------------------------------

#[cfg(feature = "dioxus")]
use dioxus::prelude::*;

#[cfg(feature = "dioxus")]
#[component]
pub fn HeatmapCanvas() -> Element {
    rsx! {
        div {
            class: "heatmap-container w-full h-full relative font-sans",
            canvas {
                id: "heatmap-canvas",
                class: "w-full h-[600px] border-2 border-slate-700 rounded shadow-xl bg-slate-900",
            }
            div {
                class: "absolute top-4 left-4 p-4 bg-slate-900/80 backdrop-blur-md text-white rounded border border-slate-600 shadow-lg",
                h2 { class: "text-xl font-bold mb-2", "Global ISP Health" }
                ul {
                    class: "space-y-1 text-sm",
                    li { span { class: "inline-block w-3 h-3 rounded-full bg-green-500 mr-2" } "Nominal" }
                    li { span { class: "inline-block w-3 h-3 rounded-full bg-yellow-500 mr-2" } "Elevated Latency/Loss" }
                    li { span { class: "inline-block w-3 h-3 rounded-full bg-red-500 mr-2" } "Critical Degradation" }
                }
            }
        }
    }
}
