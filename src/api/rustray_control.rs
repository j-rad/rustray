// src/api/rustray_control.rs
//! Intelligence-Driven gRPC Control Bus
//!
//! Implements a bi-directional gRPC streaming control plane that allows
//! the War Room UI to push zero-downtime delta config updates, broadcast
//! emergency ghost mode switches, and verify node consistency — all without
//! triggering a service restart.

use crate::config::Config;
use json_patch::patch;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};

use crate::core::registry::GLOBAL_REGISTRY;

use crate::api::rustray::api::control::{
    ConsistencyRequest, ConsistencyResponse, DeltaRequest, DeltaResponse, EmergencyRequest,
    EmergencyResponse,
    control_service_server::{ControlService, ControlServiceServer},
};

/// Maximum number of delta events buffered for late-joining subscribers.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Emergency transport mode, mirroring the proto enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostMode {
    Normal = 0,
    WsCdn = 1,
    DnsBeacon = 2,
}

impl TryFrom<i32> for GhostMode {
    type Error = Status;
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Normal),
            1 => Ok(Self::WsCdn),
            2 => Ok(Self::DnsBeacon),
            _ => Err(Status::invalid_argument(format!(
                "Unknown ghost mode: {}",
                v
            ))),
        }
    }
}

/// Broadcasts the current ghost mode to all subscribed nodes.
#[derive(Clone)]
pub struct GhostModeBus {
    tx: broadcast::Sender<GhostMode>,
}

impl GhostModeBus {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self { tx }
    }

    /// Subscribe to ghost-mode transitions.
    pub fn subscribe(&self) -> broadcast::Receiver<GhostMode> {
        self.tx.subscribe()
    }

    fn broadcast(&self, mode: GhostMode) {
        // Ignore send errors — no subscribers is fine.
        let _ = self.tx.send(mode);
    }
}

/// Shared, hot-reloadable configuration store.
///
/// Guards the in-memory config behind an `RwLock` so concurrent readers
/// (transport workers, routing engine) see consistent state while a delta
/// patch is being applied.
#[derive(Clone)]
pub struct HotConfig {
    inner: Arc<RwLock<Config>>,
}

impl HotConfig {
    /// Initialise from an already-loaded `Config`.
    pub fn new(config: Config) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    /// Compute the canonical SHA-256 hash of the current serialised config.
    pub async fn sha256_hex(&self) -> String {
        let guard = self.inner.read().await;
        let json = serde_json::to_vec(&*guard).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json);
        hex::encode(hasher.finalize())
    }

    /// Read-lock for cheap, concurrent read access.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, Config> {
        self.inner.read().await
    }

    /// Apply a JSON-Patch (`application/json-patch+json`) to the live config.
    ///
    /// Returns the new SHA-256 hash on success, or an error string on failure.
    async fn apply_patch(&self, json_patch_str: &str) -> Result<String, String> {
        let patch_value: serde_json::Value = serde_json::from_str(json_patch_str)
            .map_err(|e| format!("Invalid JSON-Patch: {}", e))?;

        let patch_ops: json_patch::Patch = serde_json::from_value(patch_value)
            .map_err(|e| format!("Could not parse patch ops: {}", e))?;

        let mut guard = self.inner.write().await;
        let mut config_value = serde_json::to_value(&*guard)
            .map_err(|e| format!("Could not serialise config: {}", e))?;

        patch(&mut config_value, &patch_ops)
            .map_err(|e| format!("Patch application failed: {}", e))?;

        let new_config: Config = serde_json::from_value(config_value)
            .map_err(|e| format!("Patched config is invalid: {}", e))?;

        // Propagate to FeatureRegistry
        if let Some(inbounds) = &new_config.inbounds {
            for inbound in inbounds {
                if let Ok(inbound_val) = serde_json::to_value(inbound) {
                    let _ = GLOBAL_REGISTRY.create_inbound(&inbound.protocol, inbound_val);
                }
            }
        }
        if let Some(outbounds) = &new_config.outbounds {
            for outbound in outbounds {
                if let Ok(outbound_val) = serde_json::to_value(outbound) {
                    let _ = GLOBAL_REGISTRY.create_outbound(&outbound.protocol, outbound_val);
                }
            }
        }

        *guard = new_config;
        let json = serde_json::to_vec(&*guard).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json);
        Ok(hex::encode(hasher.finalize()))
    }
}

/// The gRPC ControlService implementation.
pub struct ControlBus {
    config: HotConfig,
    ghost_bus: GhostModeBus,
    /// Broadcast channel for delta-response echoes (for multi-node fan-out).
    delta_tx: broadcast::Sender<DeltaResponse>,
}

impl ControlBus {
    pub fn new(config: HotConfig) -> Self {
        let (delta_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            config,
            ghost_bus: GhostModeBus::new(),
            delta_tx,
        }
    }

    /// Returns a tonic `ControlServiceServer` wrapping this bus.
    pub fn into_server(self) -> ControlServiceServer<Self> {
        ControlServiceServer::new(self)
    }

    /// Subscribe to ghost mode events — used by transport workers.
    pub fn ghost_bus(&self) -> &GhostModeBus {
        &self.ghost_bus
    }

    /// Subscribe to the live delta broadcast.
    pub fn delta_subscriber(&self) -> broadcast::Receiver<DeltaResponse> {
        self.delta_tx.subscribe()
    }
}

#[tonic::async_trait]
impl ControlService for ControlBus {
    type PushDeltaUpdateStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<DeltaResponse, Status>> + Send>>;

    /// Bi-directional streaming RPC: receive JSON-Patch deltas from the UI
    /// and stream back per-patch results (including new config hash) to all
    /// connected subscribers.
    async fn push_delta_update(
        &self,
        request: Request<Streaming<DeltaRequest>>,
    ) -> Result<Response<Self::PushDeltaUpdateStream>, Status> {
        let mut inbound = request.into_inner();
        let config = self.config.clone();
        let delta_tx = self.delta_tx.clone();

        // Spawn the inbound reader so we can return the outbound stream immediately.
        tokio::spawn(async move {
            while let Some(msg) = match inbound.message().await {
                Ok(Some(m)) => Some(m),
                Ok(None) => {
                    info!("ControlBus: delta stream closed by peer");
                    None
                }
                Err(e) => {
                    warn!("ControlBus: delta stream error: {}", e);
                    None
                }
            } {
                let response = match config.apply_patch(&msg.json_patch).await {
                    Ok(hash) => {
                        info!("ControlBus: delta applied, config hash = {}", hash);
                        DeltaResponse {
                            success: true,
                            error: String::new(),
                            current_config_hash: hash,
                        }
                    }
                    Err(err) => {
                        error!("ControlBus: delta patch failed: {}", err);
                        DeltaResponse {
                            success: false,
                            error: err,
                            current_config_hash: String::new(),
                        }
                    }
                };
                // Fan-out to all subscribers; ignore if nobody is listening.
                let _ = delta_tx.send(response);
            }
        });

        let rx = self.delta_tx.subscribe();
        let stream = BroadcastStream::new(rx)
            .map(|res| res.map_err(|e| Status::internal(format!("Broadcast error: {}", e))));
        Ok(Response::new(Box::pin(stream)))
    }

    /// Unary RPC: broadcast an emergency ghost mode to all nodes.
    ///
    /// Nodes watching `GhostModeBus::subscribe()` will switch transports
    /// within one event-loop tick — no restart required.
    async fn broadcast_emergency_ghost(
        &self,
        request: Request<EmergencyRequest>,
    ) -> Result<Response<EmergencyResponse>, Status> {
        let req = request.into_inner();
        let mode = GhostMode::try_from(req.mode)?;
        let region_note = if req.region.is_empty() {
            "global".to_string()
        } else {
            req.region.clone()
        };

        warn!(
            "ControlBus: EMERGENCY GHOST — mode={:?} region={}",
            mode, region_note
        );

        self.ghost_bus.broadcast(mode);

        Ok(Response::new(EmergencyResponse { success: true }))
    }

    /// Unary RPC: compare the UI's expected config hash with the live running
    /// config hash.  If they diverge, the UI can re-push the authoritative
    /// config via `push_delta_update`.
    async fn verify_consistency(
        &self,
        request: Request<ConsistencyRequest>,
    ) -> Result<Response<ConsistencyResponse>, Status> {
        let expected = request.into_inner().expected_hash;
        let actual = self.config.sha256_hex().await;
        let is_match = actual == expected;

        if !is_match {
            warn!(
                "ControlBus: consistency mismatch — expected={} actual={}",
                expected, actual
            );
        } else {
            info!("ControlBus: consistency check OK (hash={})", actual);
        }

        Ok(Response::new(ConsistencyResponse {
            r#match: is_match,
            actual_hash: actual,
        }))
    }
}

// ---------------------------------------------------------------------------
// Re-export a stream helper used in the PushDeltaUpdate implementation above.
// ---------------------------------------------------------------------------
use futures::StreamExt;

// ---------------------------------------------------------------------------
// Test surface — thin wrappers to avoid exposing private fields in prod code.
// ---------------------------------------------------------------------------

impl HotConfig {
    /// Exposed for integration tests; calls the same code path as the gRPC handler.
    pub async fn apply_patch_test(&self, json_patch: &str) -> Result<String, String> {
        self.apply_patch(json_patch).await
    }
}

impl GhostModeBus {
    /// Exposed for integration tests.
    pub fn broadcast_test(&self, mode: GhostMode) {
        self.broadcast(mode);
    }
}
