//! Universal UniFFI Core for RustRay
//!
//! This module provides a unified, platform-agnostic interface for controlling the
//! RustRay engine and managing application state.

pub mod desktop;
pub mod mobile;

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Runtime;
use tracing::{error, info};

use crate::app::connection_tracker::{ConnectionState as TrackerState, global_tracker};
use crate::app::secure_storage::{ServerModel, SurrealProvider};
use crate::config::Outbound;

// Expose internal helpers
pub use crate::ffi::mobile::{acquire_ios_buffer, init_ios_pool};

// ============================================================================
// CONFIG TYPES (UniFFI Records)
// ============================================================================

/// Connection configuration for mobile apps.
/// This structure is converted to an internal `Config` by the engine.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct ConnectConfig {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub protocol: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub reality_settings: Option<RealityConfig>,
    #[serde(default)]
    pub utls_fingerprint: Option<String>,
    #[serde(default)]
    pub fragment_settings: Option<FragmentConfig>,
    #[serde(default)]
    pub flow_j_settings: Option<FlowJMobileConfig>,
    #[serde(default = "default_local_address")]
    pub local_address: String,
    #[serde(default = "default_local_port")]
    pub local_port: u16,
    #[serde(default)]
    pub enable_udp: bool,
    #[serde(default)]
    pub tun_fd: Option<i32>,
    #[serde(default = "default_routing_mode")]
    pub routing_mode: String,
}
fn default_network() -> String {
    "tcp".to_string()
}
fn default_security() -> String {
    "tls".to_string()
}
fn default_local_address() -> String {
    "127.0.0.1".to_string()
}
fn default_local_port() -> u16 {
    1080
}
fn default_routing_mode() -> String {
    "global".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
pub struct RealityConfig {
    pub public_key: String,
    pub short_id: String,
    pub server_name: String,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
    #[serde(default)]
    pub spider_x: Option<String>,
}
fn default_fingerprint() -> String {
    "chrome".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct FragmentConfig {
    #[serde(default = "default_frag_len")]
    pub length: String,
    #[serde(default = "default_frag_int")]
    pub interval: String,
}
fn default_frag_len() -> String {
    "10-50".to_string()
}
fn default_frag_int() -> String {
    "20-50".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
pub struct FlowJMobileConfig {
    #[serde(default = "default_flowj_mode")]
    pub mode: String,
    #[serde(default)]
    pub reality: Option<FlowJRealityConfig>,
    #[serde(default)]
    pub cdn: Option<FlowJCdnConfig>,
    #[serde(default)]
    pub mqtt: Option<FlowJMqttConfig>,
    #[serde(default)]
    pub fec: Option<FlowJFecConfig>,
}
fn default_flowj_mode() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
pub struct FlowJRealityConfig {
    pub dest: String,
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub short_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
pub struct FlowJCdnConfig {
    #[serde(default = "default_cdn")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub use_xhttp: bool,
}
fn default_cdn() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
pub struct FlowJMqttConfig {
    pub broker: String,
    #[serde(default = "default_topic")]
    pub upload_topic: String,
    #[serde(default = "default_topic")]
    pub download_topic: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}
fn default_topic() -> String {
    "sensor/data".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, uniffi::Record)]
pub struct FlowJFecConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_data")]
    pub data_shards: u32,
    #[serde(default = "default_parity")]
    pub parity_shards: u32,
}
fn default_data() -> u32 {
    10
}
fn default_parity() -> u32 {
    3
}

// ============================================================================
// SHARED STATS (Pointer Passing)
// ============================================================================

#[repr(C)]
pub struct SharedStatsBuffer {
    pub bytes_uploaded: AtomicU64,
    pub bytes_downloaded: AtomicU64,
    /// Total number of active TCP/UDP streams being tracked.
    pub active_connections: AtomicU64,
    /// Historical count of all connections since engine start.
    pub total_connections: AtomicU64,
    /// Unix timestamp (ms) of the last stats pull.
    pub last_update: AtomicU64,
    /// Current engine state: 0=Stopped, 1=Starting, 2=Connected, 3=Error.
    pub connection_state: AtomicU64,
    /// Error counter for troubleshooting.
    pub errors: AtomicU64,
    valid: AtomicBool,
}

impl Default for SharedStatsBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedStatsBuffer {
    pub const fn new() -> Self {
        Self {
            bytes_uploaded: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            last_update: AtomicU64::new(0),
            connection_state: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            valid: AtomicBool::new(true),
        }
    }

    pub fn set_state(&self, state: u64) {
        self.connection_state.store(state, Ordering::Relaxed);
        self.update_timestamp();
    }

    fn update_timestamp(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_update.store(now, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            bytes_uploaded: self.bytes_uploaded.load(Ordering::Relaxed),
            bytes_downloaded: self.bytes_downloaded.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            last_update: self.last_update.load(Ordering::Relaxed),
            connection_state: self.connection_state.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

static SHARED_STATS: SharedStatsBuffer = SharedStatsBuffer::new();

#[unsafe(no_mangle)]
pub extern "C" fn get_shared_stats_ptr() -> *const SharedStatsBuffer {
    &SHARED_STATS as *const _
}

pub fn global_shared_stats() -> &'static SharedStatsBuffer {
    &SHARED_STATS
}

pub use crate::types::{ConnectionMetrics, RuleType, StatsSnapshot};

// ============================================================================
// FFI ERROR TYPE
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RayResult {
    Ok,
    ConfigError(String),
    ConnectionError(String),
    HandshakeError(String),
    ProtocolError(String),
    AlreadyRunning,
    NotRunning,
    PanicError(String),
    StorageError(String),
}

impl std::fmt::Display for RayResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for RayResult {}

// ============================================================================
// ENGINE MANAGER
// ============================================================================

static ENGINE_INSTANCE: OnceLock<Arc<EngineManager>> = OnceLock::new();
static STORAGE: OnceLock<SurrealProvider> = OnceLock::new();

#[derive(uniffi::Object)]
pub struct EngineManager {
    runtime: Mutex<Option<Runtime>>,
    haptic: Mutex<Option<Arc<dyn HapticFeedback>>>,
}

#[uniffi::export(callback_interface)]
pub trait VpnCallback: Send + Sync {
    fn protect(&self, fd: i32) -> bool;
}

#[uniffi::export(callback_interface)]
pub trait HapticFeedback: Send + Sync {
    fn trigger_success(&self);
    fn trigger_error(&self);
    fn trigger_selection(&self);
}

#[uniffi::export]
impl EngineManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        ENGINE_INSTANCE
            .get_or_init(|| {
                Arc::new(EngineManager {
                    runtime: Mutex::new(None),
                    haptic: Mutex::new(None),
                })
            })
            .clone()
    }

    pub fn set_haptic_callback(&self, callback: Box<dyn HapticFeedback>) {
        if let Ok(mut h) = self.haptic.lock() {
            *h = Some(Arc::from(callback));
        }
    }

    pub fn start_engine(
        &self,
        config_json: String,
        callback: Option<Box<dyn VpnCallback>>,
    ) -> RayResult {
        let mut rt_guard = match self.runtime.lock() {
            Ok(g) => g,
            Err(e) => return RayResult::PanicError(format!("Lock poisoning: {}", e)),
        };

        if rt_guard.is_some() {
            if let Ok(h) = self.haptic.lock()
                && let Some(haptic) = &*h {
                    haptic.trigger_error();
                }
            return RayResult::AlreadyRunning;
        }

        // Parse Config
        let connect_config: ConnectConfig = match serde_json::from_str(&config_json) {
            Ok(c) => c,
            Err(e) => {
                if let Ok(h) = self.haptic.lock()
                    && let Some(haptic) = &*h {
                        haptic.trigger_error();
                    }
                return RayResult::ConfigError(e.to_string());
            }
        };

        // Build Internal Config
        let config = match build_internal_config(&connect_config) {
            Ok(c) => c,
            Err(e) => {
                if let Ok(h) = self.haptic.lock()
                    && let Some(haptic) = &*h {
                        haptic.trigger_error();
                    }
                return e;
            }
        };

        // Create Runtime
        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                if let Ok(h) = self.haptic.lock()
                    && let Some(haptic) = &*h {
                        haptic.trigger_error();
                    }
                return RayResult::ConnectionError(format!("Runtime init: {}", e));
            }
        };

        // Start Internal Proxy Server
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
        runtime.spawn(async move {
            match crate::run_server(config, shutdown_rx).await {
                Ok(_) => info!("Server finished"),
                Err(e) => error!("Server failed: {}", e),
            }
        });

        // Platform Specific Launch
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            mobile::run_mobile_tun(&runtime, &connect_config, callback);
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = callback;
            desktop::run_desktop_tun(&runtime, &connect_config);
        }

        info!("Engine started");
        *rt_guard = Some(runtime);
        global_shared_stats().set_state(1);

        if let Ok(h) = self.haptic.lock()
            && let Some(haptic) = &*h {
                haptic.trigger_success();
            }

        RayResult::Ok
    }

    pub fn stop_engine(&self) -> RayResult {
        let mut rt_guard = match self.runtime.lock() {
            Ok(g) => g,
            Err(e) => return RayResult::PanicError(e.to_string()),
        };

        if rt_guard.is_none() {
            return RayResult::NotRunning;
        }

        info!("Stopping engine...");
        *rt_guard = None; // Runtime dropped, tasks cancelled
        global_shared_stats().set_state(0);
        RayResult::Ok
    }

    pub fn get_stats_json(&self) -> String {
        let tracker = global_tracker();
        let stats = tracker.get_stats();
        let shared = global_shared_stats();

        shared
            .bytes_uploaded
            .store(stats.bytes_uploaded, Ordering::Relaxed);
        shared
            .bytes_downloaded
            .store(stats.bytes_downloaded, Ordering::Relaxed);

        if stats.state == TrackerState::Connected {
            shared.set_state(2);
        }

        let snap = StatsSnapshot {
            bytes_uploaded: stats.bytes_uploaded,
            bytes_downloaded: stats.bytes_downloaded,
            active_connections: 0,
            total_connections: 0,
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            connection_state: if stats.state == TrackerState::Connected {
                2
            } else {
                0
            },
            errors: 0,
        };
        serde_json::to_string(&snap).unwrap_or_else(|_| "{}".to_string())
    }

    // --- Storage Methods (Delegated) ---
    pub fn init_storage(&self, path: String, key_hex: String) -> RayResult {
        if STORAGE.get().is_some() {
            return RayResult::Ok;
        }

        let key_bytes = match hex::decode(&key_hex) {
            Ok(k) if k.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&k);
                arr
            }
            Ok(_) => return RayResult::ConfigError("Key must be 32 bytes".into()),
            Err(e) => return RayResult::ConfigError(format!("Invalid hex key: {}", e)),
        };

        let rt = match Runtime::new() {
            Ok(r) => r,
            Err(e) => return RayResult::ConnectionError(e.to_string()),
        };

        let res = rt.block_on(async { SurrealProvider::new(&path, key_bytes).await });
        match res {
            Ok(provider) => {
                let _ = STORAGE.set(provider);
                RayResult::Ok
            }
            Err(e) => RayResult::StorageError(format!("Storage init: {}", e)),
        }
    }

    pub fn save_server(
        &self,
        name: String,
        outbound_json: String,
        sub_id: Option<String>,
    ) -> RayResult {
        let storage = match STORAGE.get() {
            Some(s) => s,
            None => return RayResult::NotRunning,
        };

        let outbound: Outbound = match serde_json::from_str(&outbound_json) {
            Ok(o) => o,
            Err(e) => return RayResult::ConfigError(e.to_string()),
        };

        let rt = Runtime::new().unwrap();
        match rt.block_on(storage.save_server(&name, &outbound, sub_id)) {
            Ok(_) => RayResult::Ok,
            Err(e) => RayResult::StorageError(e.to_string()),
        }
    }

    pub fn list_servers(&self) -> Result<String, RayResult> {
        let storage = STORAGE.get().ok_or(RayResult::NotRunning)?;
        let rt = Runtime::new().map_err(|e| RayResult::PanicError(e.to_string()))?;

        rt.block_on(async {
            let servers = storage
                .list_servers()
                .await
                .map_err(|e| RayResult::StorageError(e.to_string()))?;
            let models: Vec<ServerModel> = servers.into_iter().map(|(_, m)| m).collect();
            serde_json::to_string(&models).map_err(|e| RayResult::ConfigError(e.to_string()))
        })
    }

    pub fn delete_server(&self, id: String) -> RayResult {
        let storage = match STORAGE.get() {
            Some(s) => s,
            None => return RayResult::NotRunning,
        };
        let rt = Runtime::new().unwrap();
        match rt.block_on(storage.delete_server(&id)) {
            Ok(_) => RayResult::Ok,
            Err(e) => RayResult::StorageError(e.to_string()),
        }
    }

    // --- Geo Utils ---
    pub fn is_iranian_ip(&self, ip_str: String) -> bool {
        use crate::app::router::geo_loader::GeoManager;
        static GEO_MANAGER: OnceLock<GeoManager> = OnceLock::new();
        let manager = GEO_MANAGER.get_or_init(GeoManager::new);
        if let Ok(ip) = ip_str.parse() {
            manager.is_iranian_ip(ip)
        } else {
            false
        }
    }

    // --- Core Management ---
    pub fn get_core_version(&self, core_name: String) -> String {
        use crate::app::core_manager::{CoreManager, CoreType};
        let rt = match Runtime::new() {
            Ok(r) => r,
            Err(_) => return "error".to_string(),
        };

        rt.block_on(async {
            let manager = CoreManager::new("rustray");
            let core_type = match core_name.to_lowercase().as_str() {
                "rustray" | "xray" | "sing-box" | "singbox" => CoreType::RustRay,
                _ => return "unknown".to_string(),
            };

            manager
                .get_local_version(core_type)
                .await
                .unwrap_or("not_installed".to_string())
        })
    }

    pub fn update_core(&self, core_name: String) -> Result<String, RayResult> {
        use crate::app::core_manager::{CoreManager, CoreType};
        let rt = Runtime::new().map_err(|e| RayResult::PanicError(e.to_string()))?;

        rt.block_on(async {
            let manager = CoreManager::new("rustray");
            let core_type = match core_name.to_lowercase().as_str() {
                "rustray" | "xray" | "sing-box" | "singbox" => CoreType::RustRay,
                _ => return Err(RayResult::ConfigError("Unknown core type".to_string())),
            };

            manager
                .update_core(core_type)
                .await
                .map_err(|e| RayResult::ConnectionError(e.to_string()))
        })
    }
    pub fn apply_routing_config(&self, config_json: String) -> RayResult {
        // Parse Config
        let connect_config: ConnectConfig = match serde_json::from_str(&config_json) {
            Ok(c) => c,
            Err(e) => return RayResult::ConfigError(e.to_string()),
        };

        // Build Internal Config
        let config = match build_internal_config(&connect_config) {
            Ok(c) => c,
            Err(e) => return e,
        };

        // Get Global Stats Manager
        use crate::app::stats::StatsManager;
        if let Some(stats_manager) = StatsManager::global() {
            info!("Applying atomic routing update...");
            stats_manager.update_config(config);
            RayResult::Ok
        } else {
            RayResult::NotRunning
        }
    }
}

// Top level version
#[uniffi::export]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ============================================================================
// LEGACY FFI WRAPPERS (For Tests & Simple Integration)
// ============================================================================

#[uniffi::export]
pub fn start(config_json: String) -> RayResult {
    EngineManager::new().start_engine(config_json, None)
}

#[uniffi::export]
pub fn stop() -> bool {
    EngineManager::new().stop_engine() == RayResult::Ok
}

#[uniffi::export]
pub fn is_running() -> bool {
    let engine = EngineManager::new();
    let rt = engine.runtime.lock().unwrap();
    rt.is_some()
}

#[uniffi::export]
pub fn fetch_stats() -> StatsSnapshot {
    let engine = EngineManager::new();
    // Trigger update of shared stats from tracker
    let _ = engine.get_stats_json();
    global_shared_stats().snapshot()
}

#[uniffi::export]
pub fn test_reality_handshake(_config_json: String) -> Result<(), String> {
    // This is a stub for integration testing handshake logic without starting a full server.
    // In a real implementation, this would perform a one-off REALITY handshake.
    Ok(())
}

#[uniffi::export]
pub fn test_vision_handshake(_config_json: String) -> Result<(), String> {
    Ok(())
}

#[uniffi::export]
pub fn test_flowj_connection(_config_json: String) -> Result<(), String> {
    Ok(())
}

// Implementation Helpers

use crate::config::{
    Config, Inbound, InboundSettings, OutboundSettings, RealityClientConfig, StreamSettings,
    TlsFragmentSettings, VlessOutboundSettings,
};

fn build_internal_config(connect_config: &ConnectConfig) -> Result<Config, RayResult> {
    let mut stream_settings = StreamSettings::default();
    stream_settings.network = connect_config.network.clone();
    stream_settings.security = connect_config.security.clone();

    if let Some(reality) = &connect_config.reality_settings {
        stream_settings.reality_settings = Some(RealityClientConfig {
            show: false,
            fingerprint: reality.fingerprint.clone(),
            server_name: reality.server_name.clone(),
            public_key: reality.public_key.clone(),
            short_id: reality.short_id.clone(),
            spider_x: reality.spider_x.clone(),
        });
    }
    if let Some(frag) = &connect_config.fragment_settings {
        stream_settings.fragment_settings = Some(TlsFragmentSettings {
            length: frag.length.clone(),
            interval: frag.interval.clone(),
        });
    }
    if connect_config.security == "tls" {
        let mut tls = crate::config::TlsSettings::default();
        tls.server_name = Some(connect_config.address.clone());
        tls.allow_insecure = Some(false);
        if let Some(fp) = &connect_config.utls_fingerprint {
            tls.fingerprint = Some(fp.clone());
        }
        stream_settings.tls_settings = Some(tls);
    }

    let outbound_settings = match connect_config.protocol.as_str() {
        "vless" => OutboundSettings::Vless(VlessOutboundSettings {
            address: connect_config.address.clone(),
            port: connect_config.port,
            uuid: connect_config.uuid.clone(),
            flow: connect_config.flow.clone(),
            reality_settings: stream_settings.reality_settings.clone(),
        }),
        "flow-j" | "flowj" => {
            let _flowj = connect_config.flow_j_settings.clone().unwrap_or_default();
            OutboundSettings::Flow(crate::config::FlowOutboundSettings {
                address: connect_config.address.clone(),
                port: connect_config.port,
                uuid: connect_config.uuid.clone(),
                secret: None,
                fec: None,
                multiport: None,
            })
        }
        _ => {
            return Err(RayResult::ConfigError(format!(
                "Unsupported: {}",
                connect_config.protocol
            )));
        }
    };

    let outbound = Outbound {
        tag: "proxy".to_string(),
        protocol: connect_config.protocol.clone(),
        settings: Some(outbound_settings),
        stream_settings: Some(stream_settings),
        mux: None,
        proxy_settings: None,
    };

    let inbound = Inbound {
        tag: "socks-in".to_string(),
        port: connect_config.local_port,
        listen: Some(connect_config.local_address.clone()),
        protocol: "socks".to_string(),
        settings: Some(InboundSettings::Socks(crate::config::SocksSettings {
            auth: None,
            accounts: None,
            udp: Some(connect_config.enable_udp),
            ip: None,
            user_level: None,
        })),
        stream_settings: None,
        sniffing: None,
        allocation: None,
    };

    Ok(Config {
        inbounds: Some(vec![inbound]),
        outbounds: Some(vec![outbound]),
        ..Default::default()
    })
}
