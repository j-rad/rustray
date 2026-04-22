pub use crate::config::FakeDnsConfig;
use serde::{Deserialize, Serialize};

pub mod migration;
pub mod parser;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub enum Protocol {
    #[default]
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Flow,
}

/// Carrier type for transport selection
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarrierType {
    /// REALITY-based TLS camouflage (most stealthy)
    Reality,
    /// MQTT IoT protocol camouflage
    Mqtt,
    /// CDN-based transport (WebSocket/HTTP Upgrade)
    Cdn,
    /// Direct TCP/QUIC connection
    Direct,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ServerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>, // Database ID
    pub address: String,
    pub port: u16,
    pub remarks: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub pbk: Option<String>, // Reality public key
    #[serde(default)]
    pub sid: Option<String>, // Reality short id
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub allow_insecure: Option<bool>,
}

impl ServerConfig {
    pub fn to_uri(&self) -> String {
        match self.protocol {
            Protocol::Vless => {
                let uuid = self.uuid.as_deref().unwrap_or("");
                let host = &self.address;
                let port = self.port;
                let remarks = url::form_urlencoded::byte_serialize(self.remarks.as_bytes())
                    .collect::<String>();

                let mut params = Vec::new();
                params.push(("security", self.security.as_deref().unwrap_or("none")));
                params.push(("type", self.network.as_deref().unwrap_or("tcp")));

                if let Some(sni) = &self.sni {
                    params.push(("sni", sni));
                }
                if let Some(path) = &self.path {
                    params.push(("path", path));
                }
                if let Some(flow) = &self.flow {
                    params.push(("flow", flow));
                }
                if let Some(pbk) = &self.pbk {
                    params.push(("pbk", pbk));
                }
                if let Some(sid) = &self.sid {
                    params.push(("sid", sid));
                }
                if let Some(fp) = &self.fingerprint {
                    params.push(("fp", fp));
                }

                let query = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(params)
                    .finish();

                format!("vless://{}@{}:{}?{}#{}", uuid, host, port, query, remarks)
            }
            Protocol::Trojan => {
                let password = self.password.as_deref().unwrap_or("");
                let host = &self.address;
                let port = self.port;
                let remarks = url::form_urlencoded::byte_serialize(self.remarks.as_bytes())
                    .collect::<String>();

                let mut params = Vec::new();
                params.push(("security", self.security.as_deref().unwrap_or("tls")));
                params.push(("type", self.network.as_deref().unwrap_or("tcp")));

                if let Some(sni) = &self.sni {
                    params.push(("sni", sni));
                }
                if let Some(path) = &self.path {
                    params.push(("path", path));
                }
                if let Some(host_hdr) = &self.host {
                    params.push(("host", host_hdr));
                }

                let query = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(params)
                    .finish();

                format!(
                    "trojan://{}@{}:{}?{}#{}",
                    password, host, port, query, remarks
                )
            }
            // Fallback/TODO for other protocols
            _ => String::from("edgeray://unsupported-protocol"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum RoutingMode {
    /// Proxy all traffic
    Global,
    /// Bypass LAN and private IP ranges
    #[default]
    BypassLan,
    /// Bypass LAN and mainland China (requires GeoIP/GeoSite data)
    BypassMainland,
    // Direct
    Direct,
    // Custom Rule-based
    Rule,
}


#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum PerAppMode {
    #[default]
    Global,
    Whitelist,
    Blacklist,
}


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TunnelConfig {
    #[serde(skip)]
    pub file_descriptor: Option<i32>,
    pub active_server: ServerConfig,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_ip")]
    pub tun_ip: String,
    #[serde(default = "default_tun_cidr")]
    pub tun_cidr: u8,
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
    #[serde(default)]
    pub routing_mode: RoutingMode,
    #[serde(default)]
    pub geodata_dir: Option<String>,
    #[serde(default)]
    pub per_app_mode: PerAppMode,
    #[serde(default)]
    pub per_app_list: Vec<String>,
    #[serde(default)]
    pub sniffing: bool,
    #[serde(default)]
    pub dns_hijacking: bool,
    #[serde(default)]
    pub lock_vpn: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub urls: Vec<String>,        // Multi-URL support
    pub update_interval: u64,     // seconds
    pub last_update: Option<u64>, // unix timestamp
    #[serde(default)]
    pub filter_tags: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub node_count: usize,
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "New Subscription".to_string(),
            urls: vec![],
            update_interval: 3600, // 1 hour
            last_update: None,
            filter_tags: vec![],
            enabled: true,
            node_count: 0,
        }
    }
}

fn default_tun_name() -> String {
    "ray0".to_string()
}

fn default_tun_ip() -> String {
    "10.0.0.1".to_string()
}

fn default_tun_cidr() -> u8 {
    24
}

fn default_tun_mtu() -> u16 {
    1500
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AppSettings {
    #[serde(default = "default_theme")]
    pub theme: String, // "system", "dark", "light"
    #[serde(default = "default_ui_mode")]
    pub ui_mode: String,
    #[serde(default)]
    pub start_on_boot: bool,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default = "default_routing_mode_str")]
    pub routing_mode: String, // "rule", "global", "direct" (UI specific representation)
    #[serde(default = "default_true")]
    pub sniffing: bool,
    #[serde(default = "default_true")]
    pub dns_hijacking: bool,
    #[serde(default)]
    pub lock_vpn: bool,
    #[serde(default = "default_doh")]
    pub doh_url: String,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default = "default_core")]
    pub active_core: String,
    #[serde(default = "default_rustray_version")]
    pub rustray_version: String,
    #[serde(default = "default_singbox_version")]
    pub singbox_version: String,

    #[serde(default = "default_fec_shards")]
    pub fec_data_shards: u8,
    #[serde(default = "default_fec_parities")]
    pub fec_parities: u8,
    #[serde(default = "default_mqtt_heartbeat")]
    pub mqtt_heartbeat_interval: u64,
    #[serde(default = "default_fingerprint_interval")]
    pub fingerprint_rotation_interval: u64,

    #[serde(default)]
    pub fakedns: FakeDnsConfig,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            ui_mode: default_ui_mode(),
            start_on_boot: false,
            allow_insecure: false,
            routing_mode: default_routing_mode_str(),
            sniffing: true,
            dns_hijacking: true,
            lock_vpn: false,
            doh_url: default_doh(),
            auto_update: false,
            active_core: default_core(),
            rustray_version: default_rustray_version(),
            singbox_version: default_singbox_version(),
            fec_data_shards: default_fec_shards(),
            fec_parities: default_fec_parities(),
            mqtt_heartbeat_interval: default_mqtt_heartbeat(),
            fingerprint_rotation_interval: default_fingerprint_interval(),
            fakedns: FakeDnsConfig::default(),
        }
    }
}

fn default_rustray_version() -> String {
    "v25.12.8".to_string()
}

fn default_singbox_version() -> String {
    "v1.12.14".to_string()
}

fn default_core() -> String {
    "rustray".to_string()
}

fn default_theme() -> String {
    "system".to_string()
}
fn default_ui_mode() -> String {
    "simple".to_string()
}
fn default_routing_mode_str() -> String {
    "rule".to_string()
}
fn default_true() -> bool {
    true
}
fn default_doh() -> String {
    "https://1.1.1.1/dns-query".to_string()
}

fn default_fec_shards() -> u8 {
    10
}

fn default_fec_parities() -> u8 {
    3
}

fn default_mqtt_heartbeat() -> u64 {
    30
}

fn default_fingerprint_interval() -> u64 {
    3600
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
pub enum RuleType {
    #[default]
    Field,
    Balancer,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, uniffi::Record)]
pub struct RoutingRule {
    pub id: String,
    #[serde(default)]
    pub enabled: bool,
    pub name: String,
    pub rule_type: RuleType,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ports: String,
    pub outbound: String,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, uniffi::Record)]
pub struct StatsSnapshot {
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub active_connections: u64,
    pub total_connections: u64,
    pub last_update: u64,
    pub connection_state: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default, uniffi::Enum)]
pub enum DpiState {
    #[default]
    Clear,
    Throttled,
    ResetDetected,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, uniffi::Record)]
pub struct ConnectionMetrics {
    pub rtt_ms: u64,
    pub cwnd_bytes: u64,
    pub dpi_state: DpiState,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default, uniffi::Record)]
pub struct AppMetadata {
    pub package_id: String,
    pub name: String,
    pub icon_path: Option<String>,
    pub data_usage_mb: f64,
    pub is_system: bool,
    pub uid: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, uniffi::Record)]
pub struct PerAppRule {
    pub id: String,
    pub package_id: String,
    pub action: RuleAction,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RuleAction {
    Include, // App uses VPN
    Exclude, // App bypasses VPN
    Block,   // App network access blocked
}
