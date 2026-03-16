// src/config.rs
use crate::protocols::flow_j::FecSettings;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default)]
    pub dns: Option<DnsConfig>,

    #[serde(default)]
    pub policy: Option<PolicyConfig>,

    #[serde(default)]
    pub stats: Option<StatsConfig>,

    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    #[serde(default)]
    pub observatory: Option<ObservatoryConfig>,

    pub api: Option<ApiConfig>,
    pub log: Option<Log>,
    pub inbounds: Option<Vec<Inbound>>,
    pub outbounds: Option<Vec<Outbound>>,
    pub routing: Option<Routing>,
    #[serde(default)]
    pub isp: Option<IspConfig>,
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(routing) = &self.routing {
            if let Some(rules) = &routing.rules {
                let _visited: HashSet<String> = HashSet::new();
                for rule in rules {
                    // Detect circular balancer references or invalid tags
                    // Simplified check: ensure outbound_tag exists or is a balancer
                    if rule.outbound_tag.starts_with("balancer:") {
                        let balancer_tag = rule.outbound_tag.strip_prefix("balancer:").unwrap();
                        let balancer_exists = routing
                            .balancers
                            .as_ref()
                            .map_or(false, |b| b.iter().any(|x| x.tag == balancer_tag));
                        if !balancer_exists {
                            return Err(format!(
                                "Rule references non-existent balancer: {}",
                                balancer_tag
                            ));
                        }
                    }
                    // RustRay allows complex routing so simple cycles are hard to detect statically without full resolution logic.
                    // This basic check ensures at least target existence.
                }
            }
        }

        if let Some(isp) = &self.isp {
            let preset = isp.presets.iter().find(|p| p.name == isp.active_preset);
            if let Some(p) = preset {
                if p.edition != "2024" {
                    return Err(format!(
                        "ISP Preset '{}' is incompatible with edition 2024",
                        p.name
                    ));
                }
            } else {
                return Err(format!(
                    "Active ISP preset '{}' not found",
                    isp.active_preset
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IspConfig {
    pub active_preset: String,
    pub presets: Vec<IspPreset>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct IspPreset {
    pub name: String,
    /// MTU for this ISP (including IP + TCP headers).
    pub mtu: u16,
    /// TCP Maximum Segment Size = MTU - 40 (IPv4) or MTU - 60 (IPv6).
    /// If zero, derived automatically from `mtu`.
    #[serde(default)]
    pub mss: u16,
    pub flow_j_initial_delay_ms: u64,
    pub preferred_port_ranges: Vec<String>,
    pub edition: String,
}

/// Known Iranian carrier identifiers, used for automatic ISP profile selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IspCarrier {
    /// MCI (Hamrahe Aval) – largest mobile carrier
    Mci,
    /// MTN Irancell – second-largest mobile carrier
    Mtn,
    /// Rightel – MVNO on 3G/LTE
    Rightel,
    /// Unknown / wired ISP
    Unknown,
}

impl IspCarrier {
    /// Detect carrier from an AS-number string prefix returned by WHOIS/GeoIP.
    pub fn from_asn(asn: &str) -> Self {
        // ASNs are stable; map to carriers.
        match asn {
            // MCI (Hamrahe Aval)
            "AS197207" | "AS44244" | "AS58224" => Self::Mci,
            // MTN Irancell
            "AS43754" | "AS57218" => Self::Mtn,
            // Rightel
            "AS51074" => Self::Rightel,
            _ => Self::Unknown,
        }
    }

    /// Return the canonical profile name that `ISPProfileManager` will look up.
    pub fn profile_name(self) -> &'static str {
        match self {
            Self::Mci => "mci",
            Self::Mtn => "mtn",
            Self::Rightel => "rightel",
            Self::Unknown => "default",
        }
    }
}

/// Runtime manager for ISP-specific MTU / MSS tuning.
///
/// Holds a reference to the active presets and resolves the effective
/// network parameters for any detected carrier.  When `detect_and_apply`
/// is called the manager returns an `EffectiveMtuMss` that tun_device.rs
/// uses to set `IP_MTU_DISCOVER` / `TCP_MAXSEG` on the raw socket.
#[derive(Debug, Clone)]
pub struct ISPProfileManager {
    presets: Vec<IspPreset>,
    active_preset_name: String,
}

/// MTU + MSS combination that `tun_device.rs` applies to a socket.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveMtuMss {
    /// Ethernet payload MTU (e.g. 1400 for MCI)
    pub mtu: u16,
    /// TCP MSS = mtu - 40 for IPv4, mtu - 60 for IPv6
    pub mss_ipv4: u16,
    pub mss_ipv6: u16,
}

impl ISPProfileManager {
    /// Build from the `IspConfig` section of the loaded `Config`.
    pub fn from_config(cfg: &IspConfig) -> Self {
        Self {
            presets: cfg.presets.clone(),
            active_preset_name: cfg.active_preset.clone(),
        }
    }

    /// Look up a preset by name, falling back to the first preset or a safe default.
    fn find_preset(&self, name: &str) -> IspPreset {
        self.presets
            .iter()
            .find(|p| p.name == name)
            .cloned()
            .unwrap_or_else(|| IspPreset {
                name: "default".to_string(),
                mtu: 1400,
                mss: 0,
                flow_j_initial_delay_ms: 0,
                preferred_port_ranges: vec![],
                edition: "2024".to_string(),
            })
    }

    /// Return effective MTU/MSS for the active preset.
    pub fn effective_params(&self) -> EffectiveMtuMss {
        let preset = self.find_preset(&self.active_preset_name);
        self.compute(&preset)
    }

    /// Detect carrier from an ASN string and return ISP-specific params.
    pub fn detect_and_apply(&self, asn: &str) -> EffectiveMtuMss {
        let carrier = IspCarrier::from_asn(asn);
        let preset = self.find_preset(carrier.profile_name());
        self.compute(&preset)
    }

    fn compute(&self, preset: &IspPreset) -> EffectiveMtuMss {
        let mtu = preset.mtu;
        // If the user provided an explicit MSS, honour it; otherwise derive it.
        let mss_ipv4 = if preset.mss > 0 {
            preset.mss
        } else {
            mtu.saturating_sub(40) // 20 IP + 20 TCP
        };
        let mss_ipv6 = mtu.saturating_sub(60); // 40 IPv6 + 20 TCP
        EffectiveMtuMss {
            mtu,
            mss_ipv4,
            mss_ipv6,
        }
    }
}
// ... rest of the file ...
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DnsConfig {
    pub servers: Option<Vec<String>>,
    pub auto_detect_system_dns: Option<bool>,
    pub fakedns: Option<FakeDnsConfig>,
    pub hosts: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PolicyConfig {
    pub levels: Option<HashMap<u32, LevelPolicy>>,
    pub system: Option<SystemPolicy>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct LevelPolicy {
    pub handshake: Option<u32>,
    pub conn_idle: Option<u32>,
    pub uplink_only: Option<u32>,
    pub downlink_only: Option<u32>,
    pub stats_user_uplink: Option<bool>,
    pub stats_user_downlink: Option<bool>,
    pub buffer_size: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SystemPolicy {
    pub stats_inbound_uplink: Option<bool>,
    pub stats_inbound_downlink: Option<bool>,
    pub stats_outbound_uplink: Option<bool>,
    pub stats_outbound_downlink: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct StatsConfig {}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MetricsConfig {}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ObservatoryConfig {
    pub subject_selector: Option<Vec<String>>,
    pub probe_url: Option<String>,
    pub probe_interval: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ApiConfig {
    pub tag: String,
    pub services: Vec<String>,
    pub port: Option<u16>,
    pub listen: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Log {
    pub access: Option<String>,
    pub error: Option<String>,
    pub loglevel: Option<String>,
    pub dns_log: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Inbound {
    pub tag: String,
    pub port: u16,
    pub listen: Option<String>,
    pub protocol: String,
    pub settings: Option<InboundSettings>,
    #[serde(rename = "streamSettings")]
    pub stream_settings: Option<StreamSettings>,
    pub sniffing: Option<SniffingConfig>,
    pub allocation: Option<AllocationStrategy>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum InboundSettings {
    Socks(SocksSettings),
    Vless(VlessSettings),
    Vmess(VmessSettings),
    Hysteria2(Hysteria2Settings),
    Shadowsocks2022(Shadowsocks2022Settings),
    Dokodemo(DokodemoSettings),
    Tuic(TuicSettings),
    Trojan(TrojanSettings),
    Flow(FlowSettings),
    Http(HttpProxySettings),
    ReversePortal(ReversePortalSettings),
    // Add specific inbound settings as needed
    Generic(serde_json::Value),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Outbound {
    pub tag: String,
    pub protocol: String,
    pub settings: Option<OutboundSettings>,
    #[serde(rename = "streamSettings")]
    pub stream_settings: Option<StreamSettings>,
    pub mux: Option<MuxConfig>,
    pub proxy_settings: Option<ProxySettings>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxySettings {
    pub tag: Option<String>,
    pub transport_layer: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum OutboundSettings {
    Freedom(FreedomSettings),
    Blackhole(BlackholeSettings),
    Dns(serde_json::Value),
    ReverseBridge(ReverseBridgeSettings),
    Http(HttpProxyOutboundSettings),
    Shadowsocks2022(Shadowsocks2022OutboundSettings),
    WireGuard(WireGuardSettings),
    Naive(NaiveOutboundSettings),
    Ssh(SshOutboundSettings),
    Tor(TorOutboundSettings),
    Tailscale(TailscaleSettings),
    Vless(VlessOutboundSettings),
    Vmess(VmessOutboundSettings),
    Hysteria2(Hysteria2OutboundSettings),
    Tuic(TuicOutboundSettings),
    Trojan(TrojanOutboundSettings),
    Flow(FlowOutboundSettings),
    // Add others as needed
    Generic(serde_json::Value),
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FreedomSettings {
    pub domain_strategy: Option<String>,
    pub redirect: Option<String>,
    pub user_level: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct BlackholeSettings {
    pub response: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Routing {
    pub domain_strategy: Option<String>,
    pub rules: Option<Vec<Rule>>,
    pub balancers: Option<Vec<Balancer>>,
    pub settings: Option<RoutingSettings>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RoutingSettings {
    pub domain_strategy: Option<String>,
    pub rules: Option<Vec<Rule>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub domain: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub port: Option<String>,
    pub network: Option<String>,
    pub source: Option<Vec<String>>,
    pub user: Option<Vec<String>>,
    pub inbound_tag: Option<Vec<String>>,
    pub protocol: Option<Vec<String>>,
    pub attrs: Option<String>,
    pub outbound_tag: String,
    pub balancer_tag: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Balancer {
    pub tag: String,
    pub selector: Vec<String>,
    pub strategy: Option<String>, // "random" | "leastPing"
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    pub allow_insecure: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub certificates: Option<Vec<Certificate>>,
    pub fingerprint: Option<String>,
    pub pqc: Option<PqcSettings>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PqcSettings {
    pub enabled: bool,
    pub server_public_key: Option<String>,
    pub secret_key: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Certificate {
    pub certificate_file: String,
    pub key_file: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct KcpConfig {
    pub mtu: Option<u32>,
    pub tti: Option<u32>,
    pub uplink_capacity: Option<u32>,
    pub downlink_capacity: Option<u32>,
    pub congestion: Option<bool>,
    pub read_buffer_size: Option<u32>,
    pub write_buffer_size: Option<u32>,
    pub seed: Option<String>,
    pub header: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WebSocketConfig {
    #[serde(default = "default_ws_path")]
    pub path: String,
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

fn default_ws_path() -> String {
    "/".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RealityClientConfig {
    pub show: bool,
    pub fingerprint: String,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TlsFragmentSettings {
    pub length: String,
    pub interval: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Sip003Settings {
    // Placeholder
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct SniffingConfig {
    pub enabled: bool,
    #[serde(deserialize_with = "deserialize_dest_override")]
    pub dest_override: Option<Vec<String>>,
    pub metadata_only: Option<bool>,
}

fn deserialize_dest_override<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match Option::<StringOrVec>::deserialize(deserializer)? {
        Some(StringOrVec::String(s)) => Ok(Some(vec![s])),
        Some(StringOrVec::Vec(v)) => Ok(Some(v)),
        None => Ok(None),
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AllocationStrategy {
    pub strategy: Option<String>, // "always" | "random" | "external"
    pub refresh: Option<u32>,
    pub concurrency: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MuxConfig {
    pub enabled: bool,
    pub concurrency: Option<i16>,
    pub xudp_concurrency: Option<i16>,
    pub xudp_proxy_udp443: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct FakeDnsConfig {
    pub ip_pool: String,
    pub pool_size: u32,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    pub persist_path: Option<String>,
    #[serde(default = "default_save_interval")]
    pub save_interval_secs: u64,
}

fn default_max_entries() -> usize {
    65535
}

fn default_save_interval() -> u64 {
    300 // 5 minutes
}

impl Default for FakeDnsConfig {
    fn default() -> Self {
        Self {
            ip_pool: "198.18.0.0/16".to_string(),
            pool_size: 65536,
            max_entries: 65535,
            persist_path: None,
            save_interval_secs: 300,
        }
    }
}

// Additional settings for specific protocols
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SocksSettings {
    pub auth: Option<String>,
    pub accounts: Option<Vec<UserAccount>>,
    pub udp: Option<bool>,
    pub ip: Option<String>,
    pub user_level: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UserAccount {
    pub user: String,
    pub pass: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ReversePortalSettings {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ReverseBridgeSettings {
    pub tag: String,
    pub domain: String,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DokodemoSettings {
    pub address: String,
    pub port: u16,
    pub network: Option<String>,
    pub tproxy: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SshOutboundSettings {
    pub address: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TailscaleSettings {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TorOutboundSettings {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VlessSettings {
    pub clients: Vec<VlessUser>,
    pub decryption: Option<String>,
    pub fallbacks: Option<Vec<Fallback>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VlessUser {
    pub id: String,
    pub level: Option<u32>,
    pub email: Option<String>,
    pub flow: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Fallback {
    pub alpn: Option<String>,
    pub path: Option<String>,
    pub dest: String,
    pub xver: Option<u32>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VlessOutboundSettings {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: Option<String>,
    pub reality_settings: Option<RealityClientConfig>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VmessSettings {
    pub clients: Vec<VmessUser>,
    pub default: Option<VmessDefault>,
    pub detour: Option<VmessDetour>,
    pub disable_insecure_encryption: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VmessUser {
    pub id: String,
    pub alter_id: Option<u16>,
    pub level: Option<u32>,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VmessDefault {
    pub level: u32,
    pub alter_id: u16,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VmessDetour {
    pub to: String,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct VmessOutboundSettings {
    pub address: String,
    pub port: u16,
    pub user: VmessUser,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Hysteria2Settings {
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
    pub password: Option<String>,
    pub obfuscation: Option<Obfuscation>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Obfuscation {
    #[serde(rename = "type")]
    pub obfs_type: String,
    pub password: String,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Hysteria2OutboundSettings {
    pub address: String,
    pub port: u16,
    pub server_name: Option<String>,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
    pub password: Option<String>,
    pub obfuscation: Option<Obfuscation>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TuicUser {
    pub uuid: String,
    pub password: String,
    pub level: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TuicSettings {
    pub users: Vec<TuicUser>,
    pub certificate: Option<Certificate>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TuicOutboundSettings {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub congestion_control: Option<String>,
    pub udp_relay_mode: Option<String>,
    pub heartbeart_interval: Option<u64>,
    pub allow_insecure: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TrojanSettings {
    pub clients: Vec<TrojanUser>,
    pub fallbacks: Option<Vec<Fallback>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TrojanUser {
    pub password: String,
    pub email: Option<String>,
    pub level: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TrojanOutboundSettings {
    pub address: String,
    pub port: u16,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FlowSettings {
    pub clients: Vec<FlowUser>,
    pub secret: Option<String>,
    pub fallback: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FlowUser {
    pub uuid: String,
    pub level: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FlowOutboundSettings {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub secret: Option<String>,
    /// FEC settings
    pub fec: Option<FecSettings>,
    /// Multiport settings for QUIC
    pub multiport: Option<MultiportConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HttpProxySettings {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HttpProxyOutboundSettings {
    pub address: String,
    pub port: u16,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Shadowsocks2022Settings {
    pub method: String,
    pub password: Option<String>,
    pub key: Option<String>,
    pub level: Option<u32>,
    pub email: Option<String>,
    pub network: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct Shadowsocks2022OutboundSettings {
    pub address: String,
    pub port: u16,
    pub method: String,
    pub password: Option<String>,
    pub key: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WireGuardSettings {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WireGuardPeer {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NaiveSettings {}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NaiveOutboundSettings {
    pub address: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RealityServerConfig {
    pub show: bool,
    pub dest: String,
    pub xver: u64,
    pub server_names: Vec<String>,
    pub private_key: String,
    pub min_client_ver: String,
    pub max_client_ver: String,
    pub max_time_diff: u64,
    pub short_ids: Vec<String>,
    /// Address of a domestic site to serve as a transparent proxy decoy
    /// for probing bots that fail the REALITY handshake.
    pub decoy_proxy_addr: Option<String>,
    pub mimic_settings: Option<DbMimicConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MqttTransportSettings {
    pub broker: String,
    pub upload_topic: String,
    pub download_topic: String,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub qos: u32,
    /// Intensity of Gaussian noise padding (0.0 to 1.0)
    #[serde(default = "default_noise_intensity")]
    pub noise_intensity: f64,
}

fn default_noise_intensity() -> f64 {
    0.0
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MultiportConfig {
    pub enabled: bool,
    /// Range of ports to use (e.g., "10000-20000")
    pub port_range: String,
    /// Frequency of port rotation in packets
    pub rotation_frequency: u32,
    /// Rotation strategy ("static" or "dynamic")
    pub strategy: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GrpcSettings {
    pub service_name: String,
    pub multi_mode: bool,
    pub idle_timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SplitHttpSettings {
    pub path: String,
    pub host: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SlipstreamConfig {
    pub resolver: String,    // DNS resolver IP
    pub domain: String,      // Tunnel domain
    pub record_type: String, // "A", "AAAA", or "TXT"
    pub mtu: Option<u16>,    // DNS payload MTU
    pub quic_enabled: bool,  // Enable QUIC-over-DNS
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct PaqetConfig {
    pub mtu: Option<u32>,
    pub tti: Option<u32>,
    pub uplink_capacity: Option<u32>,
    pub downlink_capacity: Option<u32>,
    pub congestion: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DbMimicConfig {
    pub protocol: String,              // "postgresql" or "redis"
    pub database: Option<String>,      // Fake database name
    pub user: Option<String>,          // Fake username
    pub password_hash: Option<String>, // MD5 hash for PostgreSQL
}

/// QUIC transport settings
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct QuicSettings {
    /// Security mode for QUIC header encryption ("none", "aes-128-gcm", "chacha20-poly1305")
    #[serde(default)]
    pub security: String,
    /// Key for header encryption
    #[serde(default)]
    pub key: Option<String>,
    /// QUIC packet header type for disguise ("none", "srtp", "utp", "wechat-video", "dtls", "wireguard")
    #[serde(default)]
    pub header: QuicHeaderConfig,
}

/// QUIC header disguise configuration
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct QuicHeaderConfig {
    /// Header type for packet disguise
    #[serde(default = "default_quic_header_type")]
    pub r#type: String,
}

fn default_quic_header_type() -> String {
    "none".to_string()
}

fn default_qos() -> u8 {
    0
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings {
    #[serde(default = "default_tcp_network")]
    pub network: String,
    #[serde(default = "default_none_security")]
    pub security: String,
    #[serde(default)]
    pub tls_settings: Option<TlsSettings>,
    #[serde(default)]
    pub kcp_settings: Option<KcpConfig>,
    #[serde(default)]
    pub ws_settings: Option<WebSocketConfig>,
    #[serde(default)]
    pub reality_settings: Option<RealityClientConfig>,
    #[serde(default)]
    pub reality_server_settings: Option<RealityServerConfig>,
    #[serde(default)]
    pub fragment_settings: Option<TlsFragmentSettings>,
    #[serde(default)]
    pub mqtt_settings: Option<MqttTransportSettings>,
    #[serde(default)]
    pub splithttp_settings: Option<SplitHttpSettings>,
    #[serde(default)]
    pub grpc_settings: Option<GrpcSettings>,
    #[serde(default)]
    pub quic_settings: Option<QuicSettings>,
    #[serde(default)]
    pub slipstream_settings: Option<SlipstreamConfig>,
    #[serde(default)]
    pub db_mimic_settings: Option<DbMimicConfig>,
    #[serde(default)]
    pub paqet_settings: Option<PaqetConfig>,
    #[serde(default)]
    pub multiport: Option<MultiportConfig>,
    #[serde(default)]
    pub fec: Option<FecSettings>,
}

fn default_tcp_network() -> String {
    "tcp".to_string()
}
fn default_none_security() -> String {
    "none".to_string()
}

pub fn load(path: &str) -> crate::error::Result<Config> {
    let file_content = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&file_content)?;
    config.validate().map_err(|e| anyhow::anyhow!(e))?;
    Ok(config)
}
