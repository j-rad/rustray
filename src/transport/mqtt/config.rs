// src/transport/mqtt/config.rs
//! Unified MQTT Broker Parser & Port-Sweep Configuration
//!
//! Handles mqtt://, mqtts://, ws://, wss:// URI schemes with dynamic
//! port resolution and multi-entry failover configuration.

use anyhow::anyhow;
use std::time::Duration;
use url::Url;

/// MQTT transport protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MqttProtocol {
    /// Plain MQTT (default port 1883).
    Mqtt,
    /// MQTT over TLS (default port 8883).
    Mqtts,
    /// MQTT over WebSocket (default port 80).
    Ws,
    /// MQTT over secure WebSocket (default port 443).
    Wss,
}

impl MqttProtocol {
    /// Default port for this protocol variant.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Mqtt => 1883,
            Self::Mqtts => 8883,
            Self::Ws => 80,
            Self::Wss => 443,
        }
    }

    /// Whether this variant requires TLS.
    pub fn requires_tls(self) -> bool {
        matches!(self, Self::Mqtts | Self::Wss)
    }

    /// Whether this variant uses WebSocket framing.
    pub fn is_websocket(self) -> bool {
        matches!(self, Self::Ws | Self::Wss)
    }

    /// ALPN protocol identifiers for TLS negotiation.
    pub fn alpn_protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Mqtts => vec![b"mqtt".to_vec()],
            Self::Wss => vec![b"mqtt".to_vec()],
            _ => Vec::new(),
        }
    }

    /// URI scheme string.
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Mqtt => "mqtt",
            Self::Mqtts => "mqtts",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }
}

/// A parsed MQTT broker endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MqttEndpoint {
    pub protocol: MqttProtocol,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
}

impl MqttEndpoint {
    /// Parse a broker URI string into an `MqttEndpoint`.
    ///
    /// Supported formats:
    /// - `mqtt://host:port`
    /// - `mqtts://host:port`
    /// - `ws://host:port/path`
    /// - `wss://host:port/path`
    /// - `host:port` (defaults to `mqtt://`)
    /// - `host` (defaults to `mqtt://host:1883`)
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s_with_scheme = if !s.contains("://") {
            format!("mqtt://{}", s)
        } else {
            s.to_string()
        };

        let url = Url::parse(&s_with_scheme)
            .map_err(|e| anyhow!("Failed to parse MQTT URI '{}': {}", s, e))?;

        let protocol = match url.scheme() {
            "mqtt" => MqttProtocol::Mqtt,
            "mqtts" => MqttProtocol::Mqtts,
            "ws" => MqttProtocol::Ws,
            "wss" => MqttProtocol::Wss,
            other => return Err(anyhow!("Unsupported MQTT protocol scheme: {}", other)),
        };

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("Missing host in MQTT URI"))?
            .to_string();

        let port = url.port().unwrap_or_else(|| protocol.default_port());

        let path = if (protocol.is_websocket()) && url.path() != "/" && !url.path().is_empty() {
            Some(url.path().to_string())
        } else {
            None
        };

        Ok(Self {
            protocol,
            host,
            port,
            path,
        })
    }

    /// Reconstruct the canonical URL string.
    pub fn to_url(&self) -> String {
        let scheme = self.protocol.scheme();
        if let Some(path) = &self.path {
            format!("{}://{}:{}{}", scheme, self.host, self.port, path)
        } else {
            format!("{}://{}:{}", scheme, self.host, self.port)
        }
    }

    /// Create a variant of this endpoint with a different protocol and port.
    pub fn with_protocol(&self, protocol: MqttProtocol) -> Self {
        Self {
            protocol,
            host: self.host.clone(),
            port: protocol.default_port(),
            path: if protocol.is_websocket() {
                self.path.clone().or_else(|| Some("/mqtt".to_string()))
            } else {
                None
            },
        }
    }
}

/// Port-sweep failover configuration.
///
/// Defines the ordered list of endpoints to attempt and the quality
/// thresholds that trigger a failover to the next entry.
#[derive(Debug, Clone)]
pub struct PortSweepConfig {
    /// Ordered list of endpoints to attempt (first = preferred).
    pub endpoints: Vec<MqttEndpoint>,
    /// Minimum acceptable throughput in bytes/sec before triggering failover.
    /// Default: 32 * 1024 (32 kbps as specified in the Phase 13 requirement).
    pub min_throughput_bps: u64,
    /// Maximum acceptable packet loss ratio (0.0–1.0) before triggering failover.
    /// Default: 0.50 (50% as specified in Phase 13).
    pub max_packet_loss_ratio: f64,
    /// Maximum time to wait for a single endpoint probe before declaring it dead.
    pub probe_timeout: Duration,
    /// Maximum total failover time before giving up entirely.
    pub total_failover_budget: Duration,
}

impl Default for PortSweepConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            min_throughput_bps: 32 * 1024,
            max_packet_loss_ratio: 0.50,
            probe_timeout: Duration::from_secs(3),
            total_failover_budget: Duration::from_secs(3),
        }
    }
}

impl PortSweepConfig {
    /// Build a default sweep chain from a single base endpoint.
    ///
    /// Order: MQTTS (8883) → WSS (443) → Plain MQTT (1883) → WS (80).
    pub fn from_base(base: &MqttEndpoint) -> Self {
        let endpoints = vec![
            base.with_protocol(MqttProtocol::Mqtts),
            base.with_protocol(MqttProtocol::Wss),
            base.with_protocol(MqttProtocol::Mqtt),
            base.with_protocol(MqttProtocol::Ws),
        ];
        Self {
            endpoints,
            ..Self::default()
        }
    }

    /// Build a sweep chain from a list of URI strings.
    pub fn from_uris(uris: &[&str]) -> anyhow::Result<Self> {
        let mut endpoints = Vec::with_capacity(uris.len());
        for uri in uris {
            endpoints.push(MqttEndpoint::parse(uri)?);
        }
        Ok(Self {
            endpoints,
            ..Self::default()
        })
    }
}

/// Result of probing a single endpoint for quality.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub endpoint: MqttEndpoint,
    pub throughput_bps: u64,
    pub packet_loss_ratio: f64,
    pub latency: Duration,
    pub success: bool,
}

impl ProbeResult {
    /// Check if this probe meets the quality thresholds.
    pub fn meets_thresholds(&self, config: &PortSweepConfig) -> bool {
        self.success
            && self.throughput_bps >= config.min_throughput_bps
            && self.packet_loss_ratio <= config.max_packet_loss_ratio
    }
}

/// Multi-port capability advertisement for the peer registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiPortCapability {
    /// All ports this peer can accept connections on.
    pub endpoints: Vec<MqttEndpoint>,
    /// Preferred endpoint (index into `endpoints`).
    pub preferred_idx: usize,
}

impl MultiPortCapability {
    /// Create from a list of endpoints, preferring the first.
    pub fn new(endpoints: Vec<MqttEndpoint>) -> Self {
        Self {
            endpoints,
            preferred_idx: 0,
        }
    }

    /// Get the preferred endpoint.
    pub fn preferred(&self) -> Option<&MqttEndpoint> {
        self.endpoints.get(self.preferred_idx)
    }

    /// Encode to bytes for wire transmission (peer registry advertisement).
    /// Format: [count:u8] [per-entry: protocol:u8 port:u16 host_len:u8 host:bytes]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.endpoints.len() as u8);
        buf.push(self.preferred_idx as u8);
        for ep in &self.endpoints {
            let proto_byte = match ep.protocol {
                MqttProtocol::Mqtt => 0,
                MqttProtocol::Mqtts => 1,
                MqttProtocol::Ws => 2,
                MqttProtocol::Wss => 3,
            };
            buf.push(proto_byte);
            buf.extend_from_slice(&ep.port.to_be_bytes());
            let host_bytes = ep.host.as_bytes();
            buf.push(host_bytes.len() as u8);
            buf.extend_from_slice(host_bytes);
        }
        buf
    }

    /// Decode from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let count = data[0] as usize;
        let preferred_idx = data[1] as usize;
        let mut offset = 2;
        let mut endpoints = Vec::with_capacity(count);

        for _ in 0..count {
            if offset + 4 > data.len() {
                return None;
            }
            let protocol = match data[offset] {
                0 => MqttProtocol::Mqtt,
                1 => MqttProtocol::Mqtts,
                2 => MqttProtocol::Ws,
                3 => MqttProtocol::Wss,
                _ => return None,
            };
            offset += 1;
            let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let host_len = data[offset] as usize;
            offset += 1;
            if offset + host_len > data.len() {
                return None;
            }
            let host = String::from_utf8(data[offset..offset + host_len].to_vec()).ok()?;
            offset += host_len;

            endpoints.push(MqttEndpoint {
                protocol,
                host,
                port,
                path: None,
            });
        }

        Some(Self {
            endpoints,
            preferred_idx,
        })
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mqtt_uri() {
        let ep = MqttEndpoint::parse("mqtt://broker.local:1883").unwrap();
        assert_eq!(ep.protocol, MqttProtocol::Mqtt);
        assert_eq!(ep.host, "broker.local");
        assert_eq!(ep.port, 1883);
        assert!(ep.path.is_none());
    }

    #[test]
    fn test_parse_mqtts_uri() {
        let ep = MqttEndpoint::parse("mqtts://secure.broker:8883").unwrap();
        assert_eq!(ep.protocol, MqttProtocol::Mqtts);
        assert_eq!(ep.port, 8883);
        assert!(ep.protocol.requires_tls());
    }

    #[test]
    fn test_parse_ws_uri_with_path() {
        let ep = MqttEndpoint::parse("ws://broker.local:80/mqtt").unwrap();
        assert_eq!(ep.protocol, MqttProtocol::Ws);
        assert_eq!(ep.port, 80);
        assert_eq!(ep.path.as_deref(), Some("/mqtt"));
        assert!(ep.protocol.is_websocket());
    }

    #[test]
    fn test_parse_wss_uri() {
        let ep = MqttEndpoint::parse("wss://broker.local/mqtt").unwrap();
        assert_eq!(ep.protocol, MqttProtocol::Wss);
        assert_eq!(ep.port, 443);
        assert!(ep.protocol.requires_tls());
        assert!(ep.protocol.is_websocket());
    }

    #[test]
    fn test_parse_bare_host() {
        let ep = MqttEndpoint::parse("broker.local").unwrap();
        assert_eq!(ep.protocol, MqttProtocol::Mqtt);
        assert_eq!(ep.host, "broker.local");
        assert_eq!(ep.port, 1883);
    }

    #[test]
    fn test_parse_host_port() {
        let ep = MqttEndpoint::parse("broker.local:9999").unwrap();
        assert_eq!(ep.protocol, MqttProtocol::Mqtt);
        assert_eq!(ep.port, 9999);
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(MqttProtocol::Mqtt.default_port(), 1883);
        assert_eq!(MqttProtocol::Mqtts.default_port(), 8883);
        assert_eq!(MqttProtocol::Ws.default_port(), 80);
        assert_eq!(MqttProtocol::Wss.default_port(), 443);
    }

    #[test]
    fn test_alpn_protocols() {
        assert!(MqttProtocol::Mqtt.alpn_protocols().is_empty());
        assert_eq!(MqttProtocol::Mqtts.alpn_protocols(), vec![b"mqtt".to_vec()]);
    }

    #[test]
    fn test_to_url_roundtrip() {
        let ep = MqttEndpoint::parse("mqtts://broker.local:8883").unwrap();
        assert_eq!(ep.to_url(), "mqtts://broker.local:8883");

        let ep2 = MqttEndpoint::parse("wss://broker.local:443/mqtt").unwrap();
        assert_eq!(ep2.to_url(), "wss://broker.local:443/mqtt");
    }

    #[test]
    fn test_with_protocol() {
        let base = MqttEndpoint::parse("mqtt://broker.local:1883").unwrap();
        let mqtts = base.with_protocol(MqttProtocol::Mqtts);
        assert_eq!(mqtts.protocol, MqttProtocol::Mqtts);
        assert_eq!(mqtts.port, 8883);
        assert_eq!(mqtts.host, "broker.local");
    }

    #[test]
    fn test_port_sweep_from_base() {
        let base = MqttEndpoint::parse("mqtt://broker.local").unwrap();
        let sweep = PortSweepConfig::from_base(&base);
        assert_eq!(sweep.endpoints.len(), 4);
        assert_eq!(sweep.endpoints[0].protocol, MqttProtocol::Mqtts);
        assert_eq!(sweep.endpoints[1].protocol, MqttProtocol::Wss);
        assert_eq!(sweep.endpoints[2].protocol, MqttProtocol::Mqtt);
        assert_eq!(sweep.endpoints[3].protocol, MqttProtocol::Ws);
    }

    #[test]
    fn test_probe_result_thresholds() {
        let config = PortSweepConfig::default();
        let good = ProbeResult {
            endpoint: MqttEndpoint::parse("mqtt://x").unwrap(),
            throughput_bps: 100_000,
            packet_loss_ratio: 0.01,
            latency: Duration::from_millis(50),
            success: true,
        };
        assert!(good.meets_thresholds(&config));

        let throttled = ProbeResult {
            endpoint: MqttEndpoint::parse("mqtt://x").unwrap(),
            throughput_bps: 1_000,
            packet_loss_ratio: 0.01,
            latency: Duration::from_millis(50),
            success: true,
        };
        assert!(!throttled.meets_thresholds(&config));

        let lossy = ProbeResult {
            endpoint: MqttEndpoint::parse("mqtt://x").unwrap(),
            throughput_bps: 100_000,
            packet_loss_ratio: 0.60,
            latency: Duration::from_millis(50),
            success: true,
        };
        assert!(!lossy.meets_thresholds(&config));
    }

    #[test]
    fn test_multi_port_capability_roundtrip() {
        let cap = MultiPortCapability::new(vec![
            MqttEndpoint::parse("mqtt://broker:1883").unwrap(),
            MqttEndpoint::parse("mqtts://broker:8883").unwrap(),
            MqttEndpoint::parse("wss://broker:443").unwrap(),
        ]);
        let bytes = cap.to_bytes();
        let decoded = MultiPortCapability::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.endpoints.len(), 3);
        assert_eq!(decoded.preferred_idx, 0);
        assert_eq!(decoded.endpoints[0].port, 1883);
        assert_eq!(decoded.endpoints[1].port, 8883);
        assert_eq!(decoded.endpoints[2].port, 443);
    }

    #[test]
    fn test_unsupported_scheme() {
        assert!(MqttEndpoint::parse("ftp://host").is_err());
    }
}
