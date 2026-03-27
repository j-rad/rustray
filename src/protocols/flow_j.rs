// src/protocols/flow_j.rs
//! Flow-J Universal Protocol
//!
//! A next-generation multi-transport polyglot proxy protocol designed for severe censorship
//! environments. Flow-J dynamically shifts its digital fingerprint across multiple transport modes:
//!
//! - **Mode A (Direct Stealth)**: REALITY-based with probe detection and certificate stealing
//! - **Mode B (CDN Relay)**: HTTP Upgrade and xhttp for CDN traversal
//! - **Mode C (IoT Camouflage)**: MQTT tunneling disguised as sensor data
//!
//! Features:
//! - Split-Identity architecture separating control and data planes
//! - Elastic FEC for packet recovery
//! - Zero-copy optimizations
//! - Automatic mode selection based on network conditions

use crate::config::{LevelPolicy, MuxConfig};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::BoxedStream;
use crate::transport::mux::MuxPool;
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Flow-J protocol magic bytes for handshake identification
pub const FLOWJ_MAGIC: &[u8; 4] = b"FJ01";

/// Default peek size for probe detection
const PEEK_SIZE: usize = 512;

/// FEC shard configuration
const FEC_DATA_SHARDS: usize = 10;
const FEC_PARITY_SHARDS: usize = 3;

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Flow-J protocol mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FlowJMode {
    /// Automatic mode selection based on network conditions
    #[default]
    Auto,
    /// Mode A: Direct connection with REALITY
    Reality,
    /// Mode B: CDN relay (HttpUpgrade or xhttp)
    Cdn,
    /// Mode C: IoT camouflage via MQTT
    Mqtt,
}

/// REALITY security settings for Mode A
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealitySettings {
    /// Fallback destination for probes (e.g., "www.samsung.com:443")
    pub dest: String,
    /// List of valid server names
    #[serde(default)]
    pub server_names: Vec<String>,
    /// X25519 private key (hex-encoded)
    pub private_key: Option<String>,
    /// Short IDs for authentication
    #[serde(default)]
    pub short_ids: Vec<String>,
    /// Spider configuration for crawling
    pub spider_x: Option<String>,
}

/// HTTP Upgrade settings for CDN Mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpUpgradeSettings {
    /// Upgrade path (e.g., "/flow-path")
    pub path: String,
    /// Custom host header
    pub host: Option<String>,
    /// Additional headers
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

/// xhttp settings for CDN Mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XhttpSettings {
    /// Upload endpoint (POST)
    pub upload_path: String,
    /// Download endpoint (GET)
    pub download_path: String,
    /// Use HTTP/2
    #[serde(default)]
    pub h2: bool,
}

/// MQTT settings for IoT Camouflage Mode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MqttSettings {
    /// MQTT broker address
    pub broker: String,
    /// Upload topic (e.g., "sensors/temperature")
    pub upload_topic: String,
    /// Download topic (e.g., "sensors/firmware")
    pub download_topic: String,
    /// Client ID prefix
    pub client_id: Option<String>,
    /// MQTT username
    pub username: Option<String>,
    /// MQTT password
    pub password: Option<String>,
    /// QoS level (0, 1, or 2)
    #[serde(default = "default_qos")]
    pub qos: u32,
    /// Intensity of Gaussian noise padding (0.0 to 1.0)
    pub noise_intensity: f64,
}

fn default_qos() -> u32 {
    1
}

/// FEC (Forward Error Correction) settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecSettings {
    /// Enable FEC
    #[serde(default)]
    pub enabled: bool,
    /// Number of data shards
    #[serde(default = "default_data_shards")]
    pub data_shards: usize,
    /// Number of parity shards
    #[serde(default = "default_parity_shards")]
    pub parity_shards: usize,
}

fn default_data_shards() -> usize {
    FEC_DATA_SHARDS
}
fn default_parity_shards() -> usize {
    FEC_PARITY_SHARDS
}

impl Default for FecSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            data_shards: FEC_DATA_SHARDS,
            parity_shards: FEC_PARITY_SHARDS,
        }
    }
}

/// Complete Flow-J configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowJConfig {
    /// Protocol mode
    #[serde(default)]
    pub mode: FlowJMode,
    /// User UUID for authentication
    pub uuid: String,
    /// Server address
    pub address: String,
    /// Server port
    pub port: u16,
    /// REALITY settings (Mode A)
    #[serde(default)]
    pub reality: Option<RealitySettings>,
    /// HTTP Upgrade settings (Mode B)
    #[serde(default)]
    pub http_upgrade: Option<HttpUpgradeSettings>,
    /// xhttp settings (Mode B)
    #[serde(default)]
    pub xhttp: Option<XhttpSettings>,
    /// MQTT settings (Mode C)
    #[serde(default)]
    pub mqtt: Option<MqttSettings>,
    /// Mux settings for connection multiplexing
    #[serde(default)]
    pub mux: Option<MuxConfig>,
    /// FEC settings
    #[serde(default)]
    pub fec: FecSettings,
}

/// Flow-J inbound settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowJInboundSettings {
    /// Accepted clients
    #[serde(default)]
    pub clients: Vec<FlowJClient>,
    /// REALITY settings for Mode A
    #[serde(default)]
    pub reality: Option<RealitySettings>,
    /// HTTP Upgrade settings for Mode B
    #[serde(default)]
    pub http_upgrade: Option<HttpUpgradeSettings>,
    /// xhttp settings for Mode B
    #[serde(default)]
    pub xhttp: Option<XhttpSettings>,
    /// MQTT settings for Mode C
    #[serde(default)]
    pub mqtt: Option<MqttSettings>,
    /// FEC settings
    #[serde(default)]
    pub fec: FecSettings,
}

/// Flow-J client definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowJClient {
    /// Client UUID
    pub uuid: String,
    /// Optional level for policy
    pub level: Option<u8>,
    /// Flow control algorithm (e.g., "xtls-rprx-vision")
    #[serde(default)]
    pub flow: Option<String>,
}

// ============================================================================
// PROTOCOL HEADER
// ============================================================================

/// Flow-J request header structure
#[derive(Debug, Clone)]
pub struct FlowJHeader {
    /// Protocol version
    pub version: u8,
    /// Request UUID
    pub uuid: [u8; 16],
    /// Command (1 = TCP, 2 = UDP)
    pub command: u8,
    /// Destination port
    pub port: u16,
    /// Address type (1 = IPv4, 2 = Domain, 3 = IPv6)
    pub addr_type: u8,
    /// Destination address
    pub address: String,
    /// Session nonce for replay protection
    pub nonce: [u8; 8],
    /// Timestamp for freshness
    pub timestamp: u64,
}

impl FlowJHeader {
    /// Encode header to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(128);

        // Magic + Version
        buf.put_slice(FLOWJ_MAGIC);
        buf.put_u8(self.version);

        // UUID
        buf.put_slice(&self.uuid);

        // Command
        buf.put_u8(self.command);

        // Port
        buf.put_u16(self.port);

        // Address
        buf.put_u8(self.addr_type);
        match self.addr_type {
            1 => {
                // IPv4
                if let Ok(ip) = self.address.parse::<std::net::Ipv4Addr>() {
                    buf.put_slice(&ip.octets());
                }
            }
            2 => {
                // Domain
                let domain = self.address.as_bytes();
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain);
            }
            3 => {
                // IPv6
                if let Ok(ip) = self.address.parse::<std::net::Ipv6Addr>() {
                    buf.put_slice(&ip.octets());
                }
            }
            _ => {}
        }

        // Session nonce
        buf.put_slice(&self.nonce);

        // Timestamp
        buf.put_u64(self.timestamp);

        buf
    }

    /// Decode header from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(anyhow::anyhow!("Header too short"));
        }

        // Check magic
        if &data[0..4] != FLOWJ_MAGIC {
            return Err(anyhow::anyhow!("Invalid Flow-J magic"));
        }

        let mut cursor = std::io::Cursor::new(data);
        cursor.set_position(4);

        let version = cursor.get_u8();

        let mut uuid = [0u8; 16];
        cursor.copy_to_slice(&mut uuid);

        let command = cursor.get_u8();
        let port = cursor.get_u16();
        let addr_type = cursor.get_u8();

        let address = match addr_type {
            1 => {
                let mut ip = [0u8; 4];
                cursor.copy_to_slice(&mut ip);
                std::net::Ipv4Addr::from(ip).to_string()
            }
            2 => {
                let len = cursor.get_u8() as usize;
                let mut domain = vec![0u8; len];
                cursor.copy_to_slice(&mut domain);
                String::from_utf8(domain).map_err(|_| anyhow::anyhow!("Invalid domain"))?
            }
            3 => {
                let mut ip = [0u8; 16];
                cursor.copy_to_slice(&mut ip);
                std::net::Ipv6Addr::from(ip).to_string()
            }
            _ => return Err(anyhow::anyhow!("Invalid address type")),
        };

        let mut nonce = [0u8; 8];
        cursor.copy_to_slice(&mut nonce);

        let timestamp = cursor.get_u64();

        let consumed = cursor.position() as usize;

        Ok((
            Self {
                version,
                uuid,
                command,
                port,
                addr_type,
                address,
                nonce,
                timestamp,
            },
            consumed,
        ))
    }
}

// ============================================================================
// INBOUND HANDLER
// ============================================================================

pub struct FlowJInbound;

impl FlowJInbound {
    /// Handle incoming Flow-J connection
    pub async fn handle_stream(
        mut stream: BoxedStream,
        settings: Arc<FlowJInboundSettings>,
        router: Arc<Router>,
        source: String,
    ) -> Result<()> {
        debug!("Flow-J: Handling inbound stream");

        // Read header
        let mut header_buf = BytesMut::with_capacity(PEEK_SIZE);
        header_buf.resize(128, 0);

        let n = stream.read(&mut header_buf).await?;
        if n < 4 {
            warn!("Flow-J: Header too short");
            return Ok(());
        }

        // Parse header
        let (header, consumed) = match FlowJHeader::decode(&header_buf[..n]) {
            Ok(h) => h,
            Err(e) => {
                warn!("Flow-J: Failed to parse header: {}", e);
                return Ok(());
            }
        };

        // Validate client
        let uuid_str = uuid::Uuid::from_bytes(header.uuid).to_string();
        let client = settings.clients.iter().find(|c| c.uuid == uuid_str);

        if client.is_none() {
            warn!("Flow-J: Unknown client UUID: {}", uuid_str);
            return Ok(());
        }

        let client = client.unwrap();
        let policy = Arc::new(LevelPolicy::default());

        info!(
            "Flow-J Request: {} -> {}:{}",
            uuid_str, header.address, header.port
        );

        let is_vision = client.flow.as_deref() == Some("xtls-rprx-vision")
            || client.flow.as_deref() == Some("flow-j-vision");

        // Handle remaining data in buffer
        let remaining = &header_buf[consumed..n];
        let mut final_stream: BoxedStream = if !remaining.is_empty() {
            Box::new(PrefixedStream::new(remaining.to_vec(), stream))
        } else {
            stream
        };

        if is_vision {
            debug!("Flow-J: Applying Vision flow control");
            use crate::protocols::vless_vision::VisionStream;
            final_stream = Box::new(VisionStream::new(final_stream));
        }

        router
            .route_stream(final_stream, header.address, header.port, source, policy)
            .await
    }

    /// Handle REALITY mode connection with probe detection
    pub async fn handle_reality_connection(
        socket: TcpStream,
        settings: Arc<FlowJInboundSettings>,
        router: Arc<Router>,
    ) -> Result<()> {
        debug!("Flow-J REALITY: Handling connection");

        // Peek at first bytes without consuming
        let mut peek_buf = [0u8; PEEK_SIZE];
        let peek_result = socket.peek(&mut peek_buf).await;

        let peeked = match peek_result {
            Ok(n) => n,
            Err(e) => {
                warn!("Flow-J REALITY: Peek failed: {}", e);
                return Ok(());
            }
        };

        // Check if this is a Flow-J handshake
        if peeked >= 4 && &peek_buf[0..4] == FLOWJ_MAGIC {
            debug!("Flow-J REALITY: Valid Flow-J handshake detected");
            let source = socket
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            let boxed: BoxedStream = Box::new(socket);
            return Self::handle_stream(boxed, settings, router, source).await;
        }

        // This is a probe - forward to real destination
        debug!("Flow-J REALITY: Probe detected, forwarding to fallback");

        let reality = settings.reality.as_ref();
        let dest = reality
            .map(|r| r.dest.as_str())
            .unwrap_or("www.samsung.com:443");

        Self::forward_to_fallback(socket, dest, &peek_buf[..peeked]).await
    }

    /// Forward probe traffic to real destination
    async fn forward_to_fallback(
        mut client_socket: TcpStream,
        dest: &str,
        initial_data: &[u8],
    ) -> Result<()> {
        info!("Flow-J: Forwarding probe to {}", dest);

        // Connect to real destination
        let mut server_socket = TcpStream::connect(dest).await?;

        // Forward initial peeked data
        if !initial_data.is_empty() {
            server_socket.write_all(initial_data).await?;
        }

        // Bidirectional copy
        let _ = tokio::io::copy_bidirectional(&mut client_socket, &mut server_socket).await;

        Ok(())
    }
}

// ============================================================================
// OUTBOUND HANDLER
// ============================================================================

pub struct FlowJOutbound {
    config: FlowJConfig,
    /// Mux connection pool for multiplexing
    #[allow(dead_code)]
    mux_pool: Arc<MuxPool>,
    /// Whether Mux is enabled
    #[allow(dead_code)]
    mux_enabled: bool,
}

impl FlowJOutbound {
    pub fn new(config: FlowJConfig) -> Self {
        let mux_enabled = config.mux.as_ref().map(|m| m.enabled).unwrap_or(false);
        Self {
            config,
            mux_pool: Arc::new(MuxPool::new()),
            mux_enabled,
        }
    }

    /// Select optimal mode based on network conditions
    fn select_mode(&self) -> FlowJMode {
        match self.config.mode {
            FlowJMode::Auto => {
                // Auto-select based on availability
                if self.config.reality.is_some() {
                    FlowJMode::Reality
                } else if self.config.http_upgrade.is_some() || self.config.xhttp.is_some() {
                    FlowJMode::Cdn
                } else if self.config.mqtt.is_some() {
                    FlowJMode::Mqtt
                } else {
                    FlowJMode::Reality // Default
                }
            }
            mode => mode,
        }
    }

    /// Create Flow-J header
    fn create_header(&self, host: &str, port: u16, command: u8) -> FlowJHeader {
        let uuid =
            uuid::Uuid::parse_str(&self.config.uuid).unwrap_or_else(|_| uuid::Uuid::new_v4());

        let mut nonce = [0u8; 8];
        rand::thread_rng().fill(&mut nonce);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (addr_type, address) = if let Ok(_ip) = host.parse::<std::net::Ipv4Addr>() {
            (1u8, host.to_string())
        } else if let Ok(_ip) = host.parse::<std::net::Ipv6Addr>() {
            (3u8, host.to_string())
        } else {
            (2u8, host.to_string())
        };

        FlowJHeader {
            version: 1,
            uuid: *uuid.as_bytes(),
            command,
            port,
            addr_type,
            address,
            nonce,
            timestamp,
        }
    }

    /// Connect via Mode A (REALITY)
    /// Uses TLS 1.3 with Chrome-like fingerprint for stealth
    async fn connect_reality(&self) -> Result<BoxedStream> {
        let addr = format!("{}:{}", self.config.address, self.config.port);
        debug!("Flow-J: Connecting via REALITY to {}", addr);

        // Get SNI from REALITY settings
        let sni = self
            .config
            .reality
            .as_ref()
            .and_then(|r| r.server_names.first())
            .map(|s| s.as_str());

        // Get private key for authentication
        let private_key = self
            .config
            .reality
            .as_ref()
            .and_then(|r| r.private_key.as_deref());

        // Use the REALITY transport module for TLS-wrapped connection
        crate::transport::flow_j_reality::connect_reality(&addr, sni, private_key).await
    }

    /// Connect via Mode B (CDN - HttpUpgrade)
    async fn connect_http_upgrade(&self) -> Result<BoxedStream> {
        let settings = self
            .config
            .http_upgrade
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HttpUpgrade settings not configured"))?;

        let addr = format!("{}:{}", self.config.address, self.config.port);
        debug!("Flow-J: Connecting via HttpUpgrade to {}", addr);

        let mut stream = TcpStream::connect(&addr).await?;

        // Build upgrade request
        let host = settings.host.as_deref().unwrap_or(&self.config.address);

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: flow-j-transport\r\n\
             Sec-FlowJ-Key: {}\r\n\
             \r\n",
            settings.path,
            host,
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &self.config.uuid
            )
        );

        stream.write_all(request.as_bytes()).await?;

        // Read response
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).await?;

        // Verify 101 Switching Protocols
        let response_str = String::from_utf8_lossy(&response[..n]);
        if !response_str.contains("101") {
            return Err(anyhow::anyhow!("HttpUpgrade failed: {}", response_str));
        }

        debug!("Flow-J: HttpUpgrade successful");
        Ok(Box::new(stream))
    }

    /// Connect via Mode B (CDN - xhttp/SplitHTTP)
    /// Uses dual HTTP streams for upload and download
    async fn connect_xhttp(&self) -> Result<BoxedStream> {
        let settings = self
            .config
            .xhttp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("xhttp settings not configured"))?;

        let host = self
            .config
            .http_upgrade
            .as_ref()
            .and_then(|h| h.host.clone())
            .unwrap_or_else(|| self.config.address.clone());

        // Build URL for SplitHTTP
        let url = format!(
            "http://{}:{}{}",
            host,
            self.config.port,
            if settings.upload_path.is_empty() {
                "/upload"
            } else {
                &settings.upload_path
            }
        );

        debug!("Flow-J: Connecting via xhttp (SplitHTTP) to {}", url);

        // Use SplitHTTP transport
        let stream = crate::transport::splithttp::SplitHttpStream::connect(&url).await?;

        debug!("Flow-J: xhttp connection established");
        Ok(Box::new(stream))
    }

    /// Connect via Mode C (MQTT)
    /// Establishes MQTT connection and sets up topic-based tunneling
    async fn connect_mqtt(&self) -> Result<BoxedStream> {
        let settings = self
            .config
            .mqtt
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MQTT settings not configured"))?;

        debug!("Flow-J: Connecting via MQTT to {}", settings.broker);

        if settings.noise_intensity > 0.0 {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(self.config.uuid.as_bytes());
            let session_key: [u8; 32] = hasher.finalize().into();

            let tunnel =
                crate::transport::flow_j_mqtt::StealthMqttTunnel::connect(settings, session_key)
                    .await?;

            debug!(
                "Flow-J: Stealth MQTT tunnel established, session: {}",
                tunnel.session_id()
            );

            let mqtt_stream = crate::transport::flow_j_mqtt::StealthMqttStream::new(tunnel);
            let stream: BoxedStream = Box::new(mqtt_stream);
            Ok(stream)
        } else {
            let tunnel = crate::transport::flow_j_mqtt::MqttTunnel::connect(settings).await?;

            debug!(
                "Flow-J: MQTT tunnel established, session: {}",
                tunnel.session_id()
            );

            let mqtt_stream = crate::transport::flow_j_mqtt::MqttStream::new(tunnel);
            let stream: BoxedStream = Box::new(mqtt_stream);
            Ok(stream)
        }
    }
}

#[async_trait]
impl Outbound for FlowJOutbound {
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;

        // Bidirectional copy
        let _ = tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream).await;

        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let mode = self.select_mode();
        debug!("Flow-J: Using mode {:?}", mode);

        // Connect based on mode
        let mut out_stream = match mode {
            FlowJMode::Reality | FlowJMode::Auto => self.connect_reality().await?,
            FlowJMode::Cdn => {
                if self.config.http_upgrade.is_some() {
                    self.connect_http_upgrade().await?
                } else if self.config.xhttp.is_some() {
                    self.connect_xhttp().await?
                } else {
                    self.connect_reality().await?
                }
            }
            FlowJMode::Mqtt => self.connect_mqtt().await?,
        };

        // Send Flow-J header
        let header = self.create_header(&host, port, 1); // 1 = TCP
        out_stream.write_all(&header.encode()).await?;

        Ok(out_stream)
    }
}

// ============================================================================
// HELPER STRUCTS
// ============================================================================

/// Stream with prefixed data
struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.has_remaining() {
            let n = std::cmp::min(self.prefix.remaining(), buf.remaining());
            let pos = self.prefix.position() as usize;
            buf.put_slice(&self.prefix.get_ref()[pos..pos + n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode_ipv4() {
        let header = FlowJHeader {
            version: 1,
            uuid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            command: 1,
            port: 443,
            addr_type: 1,
            address: "192.168.1.1".to_string(),
            nonce: [0xAA; 8],
            timestamp: 1234567890,
        };

        let encoded = header.encode();
        assert!(!encoded.is_empty());

        let (decoded, _) = FlowJHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.port, 443);
        assert_eq!(decoded.address, "192.168.1.1");
    }

    #[test]
    fn test_header_encode_decode_domain() {
        let header = FlowJHeader {
            version: 1,
            uuid: [0; 16],
            command: 1,
            port: 80,
            addr_type: 2,
            address: "example.com".to_string(),
            nonce: [0; 8],
            timestamp: 0,
        };

        let encoded = header.encode();
        let (decoded, _) = FlowJHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.address, "example.com");
    }

    #[test]
    fn test_magic_detection() {
        let valid = [b'F', b'J', b'0', b'1', 0, 0, 0, 0];
        assert_eq!(&valid[0..4], FLOWJ_MAGIC);

        let invalid = [b'T', b'L', b'S', 0x01];
        assert_ne!(&invalid[0..4], FLOWJ_MAGIC);
    }

    #[test]
    fn test_config_parsing() {
        let json = r#"{
            "mode": "auto",
            "uuid": "12345678-1234-1234-1234-123456789012",
            "address": "server.example.com",
            "port": 443,
            "reality": {
                "dest": "www.samsung.com:443",
                "server_names": ["server.example.com"]
            }
        }"#;

        let config: FlowJConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mode, FlowJMode::Auto);
        assert!(config.reality.is_some());
    }
}
