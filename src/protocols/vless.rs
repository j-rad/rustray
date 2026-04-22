// src/protocols/vless.rs
use crate::app::dns::DnsServer; // Added
use crate::app::stats::StatsManager;
use crate::config::LevelPolicy;
use crate::config::{MuxConfig, StreamSettings, VlessOutboundSettings, VlessSettings};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::protocols::error::{VlessError, VlessResult};
use crate::router::Router;
use crate::transport::BoxedStream;
use crate::transport::mux::{MuxPool, accept_mux_connection};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use lru::LruCache;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use uuid::Uuid;

// --- Constants ---
const VERSION: u8 = 0;

// Addon Types
const ADDON_TYPE_GLOBAL_PADDING: u8 = 0x01;
const ADDON_TYPE_APP_DATA: u8 = 0x02;
const ADDON_TYPE_RANDOM_PADDING: u8 = 0x03;
const ADDON_TYPE_SESSION_METADATA: u8 = 0x04;

// VLESS Commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 1,
    Udp = 2,
}

impl VlessCommand {
    pub fn from_u8(val: u8) -> VlessResult<Self> {
        match val {
            1 => Ok(VlessCommand::Tcp),
            2 => Ok(VlessCommand::Udp),
            _ => Err(VlessError::InvalidCommand(val)),
        }
    }
}

// --- Additional Info (Addons) ---
#[derive(Debug, Clone)]
pub struct AddonInfo {
    pub addon_type: u8,
    pub data: Vec<u8>,
}

impl AddonInfo {
    /// Parse addons from raw bytes
    pub fn parse_addons(mut data: &[u8]) -> VlessResult<Vec<AddonInfo>> {
        let mut addons = Vec::new();

        while !data.is_empty() {
            if data.len() < 2 {
                return Err(VlessError::InvalidAddonType(0));
            }

            let addon_type = data[0];
            let addon_len = data[1] as usize;

            if data.len() < 2 + addon_len {
                return Err(VlessError::AddonTooLarge(addon_len));
            }

            let addon_data = data[2..2 + addon_len].to_vec();
            addons.push(AddonInfo {
                addon_type,
                data: addon_data,
            });

            data = &data[2 + addon_len..];
        }

        Ok(addons)
    }

    /// Check if addons contain Mux request
    pub fn has_mux(addons: &[AddonInfo]) -> bool {
        // Mux is typically indicated by session metadata addon
        addons
            .iter()
            .any(|a| a.addon_type == ADDON_TYPE_SESSION_METADATA)
    }

    /// Serialize addons to bytes
    pub fn serialize_addons(addons: &[AddonInfo]) -> Vec<u8> {
        let mut buf = Vec::new();
        for addon in addons {
            buf.push(addon.addon_type);
            buf.push(addon.data.len() as u8);
            buf.extend_from_slice(&addon.data);
        }
        buf
    }
}

// --- Replay Cache (Validator) ---
struct Validator {
    cache: Mutex<LruCache<[u8; 16], ()>>,
}

impl Validator {
    #[allow(dead_code)]
    fn new(capacity: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
        }
    }

    #[allow(dead_code)]
    fn check_replay(&self, nonce: &[u8; 16]) -> bool {
        let mut cache = self.cache.lock().unwrap();
        if cache.contains(nonce) {
            return false; // Replay detected
        }
        cache.put(*nonce, ());
        true
    }
}

// --- INBOUND ---

pub async fn listen_stream(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    stream: BoxedStream,
    settings: VlessSettings,
    source: String,
) -> Result<()> {
    debug!("VLESS: Handling new stream from {}", source);
    let settings = Arc::new(settings);
    handle_inbound(router, state, stream, &settings, source).await
}

/// Handle UDP relay for VLESS protocol
/// UDP packets are framed as: [2 bytes length] [address type] [address] [2 bytes port] [UDP payload]
async fn handle_udp_relay(
    mut stream: BoxedStream,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    // Bind UDP socket
    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let local_addr = udp_socket.local_addr()?;
    debug!("VLESS UDP: Bound to {}", local_addr);

    // Resolve target address
    let target_addr = format!("{}:{}", target_host, target_port);
    debug!("VLESS UDP: Target address: {}", target_addr);

    // Create channels for communication
    let (to_udp_tx, mut to_udp_rx) = mpsc::channel::<Vec<u8>>(32);
    let (from_udp_tx, mut from_udp_rx) = mpsc::channel::<Vec<u8>>(32);

    // Task to send packets to UDP
    let udp_send = udp_socket.clone();
    let target_addr_clone = target_addr.clone();
    tokio::spawn(async move {
        while let Some(payload) = to_udp_rx.recv().await {
            if let Err(e) = udp_send.send_to(&payload, &target_addr_clone).await {
                warn!("VLESS UDP: Send error: {}", e);
                break;
            }
        }
    });

    // Task to receive packets from UDP
    let udp_recv = udp_socket.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match udp_recv.recv_from(&mut buf).await {
                Ok((len, _src_addr)) => {
                    if from_udp_tx.send(buf[..len].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("VLESS UDP: Receive error: {}", e);
                    break;
                }
            }
        }
    });

    // Main loop: read from stream and write to stream
    loop {
        tokio::select! {
            // Read from stream
            result = async {
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let packet_len = u16::from_be_bytes(len_buf) as usize;

                if packet_len == 0 || packet_len > 65535 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid packet length"));
                }

                let mut packet = vec![0u8; packet_len];
                stream.read_exact(&mut packet).await?;

                // Extract payload (skip address header)
                let payload_start = if packet.len() > 7 { 7 } else { 0 };
                let payload = packet[payload_start..].to_vec();

                Ok::<Vec<u8>, std::io::Error>(payload)
            } => {
                match result {
                    Ok(payload) => {
                        if to_udp_tx.send(payload).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            // Write to stream
            Some(payload) = from_udp_rx.recv() => {
                let mut frame = BytesMut::new();
                let total_len = 1 + 4 + 2 + payload.len();
                frame.put_u16(total_len as u16);
                frame.put_u8(1); // IPv4
                frame.put_u32(0); // 0.0.0.0
                frame.put_u16(0); // port 0
                frame.put_slice(&payload);

                if stream.write_all(&frame).await.is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}

pub async fn handle_inbound(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    mut stream: BoxedStream,
    settings: &VlessSettings,
    source: String,
) -> Result<()> {
    debug!("VLESS: Handling new stream");
    // 1. Read Header
    let mut header_buf = [0u8; 1 + 16 + 1]; // Version + UUID + AddonsLen

    if let Err(e) = stream.read_exact(&mut header_buf).await {
        debug!("VLESS: Failed to read header: {}", e);
        return Err(e.into());
    }

    let ver = header_buf[0];
    debug!("VLESS: Received version: {}", ver);
    if ver != VERSION {
        // Fallback Logic
        if let Some(fallbacks) = &settings.fallbacks
            && let Some(fb) = fallbacks
                .iter()
                .find(|f| f.alpn.is_none() && f.path.is_none())
            {
                let dest = &fb.dest;
                return pipe_to_fallback(stream, dest, Some(&header_buf)).await;
            }
        return Err(VlessError::InvalidVersion(ver).into());
    }

    let uuid_bytes: [u8; 16] = header_buf[1..17].try_into().unwrap();
    debug!("VLESS: UUID bytes received: {:?}", uuid_bytes);

    // Validate User (Constant Time)
    let user = settings.clients.iter().find(|c| {
        if let Ok(id) = Uuid::parse_str(&c.id) {
            id.as_bytes().ct_eq(&uuid_bytes).into()
        } else {
            false
        }
    });

    debug!("VLESS: User found: {}", user.is_some());
    if user.is_none() {
        if let Some(fallbacks) = &settings.fallbacks
            && let Some(fb) = fallbacks
                .iter()
                .find(|f| f.alpn.is_none() && f.path.is_none())
            {
                return pipe_to_fallback(stream, &fb.dest, Some(&header_buf)).await;
            }
        return Err(VlessError::UnknownClient.into());
    }

    let user = user.unwrap();
    
    // Record online IP
    if let Some(ref email) = user.email {
        state.record_online_ip(email, source.clone());
    }

    let client_id = Uuid::from_bytes(uuid_bytes);
    let user_level = user.level.unwrap_or(0);
    let policy = state.policy_manager.get_policy(user_level);

    // Parse addons
    let addons_len = header_buf[17] as usize;
    let addons = if addons_len > 0 {
        if addons_len > 255 {
            return Err(VlessError::AddonTooLarge(addons_len).into());
        }
        let mut addon_bytes = vec![0u8; addons_len];
        stream.read_exact(&mut addon_bytes).await?;

        let parsed_addons = AddonInfo::parse_addons(&addon_bytes)?;
        debug!("VLESS: Parsed {} addons", parsed_addons.len());

        // Check if Mux is requested
        if AddonInfo::has_mux(&parsed_addons) {
            debug!("VLESS: Mux addon detected, upgrading to Yamux");
            let response = [VERSION, 0];
            stream.write_all(&response).await?;
            return accept_mux_connection(stream, router, policy).await;
        }

        Some(parsed_addons)
    } else {
        None
    };

    // Log addon types for debugging
    if let Some(ref addons) = addons {
        for addon in addons {
            match addon.addon_type {
                ADDON_TYPE_GLOBAL_PADDING => debug!("VLESS: Global padding addon"),
                ADDON_TYPE_APP_DATA => debug!("VLESS: App data addon (REALITY)"),
                ADDON_TYPE_RANDOM_PADDING => debug!("VLESS: Random padding addon"),
                ADDON_TYPE_SESSION_METADATA => debug!("VLESS: Session metadata addon"),
                _ => debug!("VLESS: Unknown addon type: {}", addon.addon_type),
            }
        }
    }

    // Parse command and address
    let mut cmd_buf = [0u8; 1 + 2 + 1];
    stream.read_exact(&mut cmd_buf).await?;
    let cmd = VlessCommand::from_u8(cmd_buf[0])?;
    let port = u16::from_be_bytes([cmd_buf[1], cmd_buf[2]]);
    let addr_type = cmd_buf[3];

    let host = match addr_type {
        1 => {
            // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            Ipv4Addr::from(buf).to_string()
        }
        2 => {
            // Domain
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf).map_err(|_| VlessError::InvalidDomainEncoding)?
        }
        3 => {
            // IPv6
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            Ipv6Addr::from(buf).to_string()
        }
        _ => return Err(VlessError::InvalidAddressType(addr_type).into()),
    };

    info!(
        "VLESS Request: {} -> {}:{} ({})",
        client_id,
        host,
        port,
        if cmd == VlessCommand::Tcp {
            "TCP"
        } else {
            "UDP"
        }
    );

    // Handle UDP differently
    if cmd == VlessCommand::Udp {
        debug!("VLESS: UDP relay mode");
        let response = [VERSION, 0];
        stream.write_all(&response).await?;
        stream.flush().await?;

        return handle_udp_relay(stream, host, port)
            .await;
    }

    // Response Logic with rustray Vision
    let response = [VERSION, 0];
    debug!("VLESS: Sending response header: {:?}", response);
    stream.write_all(&response).await?;
    stream.flush().await?;

    // Wrap stream with Vision if flow is enabled
    if let Some(flow) = &user.flow
        && flow == "vision" {
            use crate::protocols::vless_vision::VisionStream;
            let vision_stream = VisionStream::new(stream);
            return router
                .route_stream(Box::new(vision_stream), host, port, source, policy)
                .await;
        }

    router
        .route_stream(stream, host, port, source, policy)
        .await
}

async fn pipe_to_fallback(
    mut stream: BoxedStream,
    dest: &str,
    initial_data: Option<&[u8]>,
) -> Result<()> {
    info!("VLESS: Fallback to {}", dest);
    let mut dest_stream = TcpStream::connect(dest).await?;

    if let Some(data) = initial_data {
        dest_stream.write_all(data).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut stream, &mut dest_stream).await;
    Ok(())
}

async fn vless_mux_handshake(mut stream: BoxedStream, uuid_str: &str) -> Result<BoxedStream> {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(VERSION);
    let uuid = Uuid::parse_str(uuid_str)?;
    buf.put_slice(uuid.as_bytes());

    // Mux Addon
    let mux_addon = AddonInfo {
        addon_type: ADDON_TYPE_SESSION_METADATA,
        data: vec![],
    };
    let addon_bytes = AddonInfo::serialize_addons(&[mux_addon]);
    buf.put_u8(addon_bytes.len() as u8);
    buf.put_slice(&addon_bytes);

    // Command TCP, Port 0, Address Empty
    buf.put_u8(1);
    buf.put_u16(0);
    buf.put_u8(2);
    buf.put_u8(0);

    stream.write_all(&buf).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != VERSION {
        return Err(VlessError::InvalidVersion(resp[0]).into());
    }

    Ok(stream)
}

// --- OUTBOUND ---

/// VLESS outbound handler with support for REALITY, Vision, and Mux
pub struct VlessOutbound {
    settings: VlessOutboundSettings,
    stream_settings: Option<StreamSettings>,
    mux_pool: Arc<MuxPool>,
    mux_enabled: bool,
    dns_server: Arc<DnsServer>, // Added
}

impl VlessOutbound {
    pub fn new(
        settings: VlessOutboundSettings,
        stream_settings: Option<StreamSettings>,
        mux_config: Option<MuxConfig>,
        dns_server: Arc<DnsServer>, // Added
    ) -> Self {
        let mux_enabled = mux_config.map(|m| m.enabled).unwrap_or(false);
        Self {
            settings,
            stream_settings,
            mux_pool: Arc::new(MuxPool::new()),
            mux_enabled,
            dns_server,
        }
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;
        let _ = tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream).await;
        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let stream_settings = self.stream_settings.clone().unwrap_or_default();
        let server_addr = self.settings.address.clone();
        let server_port = self.settings.port;
        let dns_server = self.dns_server.clone();
        let mux_enabled = self.mux_enabled;
        let uuid = self.settings.uuid.clone();

        // Dialer closure using transport::connect
        let dialer = || {
            let d = dns_server.clone();
            let s = stream_settings.clone();
            let h = server_addr.clone();
            let p = server_port;
            let uid = uuid.clone();

            async move {
                let mut stream = crate::transport::connect(&s, d, &h, p).await?;
                // If Mux enabled, we MUST authenticate the base connection with a VLESS Header + Mux Addon
                if mux_enabled {
                    stream = vless_mux_handshake(stream, &uid).await?;
                }
                Ok(stream)
            }
        };

        let dest_str = format!("{}:{}", self.settings.address, self.settings.port);

        let mut out_stream = if self.mux_enabled {
            self.mux_pool.get_stream(&dest_str, dialer).await?
        } else {
            dialer().await?
        };

        if !self.mux_enabled {
            let mut buf = BytesMut::with_capacity(512);
            buf.put_u8(VERSION);

            let uuid_parsed = Uuid::parse_str(&uuid)?;
            buf.put_slice(uuid_parsed.as_bytes());

            // No addons in header for Vision (handled by stream wrapper)
            buf.put_u8(0); // Addons Len

            buf.put_u8(1); // Command TCP
            buf.put_u16(port);

            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                buf.put_u8(1);
                buf.put_slice(&ip.octets());
            } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
                buf.put_u8(3);
                buf.put_slice(&ip.octets());
            } else {
                buf.put_u8(2);
                let domain_bytes = host.as_bytes();
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
            }

            // Wrap with Flow if enabled
            if let Some(flow_name) = &self.settings.flow {
                use crate::protocols::flow_trait::FlowFactory;

                if FlowFactory::is_supported(flow_name) {
                    debug!("VLESS: Enabling flow protocol: {}", flow_name);
                    match FlowFactory::create(flow_name) {
                        Ok(flow) => {
                            use crate::protocols::flow_trait::FlowStream;
                            out_stream = FlowStream::new(out_stream, flow).into_boxed();
                        }
                        Err(e) => {
                            warn!("VLESS: Failed to create flow '{}': {}", flow_name, e);
                        }
                    }
                } else {
                    warn!("VLESS: Unsupported flow protocol: {}", flow_name);
                }
            }

            out_stream.write_all(&buf).await?;

            let mut resp_head = [0u8; 2];
            out_stream.read_exact(&mut resp_head).await?;
            if resp_head[0] != VERSION {
                return Err(VlessError::InvalidVersion(resp_head[0]).into());
            }
            let addons_len = resp_head[1] as usize;
            if addons_len > 0 {
                let mut addons = vec![0u8; addons_len];
                out_stream.read_exact(&mut addons).await?;
            }
        }

        Ok(out_stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use std::io::Cursor;
    // use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_vless_encode_decode() {
        let uuid = Uuid::new_v4();
        let mut buf = BytesMut::new();
        buf.put_u8(0); // Ver
        buf.put_slice(uuid.as_bytes());
        buf.put_u8(0); // Addons
        buf.put_u8(1); // Cmd TCP
        buf.put_u16(443); // Port
        buf.put_u8(2); // Domain
        buf.put_u8(11); // Len
        buf.put_slice(b"example.com");

        assert_eq!(buf.len(), 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11);
    }
}
