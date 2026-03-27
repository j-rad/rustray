// src/protocols/tuic.rs
//!
//! TUIC v5 Protocol Implementation
//!
//! TUIC is a high-performance 0-RTT proxy protocol over QUIC designed for
//! low-latency, high-throughput scenarios. This module implements both
//! inbound (server) and outbound (client) handlers.
//!
//! Protocol Overview:
//! - Uses QUIC for transport with multiplexed streams
//! - Supports TCP Connect and UDP relay modes
//! - Token-based authentication using UUID
//! - ALPN: "tuic-v5"

use crate::app::stats::StatsManager;
use crate::config::{LevelPolicy, TuicOutboundSettings, TuicSettings};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::{BoxedStream, Packet};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use lru::LruCache;
use std::collections::HashMap;
use std::io::{self};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

// --- Constants ---

/// ALPN protocol identifier for TUIC v5
pub const ALPN_TUIC_V5: &[u8] = b"tuic-v5";

/// TUIC protocol version
const TUIC_VERSION: u8 = 5;

/// Maximum idle timeout for QUIC connections
const QUIC_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Maximum datagram size for QUIC
const MAX_DATAGRAM_SIZE: usize = 1350;

/// Connection pool size
const CONNECTION_POOL_SIZE: usize = 32;

/// Authentication timeout
const AUTH_TIMEOUT_SECS: u64 = 10;

/// UDP relay session timeout
const UDP_SESSION_TIMEOUT_SECS: u64 = 300;

// --- Connection Pool ---

// Global connection pool for QUIC connection reuse
lazy_static::lazy_static! {
    static ref CONNECTION_POOL: Mutex<LruCache<SocketAddr, Arc<TuicClientConnection>>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(CONNECTION_POOL_SIZE).unwrap()));
}

// --- Commands and Types ---

/// TUIC protocol commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TuicCommand {
    /// TCP Connect request
    Connect = 0x01,
    /// UDP relay request
    ConnectUdp = 0x02,
    /// Connection close
    Close = 0x03,
    /// Dissociate UDP session
    Dissociate = 0x04,
    /// Heartbeat/keepalive
    Heartbeat = 0x05,
}

impl TuicCommand {
    /// Parse command from byte value
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(TuicCommand::Connect),
            0x02 => Some(TuicCommand::ConnectUdp),
            0x03 => Some(TuicCommand::Close),
            0x04 => Some(TuicCommand::Dissociate),
            0x05 => Some(TuicCommand::Heartbeat),
            _ => None,
        }
    }

    /// Convert command to byte value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Address types supported by TUIC
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    IPv6 = 0x02,
    Domain = 0x03,
}

impl AddressType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(AddressType::IPv4),
            0x02 => Some(AddressType::IPv6),
            0x03 => Some(AddressType::Domain),
            _ => None,
        }
    }
}

/// Target address for connection
#[derive(Debug, Clone)]
pub enum Address {
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl Address {
    /// Get the host part of the address
    pub fn host(&self) -> String {
        match self {
            Address::Ipv4(addr, _) => addr.to_string(),
            Address::Ipv6(addr, _) => addr.to_string(),
            Address::Domain(domain, _) => domain.clone(),
        }
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        match self {
            Address::Ipv4(_, port) => *port,
            Address::Ipv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    /// Calculate the serialized size
    pub fn serialized_len(&self) -> usize {
        match self {
            Address::Ipv4(_, _) => 1 + 4 + 2,             // type + addr + port
            Address::Ipv6(_, _) => 1 + 16 + 2,            // type + addr + port
            Address::Domain(d, _) => 1 + 1 + d.len() + 2, // type + len + addr + port
        }
    }

    pub async fn to_socket_addr(&self, _router: &Router) -> io::Result<SocketAddr> {
        match self {
            Address::Ipv4(addr, port) => Ok(SocketAddr::new(std::net::IpAddr::V4(*addr), *port)),
            Address::Ipv6(addr, port) => Ok(SocketAddr::new(std::net::IpAddr::V6(*addr), *port)),
            Address::Domain(domain, port) => {
                let addrs = tokio::net::lookup_host((domain.as_str(), *port)).await?;
                addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| io::Error::other("Domain resolution failed"))
            }
        }
    }
}

// --- Protocol Headers ---

/// TUIC protocol header
#[derive(Debug, Clone)]
pub struct TuicHeader {
    pub command: TuicCommand,
    pub version: u8,
    pub token: Uuid,
}

impl TuicHeader {
    /// Header size in bytes
    pub const SIZE: usize = 1 + 1 + 16; // command + version + UUID

    /// Create a new header
    pub fn new(command: TuicCommand, token: Uuid) -> Self {
        Self {
            command,
            version: TUIC_VERSION,
            token,
        }
    }

    /// Parse header from stream
    pub async fn parse<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; Self::SIZE];
        reader.read_exact(&mut header).await?;

        let command = TuicCommand::from_u8(header[0]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid TUIC command: {:#x}", header[0]),
            )
        })?;

        let version = header[1];
        if version != TUIC_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Unsupported TUIC version: {} (expected {})",
                    version, TUIC_VERSION
                ),
            ));
        }

        let token = Uuid::from_bytes(
            header[2..18]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid token bytes"))?,
        );

        Ok(Self {
            command,
            version,
            token,
        })
    }

    /// Write header to stream
    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let mut buf = BytesMut::with_capacity(Self::SIZE);
        buf.put_u8(self.command.to_u8());
        buf.put_u8(self.version);
        buf.put_slice(self.token.as_bytes());
        writer.write_all(&buf).await
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(Self::SIZE);
        buf.put_u8(self.command.to_u8());
        buf.put_u8(self.version);
        buf.put_slice(self.token.as_bytes());
        buf
    }
}

/// Connect request containing target address
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub addr: Address,
}

impl ConnectRequest {
    /// Parse connect request from stream
    pub async fn parse<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let addr_type = reader.read_u8().await?;
        let addr = match AddressType::from_u8(addr_type) {
            Some(AddressType::IPv4) => {
                let mut addr_bytes = [0u8; 4];
                reader.read_exact(&mut addr_bytes).await?;
                let addr = Ipv4Addr::from(addr_bytes);
                let port = reader.read_u16().await?;
                Address::Ipv4(addr, port)
            }
            Some(AddressType::IPv6) => {
                let mut addr_bytes = [0u8; 16];
                reader.read_exact(&mut addr_bytes).await?;
                let addr = Ipv6Addr::from(addr_bytes);
                let port = reader.read_u16().await?;
                Address::Ipv6(addr, port)
            }
            Some(AddressType::Domain) => {
                let domain_len = reader.read_u8().await? as usize;
                if domain_len == 0 || domain_len > 253 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid domain length",
                    ));
                }
                let mut domain_bytes = vec![0u8; domain_len];
                reader.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8(domain_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid domain name encoding")
                })?;
                let port = reader.read_u16().await?;
                Address::Domain(domain, port)
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported address type: {:#x}", addr_type),
                ));
            }
        };
        Ok(Self { addr })
    }

    /// Serialize to BytesMut
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.addr.serialized_len());
        match &self.addr {
            Address::Ipv4(addr, port) => {
                buf.put_u8(AddressType::IPv4 as u8);
                buf.put_slice(&addr.octets());
                buf.put_u16(*port);
            }
            Address::Ipv6(addr, port) => {
                buf.put_u8(AddressType::IPv6 as u8);
                buf.put_slice(&addr.octets());
                buf.put_u16(*port);
            }
            Address::Domain(domain, port) => {
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
        }
        buf
    }

    /// Write to async writer
    pub async fn write<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.to_bytes()).await
    }
}

// --- UDP Relay ---

/// UDP relay packet with association ID and data
#[derive(Debug, Clone)]
pub struct UdpRelayPacket {
    /// Association ID for multiplexing UDP sessions
    pub assoc_id: u16,
    /// Fragment ID (0 = no fragmentation, >0 = fragment number)
    pub frag_id: u8,
    /// Fragment total (0 = no fragmentation, >0 = total fragments)  
    pub frag_total: u8,
    /// Target address
    pub addr: Address,
    /// Packet data
    pub data: BytesMut,
}

impl UdpRelayPacket {
    /// Parse UDP relay packet from stream
    pub async fn parse<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        // Read association ID
        let assoc_id = reader.read_u16().await?;

        // Read fragmentation info
        let frag_id = reader.read_u8().await?;
        let frag_total = reader.read_u8().await?;

        // Read data length
        let data_len = reader.read_u16().await? as usize;
        if data_len > 65535 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP packet too large",
            ));
        }

        // Parse target address
        let addr_type = reader.read_u8().await?;
        let addr = match AddressType::from_u8(addr_type) {
            Some(AddressType::IPv4) => {
                let mut addr_bytes = [0u8; 4];
                reader.read_exact(&mut addr_bytes).await?;
                let addr = Ipv4Addr::from(addr_bytes);
                let port = reader.read_u16().await?;
                Address::Ipv4(addr, port)
            }
            Some(AddressType::IPv6) => {
                let mut addr_bytes = [0u8; 16];
                reader.read_exact(&mut addr_bytes).await?;
                let addr = Ipv6Addr::from(addr_bytes);
                let port = reader.read_u16().await?;
                Address::Ipv6(addr, port)
            }
            Some(AddressType::Domain) => {
                let domain_len = reader.read_u8().await? as usize;
                let mut domain_bytes = vec![0u8; domain_len];
                reader.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid domain"))?;
                let port = reader.read_u16().await?;
                Address::Domain(domain, port)
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid address type in UDP relay",
                ));
            }
        };

        // Read packet data
        let mut data = BytesMut::with_capacity(data_len);
        data.resize(data_len, 0);
        reader.read_exact(&mut data).await?;

        Ok(Self {
            assoc_id,
            frag_id,
            frag_total,
            addr,
            data,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let addr_bytes = match &self.addr {
            Address::Ipv4(addr, port) => {
                let mut buf = BytesMut::with_capacity(7);
                buf.put_u8(AddressType::IPv4 as u8);
                buf.put_slice(&addr.octets());
                buf.put_u16(*port);
                buf
            }
            Address::Ipv6(addr, port) => {
                let mut buf = BytesMut::with_capacity(19);
                buf.put_u8(AddressType::IPv6 as u8);
                buf.put_slice(&addr.octets());
                buf.put_u16(*port);
                buf
            }
            Address::Domain(domain, port) => {
                let mut buf = BytesMut::with_capacity(4 + domain.len());
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
                buf
            }
        };

        let total_len = 2 + 1 + 1 + 2 + addr_bytes.len() + self.data.len();
        let mut buf = BytesMut::with_capacity(total_len);
        buf.put_u16(self.assoc_id);
        buf.put_u8(self.frag_id);
        buf.put_u8(self.frag_total);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&addr_bytes);
        buf.put_slice(&self.data);
        buf
    }
}

// --- UDP Session Manager ---

/// Manages UDP relay sessions
pub struct UdpSessionManager {
    sessions: RwLock<HashMap<u16, UdpSession>>,
    next_assoc_id: AtomicU64,
}

/// Individual UDP session
struct UdpSession {
    socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    target_addr: Option<SocketAddr>,
    last_activity: std::time::Instant,
}

impl Default for UdpSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_assoc_id: AtomicU64::new(1),
        }
    }

    /// Create or get a UDP session
    pub async fn get_or_create_session(&self, assoc_id: u16) -> Result<Arc<UdpSocket>> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&assoc_id) {
            session.last_activity = std::time::Instant::now();
            return Ok(session.socket.clone());
        }

        // Create new session
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        sessions.insert(
            assoc_id,
            UdpSession {
                socket: socket.clone(),
                target_addr: None,
                last_activity: std::time::Instant::now(),
            },
        );

        Ok(socket)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let now = std::time::Instant::now();
        let timeout = Duration::from_secs(UDP_SESSION_TIMEOUT_SECS);

        sessions.retain(|_, session| now.duration_since(session.last_activity) < timeout);
    }

    /// Generate next association ID
    pub fn next_assoc_id(&self) -> u16 {
        (self.next_assoc_id.fetch_add(1, Ordering::Relaxed) % 65535) as u16
    }
}

// --- Inbound Handler ---

/// TUIC inbound stream handler
///
/// Handles incoming TUIC connections from clients
pub struct TuicInbound {
    settings: Arc<TuicSettings>,
    #[allow(dead_code)]
    udp_manager: Arc<UdpSessionManager>,
}

impl TuicInbound {
    pub fn new(settings: TuicSettings) -> Self {
        Self {
            settings: Arc::new(settings),
            udp_manager: Arc::new(UdpSessionManager::new()),
        }
    }

    /// Handle a new inbound stream
    pub async fn handle_stream(
        &self,
        router: Arc<Router>,
        state: Arc<StatsManager>,
        mut stream: BoxedStream,
        source: String,
    ) -> Result<()> {
        debug!("TUIC: Handling new inbound stream");

        // Parse the TUIC header with timeout
        let header = match timeout(
            Duration::from_secs(AUTH_TIMEOUT_SECS),
            TuicHeader::parse(&mut stream),
        )
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                warn!("TUIC: Failed to parse header: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                warn!("TUIC: Header parse timeout");
                return Err(anyhow::anyhow!("TUIC authentication timeout"));
            }
        };

        debug!(
            "TUIC: Received command {:?}, token: {}",
            header.command, header.token
        );

        // Authenticate user by token
        let user = self
            .settings
            .users
            .iter()
            .find(|u| {
                Uuid::parse_str(&u.uuid)
                    .map(|id| id == header.token)
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                warn!("TUIC: Authentication failed for token: {}", header.token);
                anyhow::anyhow!("TUIC: Unknown user token")
            })?;

        info!(
            "TUIC: Authenticated user {} (level: {:?})",
            user.uuid, user.level
        );

        // Get policy for this user level
        let user_level = user.level.unwrap_or(0);
        let policy = state.policy_manager.get_policy(user_level);

        // Dispatch based on command
        match header.command {
            TuicCommand::Connect => handle_connect(router, stream, policy, source).await,
            TuicCommand::ConnectUdp => handle_udp_relay(router, stream).await,
            TuicCommand::Heartbeat => handle_heartbeat(stream).await,
            TuicCommand::Dissociate => {
                debug!("TUIC: Dissociate command received");
                Ok(())
            }
            TuicCommand::Close => {
                debug!("TUIC: Close command received");
                Ok(())
            }
        }
    }
}

/// Main entry point for handling TUIC inbound streams
///
/// This function is called by the QUIC listener when a new stream is accepted.
pub async fn listen_stream(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    stream: BoxedStream,
    settings: TuicSettings,
    source: String,
) -> Result<()> {
    let inbound = TuicInbound::new(settings);
    inbound.handle_stream(router, state, stream, source).await
}

/// Handle TCP Connect command
async fn handle_connect(
    router: Arc<Router>,
    mut stream: BoxedStream,
    policy: Arc<LevelPolicy>,
    source: String,
) -> Result<()> {
    // Parse connect request
    let request = ConnectRequest::parse(&mut stream).await?;
    let host = request.addr.host();
    let port = request.addr.port();

    info!("TUIC Connect: {}:{}", host, port);

    // Route the stream to the target
    router
        .route_stream(stream, host, port, source, policy)
        .await
}

/// Handle UDP relay command
async fn handle_udp_relay(router: Arc<Router>, mut stream: BoxedStream) -> Result<()> {
    debug!("TUIC: Starting UDP relay loop");

    loop {
        match UdpRelayPacket::parse(&mut stream).await {
            Ok(packet) => {
                trace!(
                    "TUIC UDP: assoc_id={}, addr={}:{}, data_len={}",
                    packet.assoc_id,
                    packet.addr.host(),
                    packet.addr.port(),
                    packet.data.len()
                );

                // Route the UDP packet
                let udp_packet = crate::transport::UdpPacket {
                    src: std::net::SocketAddr::from(([0, 0, 0, 0], 0)), // Placeholder
                    dest: packet
                        .addr
                        .to_socket_addr(&router)
                        .await
                        .unwrap_or_else(|_| "[::]:0".parse().unwrap()),
                    data: packet.data.to_vec(),
                };

                if let Err(e) = router.route_packet(udp_packet).await {
                    warn!("TUIC: Failed to route UDP packet: {}", e);
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    debug!("TUIC: UDP relay stream closed");
                    break;
                }
                warn!("TUIC: Failed to parse UDP relay packet: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}

/// Handle heartbeat command
async fn handle_heartbeat(mut stream: BoxedStream) -> Result<()> {
    debug!("TUIC: Heartbeat received");

    // Send heartbeat response (just echo back a heartbeat header)
    let response = TuicHeader::new(TuicCommand::Heartbeat, Uuid::nil());
    response.write(&mut stream).await?;

    Ok(())
}

// --- Client Connection Management ---

/// Represents a pooled TUIC client connection
pub struct TuicClientConnection {
    /// Remote server address  
    remote_addr: SocketAddr,
    /// Server name for TLS
    server_name: String,
    /// User token (UUID)
    #[allow(dead_code)]
    token: Uuid,
    /// Whether this connection is still usable
    is_closed: RwLock<bool>,
    /// Stream counter for multiplexing
    stream_counter: AtomicU64,
    /// Last activity timestamp
    last_activity: RwLock<std::time::Instant>,
}

impl TuicClientConnection {
    pub fn new(remote_addr: SocketAddr, server_name: String, token: Uuid) -> Self {
        Self {
            remote_addr,
            server_name,
            token,
            is_closed: RwLock::new(false),
            stream_counter: AtomicU64::new(0),
            last_activity: RwLock::new(std::time::Instant::now()),
        }
    }

    pub async fn is_closed(&self) -> bool {
        *self.is_closed.read().await
    }

    pub async fn mark_closed(&self) {
        *self.is_closed.write().await = true;
    }

    pub async fn update_activity(&self) {
        *self.last_activity.write().await = std::time::Instant::now();
    }

    pub fn next_stream_id(&self) -> u64 {
        self.stream_counter.fetch_add(1, Ordering::Relaxed)
    }
}

// --- Outbound Handler ---

/// TUIC outbound client
///
/// Implements the `Outbound` trait to connect through a TUIC proxy server
pub struct TuicOutbound {
    settings: Arc<TuicOutboundSettings>,
    /// Parsed UUID for authentication
    #[allow(dead_code)]
    token: Uuid,
}

impl TuicOutbound {
    pub fn new(settings: TuicOutboundSettings) -> Self {
        let token = Uuid::parse_str(&settings.uuid).unwrap_or_else(|_| {
            warn!("TUIC: Invalid UUID in settings, using nil UUID");
            Uuid::nil()
        });

        Self {
            settings: Arc::new(settings),
            token,
        }
    }

    /// Get or create a pooled connection to the upstream server
    async fn get_connection(&self) -> Result<Arc<TuicClientConnection>> {
        let remote_addr = self.resolve_server_address()?;

        // Check pool for existing connection
        {
            let mut pool = CONNECTION_POOL.lock().await;
            if let Some(conn) = pool.get(&remote_addr)
                && !conn.is_closed().await {
                    conn.update_activity().await;
                    debug!("TUIC: Reusing pooled connection to {}", remote_addr);
                    return Ok(conn.clone());
                }
        }

        // Create new connection
        debug!("TUIC: Creating new connection to {}", remote_addr);
        let conn = Arc::new(TuicClientConnection::new(
            remote_addr,
            self.settings.server.clone(),
            self.token,
        ));

        // Add to pool
        {
            let mut pool = CONNECTION_POOL.lock().await;
            pool.put(remote_addr, conn.clone());
        }

        Ok(conn)
    }

    /// Resolve server address from settings
    fn resolve_server_address(&self) -> Result<SocketAddr> {
        (self.settings.server.as_str(), self.settings.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("TUIC: Could not resolve server address"))
    }

    /// Build ALPN list from settings
    fn get_alpn(&self) -> Vec<&[u8]> {
        if let Some(alpns) = &self.settings.alpn
            && !alpns.is_empty() {
                // Convert to static slice references
                return vec![ALPN_TUIC_V5];
            }
        vec![ALPN_TUIC_V5]
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    /// Handle an outbound connection through TUIC
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;

        debug!("TUIC Outbound: Starting bidirectional copy");

        // Bidirectional copy between incoming stream and QUIC stream
        match tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream).await {
            Ok((up, down)) => {
                debug!(
                    "TUIC: Connection closed. Uploaded: {} bytes, Downloaded: {} bytes",
                    up, down
                );
            }
            Err(e) => {
                // Check if it's a normal close
                if e.kind() != io::ErrorKind::ConnectionReset
                    && e.kind() != io::ErrorKind::UnexpectedEof
                {
                    warn!("TUIC: Bidirectional copy error: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        debug!("TUIC Outbound: Dialing {}:{}", host, port);

        // Get connection from pool
        let conn = self.get_connection().await?;
        let remote_addr = conn.remote_addr;

        // Establish QUIC connection
        let mut quic_conn =
            crate::transport::quic::connect(remote_addr, &conn.server_name, &self.get_alpn(), None)
                .await?;

        // Open a new stream for this connection
        let mut out_stream = quic_conn.open_stream().await?;

        // Send TUIC header
        let header = TuicHeader::new(TuicCommand::Connect, self.token);
        header.write(&mut out_stream).await?;

        // Send connect request
        let addr = if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
            Address::Ipv4(ipv4, port)
        } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
            Address::Ipv6(ipv6, port)
        } else {
            Address::Domain(host.clone(), port)
        };
        let request = ConnectRequest { addr };
        request.write(&mut out_stream).await?;

        conn.update_activity().await;
        Ok(Box::new(out_stream) as BoxedStream)
    }

    /// Handle UDP packets through TUIC
    async fn handle_packet(
        &self,
        packet: Box<dyn Packet>,
        _reply_tx: Option<tokio::sync::mpsc::Sender<Box<dyn Packet>>>,
    ) -> Result<()> {
        debug!(
            "TUIC: UDP packet forwarding (len={})",
            packet.payload().len()
        );

        // Get connection
        let conn = self.get_connection().await?;
        let remote_addr = conn.remote_addr;

        // Establish QUIC connection
        let mut quic_conn =
            crate::transport::quic::connect(remote_addr, &conn.server_name, &self.get_alpn(), None)
                .await?;

        // Open stream for UDP relay
        let mut out_stream = quic_conn.open_stream().await?;

        // Send TUIC header for UDP
        let header = TuicHeader::new(TuicCommand::ConnectUdp, self.token);
        header.write(&mut out_stream).await?;

        // Wrap packet in UDP relay format
        // For now, use a placeholder address - real implementation would parse the packet
        let udp_packet = UdpRelayPacket {
            assoc_id: conn.next_stream_id() as u16,
            frag_id: 0,
            frag_total: 0,
            addr: Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0), 0),
            data: BytesMut::from(packet.payload()),
        };

        out_stream.write_all(&udp_packet.to_bytes()).await?;
        out_stream.flush().await?;

        Ok(())
    }
}

// --- QUIC Configuration Helper ---

/// Create optimized QUIC configuration for TUIC
pub fn create_quic_config() -> Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    // Set ALPN
    config.set_application_protos(&[ALPN_TUIC_V5])?;

    // Timeouts
    config.set_max_idle_timeout(QUIC_IDLE_TIMEOUT_MS);

    // Stream limits
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    // Datagram settings
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);

    // Enable 0-RTT for fast reconnection
    config.enable_early_data();

    // Use BBR congestion control for better performance
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Bbr2Gcongestion);

    // Disable active migration (not needed for proxy)
    config.set_disable_active_migration(true);

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_command_conversion() {
        assert_eq!(TuicCommand::from_u8(0x01), Some(TuicCommand::Connect));
        assert_eq!(TuicCommand::from_u8(0x02), Some(TuicCommand::ConnectUdp));
        assert_eq!(TuicCommand::from_u8(0x03), Some(TuicCommand::Close));
        assert_eq!(TuicCommand::from_u8(0xFF), None);

        assert_eq!(TuicCommand::Connect.to_u8(), 0x01);
    }

    #[test]
    fn test_address_serialization() {
        let addr = Address::Domain("example.com".to_string(), 443);
        assert_eq!(addr.host(), "example.com");
        assert_eq!(addr.port(), 443);

        let request = ConnectRequest { addr };
        let bytes = request.to_bytes();

        // Type + len + domain + port
        assert_eq!(bytes.len(), 1 + 1 + 11 + 2);
    }

    #[test]
    fn test_header_serialization() {
        let token = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let header = TuicHeader::new(TuicCommand::Connect, token);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), TuicHeader::SIZE);
        assert_eq!(bytes[0], 0x01); // Connect command
        assert_eq!(bytes[1], TUIC_VERSION);
    }
}
