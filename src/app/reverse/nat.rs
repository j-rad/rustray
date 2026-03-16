//! NAT Detection and STUN Client Implementation
//!
//! Provides comprehensive NAT type detection using STUN protocol (RFC 5389)
//! with support for symmetric NAT port prediction and hole punching coordination.

use crate::error::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// STUN Message Constants (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// NAT Type Classification (RFC 3489/5389)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NatType {
    /// NAT type not yet determined
    Unknown,
    /// No NAT, direct internet connection
    OpenInternet,
    /// Full Cone NAT - allows any external host to send packets
    FullCone,
    /// Restricted Cone NAT - only hosts we've sent to can reply
    RestrictedCone,
    /// Port Restricted Cone NAT - only specific host:port can reply
    PortRestrictedCone,
    /// Symmetric NAT - different mapping for each destination
    Symmetric,
    /// UDP is blocked or filtered
    UdpBlocked,
}

impl NatType {
    /// Returns true if this NAT type supports direct P2P connections
    pub fn supports_p2p(&self) -> bool {
        matches!(
            self,
            NatType::OpenInternet
                | NatType::FullCone
                | NatType::RestrictedCone
                | NatType::PortRestrictedCone
        )
    }

    /// Returns true if hole punching is likely to succeed
    pub fn supports_hole_punching(&self) -> bool {
        !matches!(
            self,
            NatType::Symmetric | NatType::UdpBlocked | NatType::Unknown
        )
    }

    /// Returns connection strategy recommendation
    pub fn recommended_strategy(&self) -> ConnectionStrategy {
        match self {
            NatType::OpenInternet | NatType::FullCone => ConnectionStrategy::DirectConnect,
            NatType::RestrictedCone | NatType::PortRestrictedCone => ConnectionStrategy::HolePunch,
            NatType::Symmetric => ConnectionStrategy::SymmetricHolePunch,
            NatType::UdpBlocked | NatType::Unknown => ConnectionStrategy::Relay,
        }
    }
}

/// Recommended connection strategy based on NAT type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStrategy {
    /// Direct connection possible
    DirectConnect,
    /// Standard UDP hole punching
    HolePunch,
    /// Symmetric NAT hole punching with port prediction
    SymmetricHolePunch,
    /// Must use relay server
    Relay,
}

/// Complete NAT information including public endpoint and type
#[derive(Debug, Clone)]
pub struct NatInfo {
    pub nat_type: NatType,
    pub public_ip: Option<SocketAddr>,
    pub local_ip: Option<IpAddr>,
    pub last_update: Option<Instant>,
    /// Port allocation behavior (for symmetric NAT port prediction)
    pub port_delta: Option<i32>,
    /// Observed port sequence for prediction
    pub port_history: Vec<u16>,
}

impl Default for NatInfo {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            public_ip: None,
            local_ip: None,
            last_update: None,
            port_delta: None,
            port_history: Vec::new(),
        }
    }
}

/// STUN Client for NAT Discovery and Keep-Alive
#[derive(Debug)]
pub struct StunClient {
    /// Primary STUN server
    primary_server: String,
    /// Fallback STUN servers for reliability
    fallback_servers: Vec<String>,
    /// Shared NAT information
    nat_info: Arc<RwLock<NatInfo>>,
    /// Discovery interval
    discovery_interval: Duration,
    /// Maximum retry attempts per discovery cycle
    max_retries: u32,
}

impl StunClient {
    /// Create a new STUN client with a single server
    pub fn new(stun_server: String) -> Self {
        Self {
            primary_server: stun_server,
            fallback_servers: Vec::new(),
            nat_info: Arc::new(RwLock::new(NatInfo::default())),
            discovery_interval: Duration::from_secs(30),
            max_retries: 3,
        }
    }

    /// Create a STUN client with multiple servers for redundancy
    pub fn with_servers(primary: String, fallbacks: Vec<String>) -> Self {
        Self {
            primary_server: primary,
            fallback_servers: fallbacks,
            nat_info: Arc::new(RwLock::new(NatInfo::default())),
            discovery_interval: Duration::from_secs(30),
            max_retries: 3,
        }
    }

    /// Set custom discovery interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.discovery_interval = interval;
        self
    }

    /// Get current NAT information
    pub async fn get_nat_info(&self) -> NatInfo {
        self.nat_info.read().await.clone()
    }

    /// Get shared NAT info provider for other components
    pub fn get_nat_info_provider(&self) -> Arc<RwLock<NatInfo>> {
        self.nat_info.clone()
    }

    /// Main discovery loop - runs continuously
    pub async fn run_discovery(&self) {
        info!(
            "Starting STUN discovery loop against {} (+ {} fallbacks)",
            self.primary_server,
            self.fallback_servers.len()
        );

        let mut retry_count = 0;
        let mut backoff = Duration::from_secs(1);

        loop {
            match self.perform_full_nat_detection().await {
                Ok(nat_info) => {
                    let mut info = self.nat_info.write().await;

                    // Check if anything changed
                    let changed =
                        info.public_ip != nat_info.public_ip || info.nat_type != nat_info.nat_type;

                    if changed {
                        info!(
                            "NAT info updated: Type={:?}, Public={:?}, Local={:?}",
                            nat_info.nat_type, nat_info.public_ip, nat_info.local_ip
                        );
                    }

                    *info = nat_info;

                    // Reset retry counter on success
                    retry_count = 0;
                    backoff = Duration::from_secs(1);

                    drop(info);
                    tokio::time::sleep(self.discovery_interval).await;
                }
                Err(e) => {
                    retry_count += 1;
                    warn!(
                        "STUN discovery failed (attempt {}/{}): {}",
                        retry_count, self.max_retries, e
                    );

                    if retry_count >= self.max_retries {
                        error!("Max retries reached, marking NAT as UdpBlocked");
                        let mut info = self.nat_info.write().await;
                        info.nat_type = NatType::UdpBlocked;
                        retry_count = 0;
                    }

                    // Exponential backoff
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, Duration::from_secs(60));
                }
            }
        }
    }

    /// Perform comprehensive NAT type detection
    async fn perform_full_nat_detection(&self) -> Result<NatInfo> {
        debug!("Starting full NAT detection");

        // Test 1: Basic binding request to primary server
        let (public_addr1, local_addr) = self.perform_stun_binding(&self.primary_server).await?;

        debug!("Test 1: Public={}, Local={}", public_addr1, local_addr);

        // Check if we're on open internet (public == local)
        if public_addr1.ip() == local_addr {
            info!("Detected Open Internet (no NAT)");
            return Ok(NatInfo {
                nat_type: NatType::OpenInternet,
                public_ip: Some(public_addr1),
                local_ip: Some(local_addr),
                last_update: Some(Instant::now()),
                port_delta: None,
                port_history: vec![public_addr1.port()],
            });
        }

        // Test 2: Binding from same local socket to different server (if available)
        let nat_type = if let Some(fallback) = self.fallback_servers.first() {
            match self.perform_stun_binding(fallback).await {
                Ok((public_addr2, _)) => {
                    debug!("Test 2: Public from fallback={}", public_addr2);

                    // If port changes between servers, it's Symmetric NAT
                    if public_addr1.port() != public_addr2.port() {
                        warn!(
                            "Detected Symmetric NAT (port changed: {} -> {})",
                            public_addr1.port(),
                            public_addr2.port()
                        );

                        // Calculate port delta for prediction
                        let delta = public_addr2.port() as i32 - public_addr1.port() as i32;

                        return Ok(NatInfo {
                            nat_type: NatType::Symmetric,
                            public_ip: Some(public_addr1),
                            local_ip: Some(local_addr),
                            last_update: Some(Instant::now()),
                            port_delta: Some(delta),
                            port_history: vec![public_addr1.port(), public_addr2.port()],
                        });
                    }

                    NatType::PortRestrictedCone
                }
                Err(e) => {
                    warn!("Fallback STUN failed: {}, assuming PortRestrictedCone", e);
                    NatType::PortRestrictedCone
                }
            }
        } else {
            // No fallback server, assume Port Restricted Cone
            NatType::PortRestrictedCone
        };

        info!("Detected NAT type: {:?}", nat_type);

        Ok(NatInfo {
            nat_type,
            public_ip: Some(public_addr1),
            local_ip: Some(local_addr),
            last_update: Some(Instant::now()),
            port_delta: None,
            port_history: vec![public_addr1.port()],
        })
    }

    /// Perform STUN binding and return both public and local addresses
    async fn perform_stun_binding(&self, server: &str) -> Result<(SocketAddr, IpAddr)> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;

        socket.connect(server).await?;

        // Build STUN Binding Request (RFC 5389)
        let request = self.build_stun_binding_request();
        socket.send(&request).await?;

        // Wait for response with timeout
        let mut buf = vec![0u8; 1024];
        let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf)).await??;

        // Parse STUN response
        let public_addr = self.parse_stun_response(&buf[..len])?;

        Ok((public_addr, local_addr.ip()))
    }

    /// Build a STUN Binding Request packet
    pub fn build_stun_binding_request(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20);

        // Message Type: Binding Request (0x0001)
        packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

        // Message Length: 0 (no attributes)
        packet.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (96 bits = 12 bytes)
        let mut tid = [0u8; 12];
        use rand::Rng;
        rand::thread_rng().fill(&mut tid);
        packet.extend_from_slice(&tid);

        packet
    }

    /// Parse STUN response and extract mapped address
    fn parse_stun_response(&self, data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 20 {
            return Err(anyhow::anyhow!("STUN response too short"));
        }

        // Verify message type (Binding Success Response = 0x0101)
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(anyhow::anyhow!(
                "Not a STUN Binding Response: 0x{:04x}",
                msg_type
            ));
        }

        // Verify magic cookie
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err(anyhow::anyhow!("Invalid STUN magic cookie"));
        }

        // Parse attributes
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let attrs_end = std::cmp::min(20 + msg_len, data.len());
        let mut pos = 20;

        while pos + 4 <= attrs_end {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + attr_len > attrs_end {
                break;
            }

            match attr_type {
                ATTR_XOR_MAPPED_ADDRESS => {
                    return self.parse_xor_mapped_address(
                        &data[pos..pos + attr_len],
                        &data[4..8],
                        &data[8..20],
                    );
                }
                ATTR_MAPPED_ADDRESS => {
                    return self.parse_mapped_address(&data[pos..pos + attr_len]);
                }
                _ => {}
            }

            // Align to 4-byte boundary
            pos += (attr_len + 3) & !3;
        }

        Err(anyhow::anyhow!("No mapped address in STUN response"))
    }

    /// Parse XOR-MAPPED-ADDRESS attribute
    fn parse_xor_mapped_address(
        &self,
        data: &[u8],
        magic: &[u8],
        tid: &[u8],
    ) -> Result<SocketAddr> {
        if data.len() < 8 {
            return Err(anyhow::anyhow!("XOR-MAPPED-ADDRESS too short"));
        }

        let family = data[1];
        let xport = u16::from_be_bytes([data[2], data[3]]);
        let port = xport ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        let ip = match family {
            0x01 => {
                // IPv4
                let xaddr = [data[4], data[5], data[6], data[7]];
                let addr = [
                    xaddr[0] ^ magic[0],
                    xaddr[1] ^ magic[1],
                    xaddr[2] ^ magic[2],
                    xaddr[3] ^ magic[3],
                ];
                IpAddr::from(addr)
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(anyhow::anyhow!("XOR-MAPPED-ADDRESS IPv6 too short"));
                }
                let mut addr = [0u8; 16];
                for i in 0..16 {
                    let xor_byte = if i < 4 { magic[i] } else { tid[i - 4] };
                    addr[i] = data[4 + i] ^ xor_byte;
                }
                IpAddr::from(addr)
            }
            _ => return Err(anyhow::anyhow!("Unknown address family: {}", family)),
        };

        Ok(SocketAddr::new(ip, port))
    }

    /// Parse MAPPED-ADDRESS attribute (fallback for old STUN servers)
    fn parse_mapped_address(&self, data: &[u8]) -> Result<SocketAddr> {
        if data.len() < 8 {
            return Err(anyhow::anyhow!("MAPPED-ADDRESS too short"));
        }

        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        let ip = match family {
            0x01 => {
                // IPv4
                IpAddr::from([data[4], data[5], data[6], data[7]])
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(anyhow::anyhow!("MAPPED-ADDRESS IPv6 too short"));
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&data[4..20]);
                IpAddr::from(addr)
            }
            _ => return Err(anyhow::anyhow!("Unknown address family: {}", family)),
        };

        Ok(SocketAddr::new(ip, port))
    }

    /// Predict next port for symmetric NAT hole punching
    pub async fn predict_next_port(&self) -> Option<u16> {
        let info = self.nat_info.read().await;

        if let (Some(public_addr), Some(delta)) = (info.public_ip, info.port_delta) {
            let predicted = (public_addr.port() as i32 + delta) as u16;
            debug!("Predicted next port: {} (delta: {})", predicted, delta);
            Some(predicted)
        } else {
            None
        }
    }

    /// Get multiple predicted ports for symmetric NAT (increases success probability)
    pub async fn predict_port_range(&self, count: usize) -> Vec<u16> {
        let info = self.nat_info.read().await;

        if let (Some(public_addr), Some(delta)) = (info.public_ip, info.port_delta) {
            let base_port = public_addr.port() as i32;
            (1..=count as i32)
                .map(|i| (base_port + delta * i) as u16)
                .collect()
        } else {
            Vec::new()
        }
    }
}

/// UDP Hole Punching Coordinator
#[derive(Debug)]
pub struct HolePunchCoordinator {
    local_socket: Option<Arc<UdpSocket>>,
    punch_attempts: u32,
    punch_interval: Duration,
}

impl HolePunchCoordinator {
    pub fn new() -> Self {
        Self {
            local_socket: None,
            punch_attempts: 10,
            punch_interval: Duration::from_millis(100),
        }
    }

    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.punch_attempts = attempts;
        self
    }

    /// Perform UDP hole punching to establish a direct connection
    pub async fn punch_hole(
        &mut self,
        target: SocketAddr,
        nat_type: NatType,
    ) -> Result<Arc<UdpSocket>> {
        info!(
            "Initiating UDP hole punch to {} (NAT type: {:?})",
            target, nat_type
        );

        // Create or reuse local socket
        let socket = match &self.local_socket {
            Some(s) => s.clone(),
            None => {
                let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                self.local_socket = Some(sock.clone());
                sock
            }
        };

        // Hole punch packet (empty UDP packet to open NAT mapping)
        let punch_packet = b"PUNCH";

        for attempt in 1..=self.punch_attempts {
            debug!(
                "Hole punch attempt {}/{} to {}",
                attempt, self.punch_attempts, target
            );

            // Send punch packet
            if let Err(e) = socket.send_to(punch_packet, target).await {
                warn!("Punch send failed: {}", e);
            }

            // Brief wait between punches
            tokio::time::sleep(self.punch_interval).await;

            // Check for response (non-blocking)
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await
            {
                Ok(Ok((len, from))) => {
                    if from == target || from.ip() == target.ip() {
                        info!("Hole punch succeeded! Received {} bytes from {}", len, from);
                        return Ok(socket);
                    }
                }
                _ => continue,
            }
        }

        Err(anyhow::anyhow!(
            "Hole punch failed after {} attempts",
            self.punch_attempts
        ))
    }

    /// Perform symmetric NAT hole punching with port prediction
    pub async fn punch_hole_symmetric(
        &mut self,
        target_ip: IpAddr,
        predicted_ports: &[u16],
    ) -> Result<Arc<UdpSocket>> {
        info!(
            "Initiating symmetric NAT hole punch to {} with {} predicted ports",
            target_ip,
            predicted_ports.len()
        );

        let socket = match &self.local_socket {
            Some(s) => s.clone(),
            None => {
                let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                self.local_socket = Some(sock.clone());
                sock
            }
        };

        let punch_packet = b"PUNCH";

        for attempt in 1..=self.punch_attempts {
            // Try all predicted ports
            for &port in predicted_ports {
                let target = SocketAddr::new(target_ip, port);
                debug!(
                    "Symmetric punch attempt {}/{} to {}",
                    attempt, self.punch_attempts, target
                );

                if let Err(e) = socket.send_to(punch_packet, target).await {
                    warn!("Symmetric punch send failed: {}", e);
                }
            }

            tokio::time::sleep(self.punch_interval).await;

            // Check for response
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await
            {
                Ok(Ok((_len, from))) => {
                    if from.ip() == target_ip {
                        info!(
                            "Symmetric hole punch succeeded! Port {} responded",
                            from.port()
                        );
                        return Ok(socket);
                    }
                }
                _ => continue,
            }
        }

        Err(anyhow::anyhow!(
            "Symmetric hole punch failed after {} attempts",
            self.punch_attempts
        ))
    }
}

impl Default for HolePunchCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_p2p_support() {
        assert!(NatType::OpenInternet.supports_p2p());
        assert!(NatType::FullCone.supports_p2p());
        assert!(NatType::PortRestrictedCone.supports_p2p());
        assert!(!NatType::Symmetric.supports_p2p());
        assert!(!NatType::UdpBlocked.supports_p2p());
    }

    #[test]
    fn test_nat_type_hole_punching_support() {
        assert!(NatType::FullCone.supports_hole_punching());
        assert!(!NatType::Symmetric.supports_hole_punching());
        assert!(!NatType::Unknown.supports_hole_punching());
    }

    #[test]
    fn test_connection_strategy() {
        assert_eq!(
            NatType::OpenInternet.recommended_strategy(),
            ConnectionStrategy::DirectConnect
        );
        assert_eq!(
            NatType::PortRestrictedCone.recommended_strategy(),
            ConnectionStrategy::HolePunch
        );
        assert_eq!(
            NatType::Symmetric.recommended_strategy(),
            ConnectionStrategy::SymmetricHolePunch
        );
        assert_eq!(
            NatType::UdpBlocked.recommended_strategy(),
            ConnectionStrategy::Relay
        );
    }

    #[test]
    fn test_stun_binding_request_format() {
        let client = StunClient::new("stun.l.google.com:19302".to_string());
        let request = client.build_stun_binding_request();

        // Check length (20 bytes header)
        assert_eq!(request.len(), 20);

        // Check message type (Binding Request)
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);

        // Check magic cookie
        assert_eq!(request[4], 0x21);
        assert_eq!(request[5], 0x12);
        assert_eq!(request[6], 0xA4);
        assert_eq!(request[7], 0x42);
    }
}
