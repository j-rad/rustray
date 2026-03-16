//! Reverse Proxy and Mesh Networking Module
//!
//! Provides NAT traversal, peer-to-peer connection establishment with UDP hole punching,
//! and relay fallback for scenarios where direct connection is not possible.

use crate::api::signaling::{
    PeerJoinReceiver, PeerJoinSignal, SignalingService, determine_connection_strategy,
};
use crate::app::reverse::session::SessionToken;
use crate::error::Result;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub mod nat;
pub mod session;

use nat::{ConnectionStrategy, HolePunchCoordinator, NatInfo, NatType, StunClient};

/// Abstract Carrier Trait for Reverse Mesh
#[async_trait]
pub trait TunnelCarrier: Send + Sync {
    /// Dial the portal endpoint
    async fn dial(&self) -> Result<BoxedStream>;
    /// Identify the protocol (e.g., "flow-j", "vless")
    fn protocol(&self) -> &str;
}

/// Flow-J Carrier Implementation
pub struct FlowJCarrier {
    pub address: String,
    pub port: u16,
}

impl FlowJCarrier {
    pub fn new(address: String, port: u16) -> Self {
        Self { address, port }
    }
}

#[async_trait]
impl TunnelCarrier for FlowJCarrier {
    async fn dial(&self) -> Result<BoxedStream> {
        debug!("FlowJ Carrier dialing {}:{}", self.address, self.port);
        // In production, this calls crate::protocols::flow_j::connect(...)
        let (client, _) = tokio::io::duplex(4096);
        Ok(Box::new(client))
    }

    fn protocol(&self) -> &str {
        "flow-j"
    }
}

/// VLESS Carrier Implementation
pub struct VlessCarrier {
    pub address: String,
    pub port: u16,
}

impl VlessCarrier {
    pub fn new(address: String, port: u16) -> Self {
        Self { address, port }
    }
}

#[async_trait]
impl TunnelCarrier for VlessCarrier {
    async fn dial(&self) -> Result<BoxedStream> {
        debug!("VLESS Carrier dialing {}:{}", self.address, self.port);
        let (client, _) = tokio::io::duplex(4096);
        Ok(Box::new(client))
    }

    fn protocol(&self) -> &str {
        "vless"
    }
}

/// Peer Carrier with UDP Hole Punching and Relay Fallback
pub struct PeerCarrier {
    pub peer_id: String,
    pub direct_addr: SocketAddr,
    pub relay_addr: String,
    pub relay_port: u16,
    pub our_nat_type: NatType,
    pub peer_nat_type: NatType,
    pub predicted_ports: Vec<u16>,
}

impl PeerCarrier {
    pub fn new(
        peer_id: String,
        direct_addr: SocketAddr,
        relay_addr: String,
        relay_port: u16,
    ) -> Self {
        Self {
            peer_id,
            direct_addr,
            relay_addr,
            relay_port,
            our_nat_type: NatType::Unknown,
            peer_nat_type: NatType::Unknown,
            predicted_ports: Vec::new(),
        }
    }

    pub fn with_nat_info(mut self, our_nat: NatType, peer_nat: NatType) -> Self {
        self.our_nat_type = our_nat;
        self.peer_nat_type = peer_nat;
        self
    }

    pub fn with_predicted_ports(mut self, ports: Vec<u16>) -> Self {
        self.predicted_ports = ports;
        self
    }
}

#[async_trait]
impl TunnelCarrier for PeerCarrier {
    async fn dial(&self) -> Result<BoxedStream> {
        info!(
            "Attempting P2P connection to {} ({}) [Our NAT: {:?}, Peer NAT: {:?}]",
            self.peer_id, self.direct_addr, self.our_nat_type, self.peer_nat_type
        );

        let strategy = determine_connection_strategy(self.our_nat_type, self.peer_nat_type);
        info!("Connection strategy: {:?}", strategy);

        match strategy {
            ConnectionStrategy::DirectConnect => {
                // Try direct connection
                match self.try_direct_connection().await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => {
                        warn!("Direct connection failed: {}", e);
                    }
                }
            }
            ConnectionStrategy::HolePunch => {
                // Standard hole punching
                match self.try_hole_punch().await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => {
                        warn!("Hole punch failed: {}", e);
                    }
                }
            }
            ConnectionStrategy::SymmetricHolePunch => {
                // Symmetric NAT hole punching with port prediction
                match self.try_symmetric_hole_punch().await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => {
                        warn!("Symmetric hole punch failed: {}", e);
                    }
                }
            }
            ConnectionStrategy::Relay => {
                info!("NAT types require relay, skipping direct attempts");
            }
        }

        // Fallback to relay
        warn!(
            "P2P connection failed for {}. Falling back to relay at {}:{}",
            self.peer_id, self.relay_addr, self.relay_port
        );
        let relay = FlowJCarrier::new(self.relay_addr.clone(), self.relay_port);
        relay.dial().await
    }

    fn protocol(&self) -> &str {
        "flow-j-p2p"
    }
}

impl PeerCarrier {
    async fn try_direct_connection(&self) -> Result<BoxedStream> {
        debug!("Trying direct connection to {}", self.direct_addr);

        // Create UDP socket for initial handshake
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.direct_addr).await?;

        // Send handshake packet
        let handshake = b"FLOWJ-P2P-HELLO";
        socket.send(handshake).await?;

        // Wait for response
        let mut buf = [0u8; 64];
        let result = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await;

        match result {
            Ok(Ok(_len)) => {
                info!("Direct connection established with {}", self.peer_id);
                // In production: upgrade UDP socket to QUIC stream
                let (client, _) = tokio::io::duplex(4096);
                Ok(Box::new(client))
            }
            _ => Err(anyhow::anyhow!("Direct connection timeout")),
        }
    }

    async fn try_hole_punch(&self) -> Result<BoxedStream> {
        debug!("Initiating UDP hole punch to {}", self.direct_addr);

        let mut coordinator = HolePunchCoordinator::new().with_attempts(15);

        match coordinator
            .punch_hole(self.direct_addr, self.peer_nat_type)
            .await
        {
            Ok(socket) => {
                info!("Hole punch successful to {}", self.peer_id);
                // Upgrade to Flow-J QUIC handshake
                self.upgrade_to_quic(socket).await
            }
            Err(e) => Err(e),
        }
    }

    async fn try_symmetric_hole_punch(&self) -> Result<BoxedStream> {
        debug!(
            "Initiating symmetric NAT hole punch to {} with {} predicted ports",
            self.direct_addr.ip(),
            self.predicted_ports.len()
        );

        let mut coordinator = HolePunchCoordinator::new().with_attempts(20);

        // Use predicted ports if available, otherwise generate a range
        let ports = if self.predicted_ports.is_empty() {
            // Generate a range around the known port
            let base = self.direct_addr.port();
            (-10..=10i32)
                .map(|delta| (base as i32 + delta) as u16)
                .collect()
        } else {
            self.predicted_ports.clone()
        };

        match coordinator
            .punch_hole_symmetric(self.direct_addr.ip(), &ports)
            .await
        {
            Ok(socket) => {
                info!("Symmetric hole punch successful to {}", self.peer_id);
                self.upgrade_to_quic(socket).await
            }
            Err(e) => Err(e),
        }
    }

    async fn upgrade_to_quic(&self, _socket: Arc<UdpSocket>) -> Result<BoxedStream> {
        // In production: perform Flow-J QUIC handshake over the punched hole
        // For now, return a duplex stream as placeholder
        debug!("Upgrading hole-punched connection to Flow-J QUIC");
        let (client, _) = tokio::io::duplex(4096);
        Ok(Box::new(client))
    }
}

/// Mesh Client: The Active Tunnel Maintainer
pub struct MeshClient {
    carrier: Box<dyn TunnelCarrier>,
    session: Mutex<Option<SessionToken>>,
    cancellation_token: CancellationToken,
    link_change_notify: Arc<tokio::sync::Notify>,
}

impl MeshClient {
    pub fn new(carrier: Box<dyn TunnelCarrier>) -> Self {
        Self {
            carrier,
            session: Mutex::new(None),
            cancellation_token: CancellationToken::new(),
            link_change_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Run the bridge loop with dynamic IP resilience
    pub async fn run(&self) {
        loop {
            if self.cancellation_token.is_cancelled() {
                info!("MeshClient stopping due to cancellation");
                break;
            }

            // 1. Check/Resume Session
            let token = {
                let mut session_lock = self.session.lock().await;
                if let Some(tok) = &*session_lock {
                    if tok.is_valid() {
                        tok.clone()
                    } else {
                        info!("Session expired, creating new");
                        let new_tok = SessionToken::new(Duration::from_secs(3600));
                        *session_lock = Some(new_tok.clone());
                        new_tok
                    }
                } else {
                    let new_tok = SessionToken::new(Duration::from_secs(3600));
                    *session_lock = Some(new_tok.clone());
                    new_tok
                }
            };

            info!(
                "Dialing Portal via Carrier: {} [Session: {}]",
                self.carrier.protocol(),
                token.id
            );

            // 2. Dial Carrier
            let dial_future = self.carrier.dial();
            let link_change_notify = self.link_change_notify.clone();

            let stream_result = tokio::select! {
                res = dial_future => res,
                _ = link_change_notify.notified() => {
                    info!("Link change detected during dial. Retrying immediately...");
                    continue;
                }
                _ = self.cancellation_token.cancelled() => {
                    break;
                }
            };

            match stream_result {
                Ok(mut stream) => {
                    info!("Tunnel established. Maintaining session...");

                    // 3. Maintain connection (yamux mux loop or simple keep-alive)
                    loop {
                        tokio::select! {
                            _ = link_change_notify.notified() => {
                                info!("Link change detected! Dropping current tunnel and reconnecting...");
                                break; // Break inner loop to re-dial
                            }
                            _ = self.cancellation_token.cancelled() => {
                                return; // Exit run completely
                            }
                            // Wait for stream close/error
                            read_res = stream.read_u8() => {
                                match read_res {
                                    Ok(_) => {
                                        // Received keep-alive/control byte
                                    }
                                    Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                        warn!("Tunnel closed by remote. Reconnecting...");
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Tunnel read error: {}. Reconnecting...", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Carrier dial failed ({}), retrying...", e);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                        _ = link_change_notify.notified() => {
                            info!("Link change detected during retry wait. Retrying immediately...");
                        }
                        _ = self.cancellation_token.cancelled() => {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Stop the mesh client
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }

    /// Handle IP/Link Change Event
    pub async fn handle_link_change(&self) {
        warn!("Link Change detected! Triggering immediate Re-Dial with session resumption.");
        self.link_change_notify.notify_waiters();
    }
}

/// Reverse Portal: The Server Side
#[derive(Debug)]
pub struct ReversePortal {
    sessions: DashMap<String, SessionToken>,
}

impl ReversePortal {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn validate_session(&self, token: &SessionToken) -> bool {
        token.is_valid()
    }

    pub fn handle_connection(&self, _stream: BoxedStream) {
        debug!("ReversePortal handling new connection");
    }
}

impl Default for ReversePortal {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse Manager: Coordinates NAT traversal, signaling, and peer connections
pub struct ReverseManager {
    managers: DashMap<String, Arc<ReversePortal>>,
    stun_client: Option<Arc<StunClient>>,
    peer_connections: DashMap<String, Arc<MeshClient>>,
    relay_addr: String,
    relay_port: u16,
    cancellation_token: CancellationToken,
}

impl Default for ReverseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReverseManager {
    pub fn new() -> Self {
        Self {
            managers: DashMap::new(),
            stun_client: None,
            peer_connections: DashMap::new(),
            relay_addr: "relay.example.com".to_string(),
            relay_port: 443,
            cancellation_token: CancellationToken::new(),
        }
    }

    /// Configure with STUN server for NAT detection
    pub fn with_stun(mut self, stun_server: String) -> Self {
        let client = Arc::new(StunClient::new(stun_server));
        let client_clone = client.clone();

        // Start STUN discovery in background
        tokio::spawn(async move {
            client_clone.run_discovery().await;
        });

        self.stun_client = Some(client);
        self
    }

    /// Configure with multiple STUN servers
    pub fn with_stun_servers(mut self, primary: String, fallbacks: Vec<String>) -> Self {
        let client = Arc::new(StunClient::with_servers(primary, fallbacks));
        let client_clone = client.clone();

        tokio::spawn(async move {
            client_clone.run_discovery().await;
        });

        self.stun_client = Some(client);
        self
    }

    /// Set the relay server for fallback connections
    pub fn with_relay(mut self, addr: String, port: u16) -> Self {
        self.relay_addr = addr;
        self.relay_port = port;
        self
    }

    /// Start listening for peer join signals and initiate connections
    pub fn start_peer_join_handler(&self, mut peer_join_rx: PeerJoinReceiver) {
        let stun_client = self.stun_client.clone();
        let relay_addr = self.relay_addr.clone();
        let relay_port = self.relay_port;
        let peer_connections = self.peer_connections.clone();
        let token = self.cancellation_token.clone();

        tokio::spawn(async move {
            info!("Starting peer join handler");

            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        info!("Peer join handler stopping");
                        break;
                    }
                    Some(peer_join) = peer_join_rx.recv() => {
                        info!("Received PeerJoin signal from {}", peer_join.peer_id);

                        // Get our NAT type
                        let our_nat = if let Some(client) = &stun_client {
                            client.get_nat_info().await.nat_type
                        } else {
                            NatType::Unknown
                        };

                        // Create peer carrier with NAT info
                        let carrier = Box::new(
                            PeerCarrier::new(
                                peer_join.peer_id.clone(),
                                peer_join.public_addr,
                                relay_addr.clone(),
                                relay_port,
                            )
                            .with_nat_info(our_nat, peer_join.nat_type)
                            .with_predicted_ports(peer_join.predicted_ports)
                        );

                        // Create and start mesh client
                        let client = Arc::new(MeshClient::new(carrier));
                        let client_clone = client.clone();

                        peer_connections.insert(peer_join.peer_id.clone(), client);

                        tokio::spawn(async move {
                            client_clone.run().await;
                        });
                    }
                }
            }
        });
    }

    /// Register a portal connection (Bridge -> Portal)
    pub fn register_portal(&self, tag: &str, stream: BoxedStream) {
        let portal = self
            .managers
            .entry(tag.to_string())
            .or_insert_with(|| Arc::new(ReversePortal::new()));
        portal.handle_connection(stream);
    }

    /// Get a stream from the portal (User -> Portal -> Bridge)
    pub async fn send_to_portal(
        &self,
        tag: &str,
        _original_stream: BoxedStream,
    ) -> Result<BoxedStream> {
        if let Some(_portal) = self.managers.get(tag) {
            let (s, _) = tokio::io::duplex(1024);
            Ok(Box::new(s))
        } else {
            Err(anyhow::anyhow!("Portal not found for tag: {}", tag))
        }
    }

    /// Get current NAT information
    pub async fn get_nat_info(&self) -> Option<NatInfo> {
        if let Some(client) = &self.stun_client {
            Some(client.get_nat_info().await)
        } else {
            None
        }
    }

    /// Get the STUN client
    pub fn get_stun_client(&self) -> Option<Arc<StunClient>> {
        self.stun_client.clone()
    }

    /// Initiate a connection to a peer (P2P with Relay Fallback)
    pub async fn connect_peer(
        &self,
        peer_id: &str,
        direct_addr: SocketAddr,
        peer_nat_type: NatType,
        predicted_ports: Vec<u16>,
    ) {
        let our_nat = if let Some(client) = &self.stun_client {
            client.get_nat_info().await.nat_type
        } else {
            NatType::Unknown
        };

        let carrier = Box::new(
            PeerCarrier::new(
                peer_id.to_string(),
                direct_addr,
                self.relay_addr.clone(),
                self.relay_port,
            )
            .with_nat_info(our_nat, peer_nat_type)
            .with_predicted_ports(predicted_ports),
        );

        let client = Arc::new(MeshClient::new(carrier));
        let client_clone = client.clone();

        self.peer_connections.insert(peer_id.to_string(), client);

        tokio::spawn(async move {
            client_clone.run().await;
        });
    }

    /// Disconnect from a peer
    pub fn disconnect_peer(&self, peer_id: &str) {
        if let Some((_, client)) = self.peer_connections.remove(peer_id) {
            client.stop();
            info!("Disconnected from peer: {}", peer_id);
        }
    }

    /// Stop all connections and cleanup
    pub fn shutdown(&self) {
        self.cancellation_token.cancel();
        for entry in self.peer_connections.iter() {
            entry.value().stop();
        }
        self.peer_connections.clear();
        info!("ReverseManager shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_carrier_strategy() {
        let carrier = PeerCarrier::new(
            "test-peer".to_string(),
            "1.2.3.4:5678".parse().unwrap(),
            "relay.test".to_string(),
            443,
        )
        .with_nat_info(NatType::PortRestrictedCone, NatType::PortRestrictedCone);

        assert_eq!(carrier.protocol(), "flow-j-p2p");
        assert_eq!(carrier.our_nat_type, NatType::PortRestrictedCone);
    }

    #[tokio::test]
    async fn test_reverse_manager_creation() {
        let manager = ReverseManager::new().with_relay("relay.test.com".to_string(), 8443);

        assert_eq!(manager.relay_addr, "relay.test.com");
        assert_eq!(manager.relay_port, 8443);
    }
}
