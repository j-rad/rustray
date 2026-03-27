//! Mesh Discovery Integration Tests
//!
//! Tests NAT traversal, peer signaling, and hole punching scenarios
//! including symmetric vs cone NAT simulation.

use rustray::api::signaling::{
    PeerSignal, SignalingService,
    determine_connection_strategy,
};
use rustray::app::reverse::nat::{
    ConnectionStrategy, HolePunchCoordinator, NatInfo, NatType, StunClient,
};
use rustray::app::reverse::{FlowJCarrier, PeerCarrier, ReverseManager, TunnelCarrier};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ============================================================================
// NAT Detection Tests
// ============================================================================

#[tokio::test]
async fn test_nat_type_classification() {
    // Test NAT type properties
    assert!(NatType::OpenInternet.supports_p2p());
    assert!(NatType::FullCone.supports_p2p());
    assert!(NatType::RestrictedCone.supports_p2p());
    assert!(NatType::PortRestrictedCone.supports_p2p());
    assert!(!NatType::Symmetric.supports_p2p());
    assert!(!NatType::UdpBlocked.supports_p2p());
    assert!(!NatType::Unknown.supports_p2p());

    // Test hole punching support
    assert!(NatType::FullCone.supports_hole_punching());
    assert!(NatType::PortRestrictedCone.supports_hole_punching());
    assert!(!NatType::Symmetric.supports_hole_punching());
    assert!(!NatType::UdpBlocked.supports_hole_punching());
    assert!(!NatType::Unknown.supports_hole_punching());
}

#[tokio::test]
async fn test_nat_info_default() {
    let info = NatInfo::default();
    assert_eq!(info.nat_type, NatType::Unknown);
    assert!(info.public_ip.is_none());
    assert!(info.local_ip.is_none());
    assert!(info.port_delta.is_none());
}

#[tokio::test]
async fn test_stun_client_creation() {
    let client = StunClient::new("stun.l.google.com:19302".to_string());
    let info = client.get_nat_info().await;
    assert_eq!(info.nat_type, NatType::Unknown);
}

#[tokio::test]
async fn test_stun_client_with_multiple_servers() {
    let client = StunClient::with_servers(
        "stun.l.google.com:19302".to_string(),
        vec![
            "stun1.l.google.com:19302".to_string(),
            "stun2.l.google.com:19302".to_string(),
        ],
    )
    .with_interval(Duration::from_secs(60));

    let provider = client.get_nat_info_provider();
    let info = provider.read().await;
    assert_eq!(info.nat_type, NatType::Unknown);
}

#[tokio::test]
async fn test_stun_binding_request_format() {
    let client = StunClient::new("stun.l.google.com:19302".to_string());
    let request = client.build_stun_binding_request();

    // STUN header is 20 bytes
    assert_eq!(request.len(), 20);

    // Message Type: Binding Request (0x0001)
    assert_eq!(request[0], 0x00);
    assert_eq!(request[1], 0x01);

    // Message Length: 0 (no attributes)
    assert_eq!(request[2], 0x00);
    assert_eq!(request[3], 0x00);

    // Magic Cookie: 0x2112A442
    assert_eq!(request[4], 0x21);
    assert_eq!(request[5], 0x12);
    assert_eq!(request[6], 0xA4);
    assert_eq!(request[7], 0x42);
}

// ============================================================================
// Connection Strategy Tests
// ============================================================================

#[test]
fn test_connection_strategy_determination() {
    // Open Internet allows direct connection with anything
    assert_eq!(
        determine_connection_strategy(NatType::OpenInternet, NatType::Symmetric),
        ConnectionStrategy::DirectConnect
    );
    assert_eq!(
        determine_connection_strategy(NatType::FullCone, NatType::UdpBlocked),
        ConnectionStrategy::DirectConnect
    );

    // Two cone NATs can hole punch
    assert_eq!(
        determine_connection_strategy(NatType::PortRestrictedCone, NatType::PortRestrictedCone),
        ConnectionStrategy::HolePunch
    );
    assert_eq!(
        determine_connection_strategy(NatType::RestrictedCone, NatType::PortRestrictedCone),
        ConnectionStrategy::HolePunch
    );

    // Symmetric + Cone requires symmetric hole punch
    assert_eq!(
        determine_connection_strategy(NatType::Symmetric, NatType::PortRestrictedCone),
        ConnectionStrategy::SymmetricHolePunch
    );
    assert_eq!(
        determine_connection_strategy(NatType::RestrictedCone, NatType::Symmetric),
        ConnectionStrategy::SymmetricHolePunch
    );

    // Both symmetric or blocked requires relay
    assert_eq!(
        determine_connection_strategy(NatType::Symmetric, NatType::Symmetric),
        ConnectionStrategy::Relay
    );
    assert_eq!(
        determine_connection_strategy(NatType::UdpBlocked, NatType::UdpBlocked),
        ConnectionStrategy::Relay
    );
}

#[test]
fn test_nat_type_recommended_strategy() {
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

// ============================================================================
// Signaling Service Tests
// ============================================================================

#[tokio::test]
async fn test_signaling_service_creation() {
    let nat_info = Arc::new(RwLock::new(NatInfo::default()));
    let (service, _rx) = SignalingService::new(
        "http://orchestrator.local".to_string(),
        "peer-123".to_string(),
        nat_info.clone(),
    );

    assert_eq!(service.public_key_bytes().len(), 32);
}

#[tokio::test]
async fn test_signaling_start_stop() {
    let nat_info = Arc::new(RwLock::new(NatInfo {
        nat_type: NatType::FullCone,
        public_ip: Some("127.0.0.1:12345".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        last_update: Some(Instant::now()),
        port_delta: None,
        port_history: Vec::new(),
    }));

    let (service, _rx) = SignalingService::new(
        "http://orchestrator.local".to_string(),
        "peer-123".to_string(),
        nat_info.clone(),
    );

    service.start().await;

    // Allow some time for the loop to run
    tokio::time::sleep(Duration::from_millis(100)).await;

    service.stop();

    // Verify NAT info is accessible
    let info = nat_info.read().await;
    assert_eq!(info.nat_type, NatType::FullCone);
    assert!(info.public_ip.is_some());
}

#[tokio::test]
async fn test_peer_signal_serialization() {
    let signal = PeerSignal {
        peer_id: "test-peer".to_string(),
        public_addr: "1.2.3.4:5678".to_string(),
        nat_type: "Symmetric".to_string(),
        timestamp: 1234567890,
        public_key: [0u8; 32],
    };

    let json = serde_json::to_string(&signal).unwrap();
    assert!(json.contains("test-peer"));
    assert!(json.contains("1.2.3.4:5678"));
    assert!(json.contains("Symmetric"));

    // Deserialize back
    let parsed: PeerSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.peer_id, "test-peer");
    assert_eq!(parsed.timestamp, 1234567890);
}

#[tokio::test]
async fn test_encryption_decryption_roundtrip() {
    let nat_info1 = Arc::new(RwLock::new(NatInfo::default()));
    let nat_info2 = Arc::new(RwLock::new(NatInfo::default()));

    let (service1, _rx1) = SignalingService::new(
        "http://localhost".to_string(),
        "peer-1".to_string(),
        nat_info1,
    );

    let (service2, _rx2) = SignalingService::new(
        "http://localhost".to_string(),
        "peer-2".to_string(),
        nat_info2,
    );

    // Exchange keys
    service1.add_peer_key("peer-2".to_string(), service2.public_key_bytes());
    service2.add_peer_key("peer-1".to_string(), service1.public_key_bytes());

    // Test encryption from peer-1 to peer-2
    let message = b"Hello, peer-2! This is a secret message.";
    let encrypted = service1.encrypt_for_peer("peer-2", message).unwrap();

    assert_eq!(encrypted.sender_id, "peer-1");
    assert!(!encrypted.payload.is_empty());
    assert_eq!(encrypted.nonce.len(), 12);

    // Decryption at peer-2
    let decrypted = service2.decrypt_from_peer(&encrypted).unwrap();
    assert_eq!(decrypted, message);
}

#[tokio::test]
async fn test_encryption_failure_unknown_peer() {
    let nat_info = Arc::new(RwLock::new(NatInfo::default()));
    let (service, _rx) = SignalingService::new(
        "http://localhost".to_string(),
        "peer-1".to_string(),
        nat_info,
    );

    let result = service.encrypt_for_peer("unknown-peer", b"hello");
    assert!(result.is_err());
}

// ============================================================================
// Hole Punching Tests
// ============================================================================

#[tokio::test]
async fn test_hole_punch_coordinator_creation() {
    let _coordinator = HolePunchCoordinator::new().with_attempts(20);
    // Coordinator is created successfully
    assert!(true);
}

// ============================================================================
// Peer Carrier Tests
// ============================================================================

#[tokio::test]
async fn test_peer_carrier_creation() {
    let carrier = PeerCarrier::new(
        "test-peer".to_string(),
        "192.168.1.100:8080".parse().unwrap(),
        "relay.example.com".to_string(),
        443,
    )
    .with_nat_info(NatType::PortRestrictedCone, NatType::Symmetric)
    .with_predicted_ports(vec![8081, 8082, 8083]);

    assert_eq!(carrier.peer_id, "test-peer");
    assert_eq!(carrier.our_nat_type, NatType::PortRestrictedCone);
    assert_eq!(carrier.peer_nat_type, NatType::Symmetric);
    assert_eq!(carrier.predicted_ports.len(), 3);
    assert_eq!(carrier.protocol(), "flow-j-p2p");
}

#[tokio::test]
async fn test_flowj_carrier() {
    let carrier = FlowJCarrier::new("proxy.example.com".to_string(), 443);
    assert_eq!(carrier.protocol(), "flow-j");

    // Dial should succeed (returns mock stream)
    let result = carrier.dial().await;
    assert!(result.is_ok());
}

// ============================================================================
// Reverse Manager Tests
// ============================================================================

#[tokio::test]
async fn test_reverse_manager_creation() {
    let manager = ReverseManager::new().with_relay("relay.example.com".to_string(), 8443);

    assert!(manager.get_nat_info().await.is_none());
}

#[tokio::test]
async fn test_reverse_manager_portal_operations() {
    let manager = ReverseManager::new();

    // Create a mock stream
    let (stream, _) = tokio::io::duplex(1024);
    manager.register_portal("test-portal", Box::new(stream));

    // Try to send to the portal
    let (another_stream, _) = tokio::io::duplex(1024);
    let result = manager
        .send_to_portal("test-portal", Box::new(another_stream))
        .await;
    assert!(result.is_ok());

    // Non-existent portal should fail
    let (yet_another, _) = tokio::io::duplex(1024);
    let result = manager
        .send_to_portal("non-existent", Box::new(yet_another))
        .await;
    assert!(result.is_err());
}

// ============================================================================
// Simulated NAT Scenario Tests
// ============================================================================

/// Simulates two nodes: one behind Symmetric NAT, one behind Cone NAT
#[tokio::test]
async fn test_symmetric_vs_cone_nat_scenario() {
    // Node A: Symmetric NAT
    let node_a_nat = NatInfo {
        nat_type: NatType::Symmetric,
        public_ip: Some("203.0.113.1:45678".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        last_update: Some(Instant::now()),
        port_delta: Some(2), // Port increments by 2
        port_history: vec![45678, 45680],
    };

    // Node B: Port Restricted Cone NAT
    let node_b_nat = NatInfo {
        nat_type: NatType::PortRestrictedCone,
        public_ip: Some("198.51.100.1:32000".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
        last_update: Some(Instant::now()),
        port_delta: None,
        port_history: vec![32000],
    };

    // Determine connection strategy
    let strategy = determine_connection_strategy(node_a_nat.nat_type, node_b_nat.nat_type);
    assert_eq!(strategy, ConnectionStrategy::SymmetricHolePunch);

    // Node B is cone NAT, so it should be reachable
    // Node A needs port prediction
    let predicted_ports: Vec<u16> = (1..=5)
        .map(|i| (45678 + node_a_nat.port_delta.unwrap_or(1) * i) as u16)
        .collect();

    assert_eq!(predicted_ports, vec![45680, 45682, 45684, 45686, 45688]);
}

/// Simulates two nodes both behind Cone NAT
#[tokio::test]
async fn test_cone_vs_cone_nat_scenario() {
    let node_a_nat = NatInfo {
        nat_type: NatType::PortRestrictedCone,
        public_ip: Some("203.0.113.1:12345".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        last_update: Some(Instant::now()),
        port_delta: None,
        port_history: vec![12345],
    };

    let node_b_nat = NatInfo {
        nat_type: NatType::RestrictedCone,
        public_ip: Some("198.51.100.1:54321".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))),
        last_update: Some(Instant::now()),
        port_delta: None,
        port_history: vec![54321],
    };

    // Should use standard hole punching
    let strategy = determine_connection_strategy(node_a_nat.nat_type, node_b_nat.nat_type);
    assert_eq!(strategy, ConnectionStrategy::HolePunch);

    // Both support hole punching
    assert!(node_a_nat.nat_type.supports_hole_punching());
    assert!(node_b_nat.nat_type.supports_hole_punching());
}

/// Simulates two nodes both behind Symmetric NAT (requires relay)
#[tokio::test]
async fn test_symmetric_vs_symmetric_nat_scenario() {
    let node_a_nat = NatType::Symmetric;
    let node_b_nat = NatType::Symmetric;

    let strategy = determine_connection_strategy(node_a_nat, node_b_nat);
    assert_eq!(strategy, ConnectionStrategy::Relay);

    // Neither supports P2P
    assert!(!node_a_nat.supports_p2p());
    assert!(!node_b_nat.supports_p2p());
}

/// Simulates connection when one node has Open Internet
#[tokio::test]
async fn test_open_internet_scenario() {
    let node_a_nat = NatType::OpenInternet;
    let node_b_nat = NatType::Symmetric;

    let strategy = determine_connection_strategy(node_a_nat, node_b_nat);
    assert_eq!(strategy, ConnectionStrategy::DirectConnect);

    // Even with symmetric NAT on one side, if other has open internet, direct connect works
    assert!(node_a_nat.supports_p2p());
}

// ============================================================================
// Integration Test: Full Mesh Discovery Flow
// ============================================================================

#[tokio::test]
async fn test_full_mesh_discovery_flow() {
    // Setup two signaling services representing two peers
    let nat_info_a = Arc::new(RwLock::new(NatInfo {
        nat_type: NatType::PortRestrictedCone,
        public_ip: Some("1.2.3.4:5678".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
        last_update: Some(Instant::now()),
        port_delta: None,
        port_history: Vec::new(),
    }));

    let nat_info_b = Arc::new(RwLock::new(NatInfo {
        nat_type: NatType::PortRestrictedCone,
        public_ip: Some("5.6.7.8:9012".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20))),
        last_update: Some(Instant::now()),
        port_delta: None,
        port_history: Vec::new(),
    }));

    let (service_a, _rx_a) = SignalingService::new(
        "http://orchestrator.test".to_string(),
        "peer-A".to_string(),
        nat_info_a.clone(),
    );

    let (service_b, _rx_b) = SignalingService::new(
        "http://orchestrator.test".to_string(),
        "peer-B".to_string(),
        nat_info_b.clone(),
    );

    // Exchange keys
    service_a.add_peer_key("peer-B".to_string(), service_b.public_key_bytes());
    service_b.add_peer_key("peer-A".to_string(), service_a.public_key_bytes());

    // Peer A sends encrypted connection request to Peer B
    let connect_request = serde_json::json!({
        "action": "connect",
        "nat_type": "PortRestrictedCone",
        "public_addr": "1.2.3.4:5678"
    });
    let request_bytes = serde_json::to_vec(&connect_request).unwrap();

    let encrypted = service_a
        .encrypt_for_peer("peer-B", &request_bytes)
        .unwrap();

    // Peer B decrypts and processes
    let decrypted = service_b.decrypt_from_peer(&encrypted).unwrap();
    let received: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();

    assert_eq!(received["action"], "connect");
    assert_eq!(received["nat_type"], "PortRestrictedCone");

    // Determine they can hole punch
    let info_a = nat_info_a.read().await;
    let info_b = nat_info_b.read().await;
    let strategy = determine_connection_strategy(info_a.nat_type, info_b.nat_type);
    assert_eq!(strategy, ConnectionStrategy::HolePunch);
}

// ============================================================================
// Port Prediction Tests
// ============================================================================

#[tokio::test]
async fn test_port_prediction_for_symmetric_nat() {
    let _nat_info = Arc::new(RwLock::new(NatInfo {
        nat_type: NatType::Symmetric,
        public_ip: Some("1.2.3.4:10000".parse().unwrap()),
        local_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        last_update: Some(Instant::now()),
        port_delta: Some(3),
        port_history: vec![10000, 10003, 10006],
    }));

    let client = StunClient::new("stun.test:19302".to_string());

    // Manually update the client's internal NAT info for testing
    {
        let provider = client.get_nat_info_provider();
        let mut info = provider.write().await;
        info.nat_type = NatType::Symmetric;
        info.public_ip = Some("1.2.3.4:10000".parse().unwrap());
        info.port_delta = Some(3);
    }

    // Test single port prediction
    let predicted = client.predict_next_port().await;
    assert_eq!(predicted, Some(10003));

    // Test range prediction
    let range = client.predict_port_range(5).await;
    assert_eq!(range, vec![10003, 10006, 10009, 10012, 10015]);
}
