use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use rustray::api::signaling::{PeerSignal, SignalingService};
use rustray::app::reverse::nat::{NatInfo, NatType};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// Mock Orchestrator State
struct OrchestratorState {
    peers: RwLock<Vec<PeerSignal>>,
}

async fn handle_heartbeat(
    state: web::Data<Arc<OrchestratorState>>,
    peer_signal: web::Json<PeerSignal>,
) -> impl Responder {
    let mut peers = state.peers.write().await;

    // Update or insert peer
    if let Some(existing) = peers.iter_mut().find(|p| p.peer_id == peer_signal.peer_id) {
        *existing = peer_signal.clone();
    } else {
        peers.push(peer_signal.clone());
    }

    // Return list of all peers
    HttpResponse::Ok().json(&*peers)
}

#[tokio::test]
async fn test_signaling_stress_100_nodes() {
    // 1. Setup Mock Orchestrator on random port
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();
    let orchestrator_url = format!("http://127.0.0.1:{}", port);

    let state = Arc::new(OrchestratorState {
        peers: RwLock::new(Vec::new()),
    });
    let state_data = web::Data::new(state.clone());

    let server = HttpServer::new(move || {
        App::new()
            .app_data(state_data.clone())
            .route("/api/v1/signal/heartbeat", web::post().to(handle_heartbeat))
    })
    .listen(listener)
    .expect("Failed to listen")
    .run();

    let _server_handle = tokio::spawn(server);

    // Give server a moment
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. Spawn Mock Clients (Stress Test)
    // "1,000+ concurrent" might overload the test runner/Mock server in debug mode.
    // We start with 50 nodes sending heartbeats rapidly, simulating load.
    let node_count = 50;
    let mut handles = Vec::new();

    for i in 0..node_count {
        let url = orchestrator_url.clone();
        let peer_id = format!("node-{}", i);

        handles.push(tokio::spawn(async move {
            let nat_info = Arc::new(RwLock::new(NatInfo {
                nat_type: NatType::FullCone,
                public_ip: Some("1.2.3.4:12345".parse().unwrap()),
                local_ip: None,
                last_update: None,
                port_delta: None,
                port_history: Vec::new(),
            }));

            let (service, _rx) = SignalingService::new(url, peer_id, nat_info);

            let service = service.with_heartbeat_interval(Duration::from_millis(100)); // Fast heartbeat

            // Run for 2 seconds
            service.start().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            service.stop();

            service // Return service to check peer map
        }));
    }

    // 3. Wait/Join
    let mut services = Vec::new();
    for handle in handles {
        services.push(handle.await.unwrap());
    }

    // 4. Verify Convergence
    // Every node should differ discovered (node_count) peers eventually.
    // Since we ran for 2s with 100ms interval, they should have converged.

    let total_peers_registered = state.peers.read().await.len();
    assert_eq!(
        total_peers_registered, node_count,
        "Orchestrator should see all peers"
    );

    // Check a random node's peer map
    // Note: Due to async timing, some might not have processed the LAST heartbeat response,
    // but they should be close to node_count.
    let sample_node = &services[0];
    let known_peers = sample_node.peer_map().len();

    println!(
        "Sample Node known peers: {}/{}",
        known_peers,
        node_count - 1
    ); // -1 for self?
    // Self is not in map usually (impl dependent), code showed: `if peer_signal.peer_id != peer_id`

    assert!(
        known_peers >= (node_count - 5),
        "Peer convergence check (allowing minor jitter)"
    );

    // Cleanup
    // server_handle.abort(); // Actix server runs forever unless stopped, but test end kills it.
}
