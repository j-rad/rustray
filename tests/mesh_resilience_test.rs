// tests/mesh_resilience_test.rs
use rustray::app::reverse::{FlowJCarrier, MeshClient};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_mesh_ip_swap_recovery() {
    // 1. Setup Bridge with Flow-J Carrier
    // We mock the carrier dialing by using 127.0.0.1:443
    // In strict testing we might want a real listener, but the `FlowJCarrier::dial`
    // implementation currently uses `tokio::io::duplex` for simulation as per previous step.
    let carrier = Box::new(FlowJCarrier::new("127.0.0.1".to_string(), 443));
    let bridge = Arc::new(MeshClient::new(carrier));

    // 2. Run Bridge in background
    let bg_bridge = bridge.clone();

    let run_handle = tokio::spawn(async move {
        // Run loop with a timeout.
        // We expect it to run continuously dialing and holding/waiting.
        // We'll give it enough time to dial a couple of times.
        if let Err(_) = timeout(Duration::from_secs(3), bg_bridge.run()).await {
            // Timeout is expected as run() loops forever
            return "looped";
        }
        "exited"
    });

    // 3. Trigger "Link Change" simulation
    // Simulate event trigger
    bridge.handle_link_change().await;

    let res = run_handle.await.unwrap();
    assert_eq!(
        res, "looped",
        "Bridge should maintain loop despite link change"
    );
}
