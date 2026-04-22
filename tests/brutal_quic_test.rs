// tests/brutal_quic_test.rs
use rustray::transport::brutal_cc::BrutalCongestionController;
use rustray::transport::flow_j_brutal::BrutalTransportConfig;
use rustray::transport::brutal_cc::BrutalCcConfig;
use quinn::congestion::Controller;
use std::time::Instant;

#[tokio::test]
async fn test_brutal_cc_pacing() {
    // 10 Mbps = 1.25 MB/s
    let mut cc = BrutalCongestionController::new(10);
    
    // Initial window should be minimum
    let initial = cc.window();
    assert!(initial > 0);
    
    // Simulate RTT and ACKs
    let now = Instant::now();
    
    // Simulate some acks, brutal CC should just pace based on RTT. 
    // It ignores loss. We verify it doesn't crash on congestion.
    cc.on_congestion_event(now, now, false, 1000); // Should be ignored
    
    let w1 = cc.window();
    
    // If it were cubic/reno, the window would drop on congestion.
    // For Brutal, it maintains pacing based on configured upload speed and RTT.
    assert!(w1 >= initial);
}

#[tokio::test]
async fn test_flow_j_brutal_config() {
    let config = BrutalTransportConfig {
        address: "127.0.0.1:443".to_string(),
        server_name: "test.local".to_string(),
        bandwidth: BrutalCcConfig {
            upload_mbps: 100,
            download_mbps: 100,
        },
        fec: Default::default(),
        fec_enabled: true,
    };
    
    // We only test config construction and types for unit testing,
    // as full QUIC stream tests require a quinn server on the other end
    // which is covered in `stability_e2e.rs`.
    assert_eq!(config.address, "127.0.0.1:443");
    assert_eq!(config.server_name, "test.local");
}
