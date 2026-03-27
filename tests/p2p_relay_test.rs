// tests/p2p_relay_test.rs
use rustray::p2p::relay::{RelayConfig, RelayListener};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_p2p_relay_connection() {
    let psk = "test_psk_12345".to_string();
    let port = 34567; // Use specific port for test
    let listen_addr = format!("127.0.0.1:{}", port);
    
    let config = RelayConfig {
        listen: listen_addr.clone(),
        psk: psk.clone(),
        max_peers: 5,
    };
    
    let listener = RelayListener::new(config);
    
    tokio::spawn(async move {
        let _ = listener.listen().await;
    });
    
    // Give server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    // Test successful authentication
    let mut client = RelayListener::connect_to_relay(&listen_addr, &psk).await.unwrap();
    client.write_all(b"PING").await.unwrap();
    
    // Test failed authentication
    let failed_auth = RelayListener::connect_to_relay(&listen_addr, "wrongpsk").await;
    assert!(failed_auth.is_err(), "Authentication should have failed with wrong PSK");
}
