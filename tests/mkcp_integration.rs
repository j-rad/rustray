use rustray::config::KcpConfig;
use rustray::transport::mkcp;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_mkcp_loopback() {
    // 1. Start Listener
    let config = Arc::new(KcpConfig {
        mtu: Some(1350),
        tti: Some(20),
        uplink_capacity: Some(10),
        downlink_capacity: Some(10),
        congestion: Some(false),
        ..Default::default()
    });

    // Use a random high port
    let mut listener = mkcp::listen(config.clone(), "127.0.0.1", 12345)
        .await
        .expect("failed to listen");

    // Spawn server
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });

    // 2. Connect Client
    // Give server a moment
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let addr = "127.0.0.1:12345".parse().unwrap();
    let mut client = mkcp::connect(config.clone(), addr)
        .await
        .expect("failed to connect");

    // 3. Write data
    let payload = b"Hello mKCP";
    client.write_all(payload).await.expect("failed to write");

    // 4. Read echo
    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.expect("failed to read");
    assert_eq!(&buf[..n], payload);
}
