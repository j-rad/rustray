// tests/desync_http_tls_test.rs
//! Integration test for the Application-Layer Desynchronization Engine.

use rustray::transport::desync::{DesyncConfig, DesyncStrategy, DesyncStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test]
async fn test_desync_split_fragments_tls_header() {
    let config = DesyncConfig {
        strategy: DesyncStrategy::Split,
        split_offset: 5, // After TLS record header
        delay_ms: 10,
        first_n_writes: 1,
    };

    // Create a duplex pair to capture output
    let (client, mut server) = duplex(4096);
    let mut desync = DesyncStream::new(client, config);

    // Simulate TLS ClientHello (simplified)
    let tls_record = b"\x16\x03\x01\x02\x00ClientHelloPayloadData";

    // Write the TLS payload through the desync wrapper
    let written = desync.write(tls_record).await.unwrap();
    assert_eq!(written, tls_record.len());

    // Read what the server received (should be fragmented)
    let mut received = vec![0u8; 1024];
    let n = server.read(&mut received).await.unwrap();
    assert!(n > 0, "Should have received data");

    // The first 5 bytes should be the TLS record header
    assert_eq!(&received[..5], &tls_record[..5]);
}

#[tokio::test]
async fn test_desync_passthrough_after_first_write() {
    let config = DesyncConfig {
        strategy: DesyncStrategy::Split,
        split_offset: 5,
        delay_ms: 1,
        first_n_writes: 1,
    };

    let (client, mut server) = duplex(4096);
    let mut desync = DesyncStream::new(client, config);

    // First write triggers desync
    let data1 = b"\x16\x03\x01\x02\x00Hello";
    let _ = desync.write(data1).await.unwrap();

    // Read the desync'd data
    let mut buf = vec![0u8; 1024];
    let _ = server.read(&mut buf).await.unwrap();

    // Wait for delay to complete
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Read remainder after delay
    let mut buf2 = vec![0u8; 1024];
    match tokio::time::timeout(
        std::time::Duration::from_millis(100),
        server.read(&mut buf2)
    ).await {
        Ok(Ok(n)) if n > 0 => {
            // Good, received the second fragment
        }
        _ => {
            // May have been combined, that's OK
        }
    }

    // Second write should pass through without desync
    let data2 = b"subsequent data should pass through";
    let written = desync.write(data2).await.unwrap();
    assert_eq!(written, data2.len());

    let mut buf3 = vec![0u8; 1024];
    let n = server.read(&mut buf3).await.unwrap();
    assert_eq!(&buf3[..n], data2);
}

#[tokio::test]
async fn test_desync_small_payload_passthrough() {
    // Payload smaller than split_offset should pass through unchanged
    let config = DesyncConfig {
        strategy: DesyncStrategy::Split,
        split_offset: 10,
        delay_ms: 50,
        first_n_writes: 1,
    };

    let (client, mut server) = duplex(4096);
    let mut desync = DesyncStream::new(client, config);

    let small_data = b"tiny";
    let written = desync.write(small_data).await.unwrap();
    assert_eq!(written, small_data.len());

    let mut buf = vec![0u8; 1024];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], small_data);
}
