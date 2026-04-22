// tests/handshake_forensics_test.rs
use rustray::config::TlsFragmentSettings;
use rustray::transport::tls_fragment::FragmentStream;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_handshake_forensics_fragmentation() {
    // 1. Setup a listener to capture fragments
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut captured = Vec::new();
        let mut fragment_times = Vec::new();
        let mut buffer = [0u8; 2048];

        loop {
            let start = Instant::now();
            match socket.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    fragment_times.push(start);
                    captured.push(buffer[..n].to_vec());
                }
                Err(_) => break,
            }
        }
        (captured, fragment_times)
    });

    // 2. Client sends a ClientHello via FragmentStream
    let client_socket = TcpStream::connect(addr).await.unwrap();
    let settings = TlsFragmentSettings {
        length: "100-200".to_string(),
        interval: "1-10".to_string(),
    };
    // Wrap the socket in a FragmentStream.
    let mut fragment_stream = FragmentStream::new(Box::new(client_socket), settings);

    // Realistic TLS v1.2 ClientHello (truncated for brevity but identifiable)
    let mut client_hello = vec![0x16, 0x03, 0x01, 0x01, 0x2C]; // Header: Handshake, TLS 1.0, 300 bytes
    client_hello.extend(vec![0x01, 0x00, 0x01, 0x28]); // Handshake Type: ClientHello, Length: 296
    client_hello.resize(305, 0xAB); // Payload padding

    fragment_stream.write_all(&client_hello).await.unwrap();
    fragment_stream.shutdown().await.unwrap();

    let (captured, fragment_times) = server_handle.await.unwrap();

    // 3. Validation
    // Note: Due to TCP nagling or buffering, we might not see exact fragments
    // as distinct reads if they arrive too fast, but since we have 1-10ms delays,
    // they SHOULD arrive as distinct reads on a local interface.

    assert!(
        captured.len() >= 3,
        "Expected at least 3 fragments, got {}",
        captured.len()
    );

    // The first fragment must be < 5 bytes to hide the SNI/Handshake header.
    // In our implementation, we split the 5-byte header itself or immediately after.
    assert!(
        captured[0].len() < 5,
        "First fragment should be < 5 bytes, got {}",
        captured[0].len()
    );

    // Verify inter-fragment delays.
    // We expect at least 2 delays. Because of OS scheduling, delays can be slightly longer,
    // but should be at least ~300us (0.3ms).
    for i in 0..fragment_times.len().saturating_sub(1) {
        let diff = fragment_times[i + 1].duration_since(fragment_times[i]);
        println!("Fragment {} delay: {:?}", i, diff);
        assert!(
            diff.as_micros() >= 250, // allow 50us scheduling margin
            "Delay {:?} is shorter than the 300us minimum",
            diff
        );
    }

    // Reconstruct and verify integrity
    let reconstructed: Vec<u8> = captured.into_iter().flatten().collect();
    assert_eq!(
        reconstructed, client_hello,
        "Reconstructed ClientHello mismatch"
    );
}
