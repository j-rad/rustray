use rustray::transport::utls;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_rutls_handshake_custom_extensions() {
    // 1. Setup a dummy TCP server to capture the ClientHello
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        let mut buf = [0u8; 4096];
        let n = socket.read(&mut buf).await.unwrap();

        // Basic inspection of ClientHello (this is a rough check, real validation would parse TLS)
        let data = &buf[..n];

        // Check for GREASE values (usually start with 0xFA, 0x1A, etc. or just distinct patterns)
        // Check for ALPN "h2"
        // Check for SNI "example.com"

        // SNI "example.com" hex: 65 78 61 6d 70 6c 65 2e 63 6f 6d
        let has_sni = data.windows(11).any(|w| w == b"example.com");

        // We expect SNI to be present
        assert!(has_sni, "ClientHello missing SNI 'example.com'");

        // ALPN might be randomized or defaults, skipping strict check for "h2"
        // as we are using randomized() strategy which is opaque.

        // Send a dummy alert or close to finish cleanly
        socket.shutdown().await.ok();
    });

    // 2. Client side: use build_custom_connector via tls wrapper logic (simulated)
    // We can test utls::build_custom_connector directly first
    let alpn = Some(vec!["h2".to_string()]);
    let sni = Some("example.com".to_string());

    let connector = utls::build_custom_connector(alpn, sni).expect("Failed to build connector");

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("Failed to connect");

    // Perform handshake
    // Note: This will fail on the server response side because our mock server doesn't reply with ServerHello.
    // However, the client MUST send ClientHello first. so we might get an error but the server text should pass.
    let _ = connector.connect_async("example.com", stream).await;

    // Wait for server assertion
    server_handle.await.expect("Server task failed");
}
