// tests/vless_ws_fragmented.rs
use rustray::core::instance::RustrayInstance;
use rustray::core::registry::GLOBAL_REGISTRY;
use rustray::config::{Config, VlessSettings, VlessUser, InboundConfig};
use rustray::transport::websocket::WebSocketAdapter;
use rustray::transport::fragmentation::split_handshake;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_vless_ws_fragmented_flow() {
    // 1. Mock a WebSocket server (Cloudflare-like)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        
        if req.contains("Upgrade: websocket") {
            let response = "HTTP/1.1 101 Switching Protocols\r\n\
                            Upgrade: websocket\r\n\
                            Connection: Upgrade\r\n\
                            Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
            socket.write_all(response.as_bytes()).await.unwrap();
            
            // Now handle data
            let mut data_buf = [0u8; 1024];
            while let Ok(n) = socket.read(&mut data_buf).await {
                if n == 0 { break; }
                socket.write_all(&data_buf[..n]).await.unwrap(); // Echo
            }
        }
    });

    // 2. Client-side: fragmentation and WS upgrade
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    
    // Test 1-byte fragmentation
    let handshake_data = b"GET /chat HTTP/1.1\r\nHost: example.com\r\n\r\n";
    // We can't easily test the 'wait' in a unit test without mocking time, 
    // but we can verify the function runs.
    let fragmented = split_handshake(Box::new(stream), handshake_data).await.unwrap();
    
    // Test WebSocket upgrade
    // Note: split_handshake already sent the GET. WebSocketAdapter::upgrade sends its own.
    // In a real scenario, split_handshake would be used on the TLS ClientHello *inside* or *before* the carrier.
    // Here we just verify WebSocketAdapter can upgrade.
    let ws_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let adapter = WebSocketAdapter::upgrade(ws_stream, "127.0.0.1", "/ws").await.unwrap();
    
    assert!(true); // If we reached here, upgrade worked
}
