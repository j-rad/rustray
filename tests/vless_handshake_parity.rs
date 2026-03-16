use rustray::config::{
    self, ApiConfig, Config, FreedomSettings, Inbound, InboundSettings, Outbound, OutboundSettings,
    VlessSettings, VlessUser,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

#[tokio::test]
async fn test_vless_handshake_parity() {
    // 1. Start RustRay VLESS Server
    let server_port = 10010;
    let uuid_str = "509c3132-7232-4235-9626-267926132174";
    let uuid = Uuid::parse_str(uuid_str).unwrap();

    let mut server_config = Config::default();
    server_config.inbounds = Some(vec![Inbound {
        tag: "vless-in".to_string(),
        port: server_port,
        listen: Some("127.0.0.1".to_string()),
        protocol: "vless".to_string(),
        settings: Some(InboundSettings::Vless(VlessSettings {
            clients: vec![VlessUser {
                id: uuid_str.to_string(),
                level: Some(0),
                email: None,
                flow: None,
            }],
            decryption: Some("none".to_string()),
            fallbacks: None,
        })),
        stream_settings: None,
        sniffing: None,
        allocation: None,
    }]);

    // Direct outbound
    server_config.outbounds = Some(vec![Outbound {
        tag: "direct".to_string(),
        protocol: "freedom".to_string(),
        settings: Some(OutboundSettings::Freedom(FreedomSettings::default())),
        stream_settings: None,
        mux: None,
        proxy_settings: None,
    }]);

    // API with unique port
    server_config.api = Some(ApiConfig {
        tag: "api".to_string(),
        services: vec![],
        port: Some(8099),
        listen: Some("127.0.0.1".to_string()),
    });

    // Spawn server
    let (_tx, rx) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        rustray::run_server(server_config, rx).await.unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2. Perform raw handshake test
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", server_port))
        .await
        .unwrap();

    let mut request = Vec::new();

    // Version
    request.push(0u8);
    // UUID
    request.extend_from_slice(uuid.as_bytes());
    // Addons length
    request.push(0u8);
    // Command (TCP)
    request.push(1u8);
    // Port (80 in big endian - target port)
    request.extend_from_slice(&80u16.to_be_bytes());
    // Address type (IPv4)
    request.push(1u8);
    // Address (8.8.8.8 - just a test target, freedom outbound will try to connect)
    // IMPORTANT: If we connect to a real IP, freedom outbound will try to connect.
    // We should probably setup a local echo server as the target to be robust.
    // Or just check if we get a response header.
    request.extend_from_slice(&[127, 0, 0, 1]);

    // We need a target to connect to if we want the VLESS server to respond with success.
    // Start a dummy echo target on 8088
    let target_port: u16 = 8088;
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", target_port))
            .await
            .unwrap();
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            socket.write_all(&buf[..n]).await.unwrap_or(());
        }
    });

    // Adjust request to point to local target
    // Pop last 6 bytes (addr type 1 + 4 ip) + 2 port
    request.truncate(1 + 16 + 1 + 1);
    // New Port
    request.extend_from_slice(&target_port.to_be_bytes());
    // New Address (127.0.0.1)
    request.push(1u8);
    request.extend_from_slice(&[127, 0, 0, 1]);

    println!("Sending VLESS request: {} bytes", request.len());
    stream.write_all(&request).await.unwrap();
    stream.flush().await.unwrap();

    // Read response header (2 bytes: version + addons len)
    let mut response = [0u8; 2];
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        stream.read_exact(&mut response),
    )
    .await
    {
        Ok(Ok(_)) => {
            println!("Received response: {:?}", response);
            if response[0] == 0 && response[1] == 0 {
                println!("✓ VLESS handshake successful!");

                // Try to send data
                stream.write_all(b"HELLO").await.unwrap();
                let mut buf = [0u8; 5];
                // Expect echo
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    stream.read_exact(&mut buf),
                )
                .await
                {
                    Ok(Ok(_)) => assert_eq!(&buf, b"HELLO"),
                    _ => panic!("Echo failed"),
                }
            } else {
                panic!("✗ Invalid response header: {:?}", response);
            }
        }
        Ok(Err(e)) => panic!("✗ Read error: {}", e),
        Err(_) => panic!("✗ Response timeout - server not responding"),
    }
}
