// tests/udp_fallback_test.rs
//! Integration tests for UDP-over-TCP fallback multiplexer.

use rustray::transport::udp_fallback::UdpOverTcpStream;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_udp_over_tcp_datagram_roundtrip() {
    // Spawn a TCP echo server that reads length-prefixed frames
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        
        // Read length prefix
        let len = stream.read_u16().await.unwrap() as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        
        // Echo it back with length prefix
        stream.write_u16(len as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Connect client
    let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut uot = UdpOverTcpStream::new(tcp_stream);

    // Send a datagram
    let test_data = b"Hello UDP-over-TCP!";
    uot.send_datagram(test_data).await.unwrap();

    // Receive the echoed datagram
    let received = uot.recv_datagram().await.unwrap();
    assert_eq!(received, test_data);

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_udp_over_tcp_multiple_datagrams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        
        // Read and echo 3 datagrams
        for _ in 0..3 {
            let len = stream.read_u16().await.unwrap() as usize;
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            
            stream.write_u16(len as u16).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        }
        stream.flush().await.unwrap();
    });

    let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut uot = UdpOverTcpStream::new(tcp_stream);

    let messages = vec![
        b"First datagram".to_vec(),
        b"Second datagram with more data".to_vec(),
        b"Third".to_vec(),
    ];

    // Send all
    for msg in &messages {
        uot.send_datagram(msg).await.unwrap();
    }

    // Receive all
    for expected in &messages {
        let received = uot.recv_datagram().await.unwrap();
        assert_eq!(received, *expected);
    }

    server_task.await.unwrap();
}
