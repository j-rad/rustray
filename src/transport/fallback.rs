// src/transport/fallback.rs
use crate::protocols::flow_trait::BoxedTrinityTransport;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use std::io;
use tracing::{info, error};

/// Transparently proxies unauthenticated active probes to the decoy loopback web server.
/// Serves a legitimate corporate speed test or bank portal decoy page.
pub async fn handle_decoy_fallback(
    mut client_stream: BoxedTrinityTransport,
    decoy_proxy_addr: &str,
) -> io::Result<()> {
    handle_decoy_fallback_with_initial_data(client_stream, decoy_proxy_addr, bytes::BytesMut::new()).await
}

/// Transparently proxies unauthenticated active probes to the decoy loopback web server,
/// forwarding initial data read from the socket (like HTTP headers) first.
pub async fn handle_decoy_fallback_with_initial_data(
    mut client_stream: BoxedTrinityTransport,
    decoy_proxy_addr: &str,
    initial_data: bytes::BytesMut,
) -> io::Result<()> {
    info!("DecoyFallback: Establishing connection to decoy at {}", decoy_proxy_addr);
    
    let mut decoy_stream = match TcpStream::connect(decoy_proxy_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("DecoyFallback: Failed to connect to local decoy web server: {}", e);
            // Write a generic 500 error to censor so they don't see immediately closed connection
            let _ = client_stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n").await;
            return Err(e);
        }
    };

    if !initial_data.is_empty() {
        if let Err(e) = decoy_stream.write_all(&initial_data).await {
            error!("DecoyFallback: Failed to write initial data to decoy: {}", e);
            return Err(e);
        }
        let _ = decoy_stream.flush().await;
    }

    info!("DecoyFallback: Handoff initiated between probe client and decoy web server");
    
    // Bidirectional copy between probe client and local decoy web server
    match tokio::io::copy_bidirectional(&mut client_stream, &mut decoy_stream).await {
        Ok((sent, rcvd)) => {
            info!(
                "DecoyFallback: Handoff completed. Bytes sent: {}, Bytes received: {}",
                sent, rcvd
            );
            Ok(())
        }
        Err(e) => {
            error!("DecoyFallback: Bidirectional copy error: {}", e);
            Err(e)
        }
    }
}

