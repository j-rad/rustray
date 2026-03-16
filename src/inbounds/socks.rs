// src/inbounds/socks.rs
use crate::app::dns::DnsServer;
use crate::app::stats::StatsManager;
use crate::config::SocksSettings;
use crate::error::Result;
use crate::router::Router;
use crate::transport::BoxedStream;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Handles a single SOCKS5 stream.
pub async fn listen_stream(
    router: Arc<Router>,
    dns_server: Arc<DnsServer>,
    state: Arc<StatsManager>,
    stream: BoxedStream,
    settings: SocksSettings,
    source: String,
) -> Result<()> {
    handle_connection(router, dns_server, state, stream, &settings, source).await
}

async fn handle_connection(
    router: Arc<Router>,
    dns_server: Arc<DnsServer>,
    state: Arc<StatsManager>,
    mut stream: BoxedStream,
    _settings: &SocksSettings,
    source: String,
) -> Result<()> {
    // ... (Handshake logic) ...
    let ver = stream.read_u8().await?;
    if ver != 5 {
        return Err(anyhow::anyhow!("Invalid SOCKS version"));
    }
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0x00]).await?;

    let _ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    let host = match atyp {
        0x01 => {
            let ip_bytes = stream.read_u32().await?;
            let ip = IpAddr::V4(Ipv4Addr::from(ip_bytes));
            if let Some(domain) = dns_server.get_domain_from_fake_ip(ip) {
                domain
            } else {
                ip.to_string()
            }
        }
        0x03 => {
            let len = stream.read_u8().await?;
            let mut domain_bytes = vec![0u8; len as usize];
            stream.read_exact(&mut domain_bytes).await?;
            String::from_utf8(domain_bytes)?
        }
        _ => return Err(anyhow::anyhow!("Unknown ATYP")),
    };

    let port = stream.read_u16().await?;

    match cmd {
        0x01 => {
            // CONNECT
            stream
                .write_all(&[5, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            let default_policy = state.policy_manager.get_policy(0);
            router
                .route_stream(stream, host, port, source, default_policy)
                .await?;
            Ok(())
        }
        0x03 => {
            // UDP ASSOCIATE
            use tracing::info;
            info!("SOCKS5: Starting UDP ASSOCIATE relay");
            // Send success response with bind address
            stream
                .write_all(&[5, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            handle_socks5_udp_relay(stream, router, dns_server).await?;
            Ok(())
        }
        _ => {
            stream
                .write_all(&[5, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(anyhow::anyhow!("Unsupported SOCKS5 command"))
        }
    }
}

/// Handle SOCKS5 UDP ASSOCIATE relay
/// UDP packets are framed as: [RSV(2)] [FRAG] [ATYP] [DST.ADDR] [DST.PORT] [DATA]
async fn handle_socks5_udp_relay(
    mut _stream: BoxedStream,
    _router: Arc<Router>,
    _dns_server: Arc<DnsServer>,
) -> Result<()> {
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    // Bind UDP socket for SOCKS5 relay
    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let local_addr = udp_socket.local_addr()?;
    debug!("SOCKS5 UDP: Bound to {}", local_addr);

    // Create channels
    let (_to_udp_tx, mut to_udp_rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(32);
    let (from_udp_tx, _from_udp_rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(32);

    // Task: Send to UDP
    let udp_send = udp_socket.clone();
    tokio::spawn(async move {
        while let Some((payload, addr)) = to_udp_rx.recv().await {
            if let Err(e) = udp_send.send_to(&payload, addr).await {
                warn!("SOCKS5 UDP: Send error: {}", e);
                break;
            }
        }
    });

    // Task: Receive from UDP
    let udp_recv = udp_socket.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match udp_recv.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    if from_udp_tx
                        .send((buf[..len].to_vec(), src_addr))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    warn!("SOCKS5 UDP: Receive error: {}", e);
                    break;
                }
            }
        }
    });

    // Main relay loop
    // Note: SOCKS5 UDP relay typically uses UDP datagrams directly, not the TCP control connection
    // The TCP connection is kept alive to signal session termination
    // For simplicity, we'll just keep the socket alive and relay UDP packets

    // In production, you would:
    // 1. Parse SOCKS5 UDP request format from UDP datagrams
    // 2. Extract target address and data
    // 3. Forward to destination
    // 4. Wrap responses in SOCKS5 UDP reply format

    // For now, just keep the session alive
    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;

    Ok(())
}
