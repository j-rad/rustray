// src/inbounds/dokodemo.rs
use crate::app::dns::DnsServer;
use crate::app::stats::StatsManager;
use crate::config::DokodemoSettings;
use crate::error::Result;
use crate::router::Router;
use crate::transport::{BoxedStream, UdpPacket, tproxy};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};

pub async fn listen_stream(
    router: Arc<Router>,
    _dns_server: Arc<DnsServer>,
    state: Arc<StatsManager>,
    stream: BoxedStream,
    settings: DokodemoSettings,
    source: String,
) -> Result<()> {
    // TCP handling (existing logic stub)
    // Read dest from settings or environment
    // For Dokodemo, usually address/port in settings is the destination if not following redirect.
    // Or if follow_redirect (TProxy TCP), we get it from getsockopt.
    // Since this task focused on UDP, I'll leave TCP stub as is or improve if needed.

    // For TCP:
    let dest_host = settings.address.clone();
    let dest_port = settings.port;
    let policy = state.policy_manager.get_policy(0); // Default level

    // Route
    router
        .route_stream(stream, dest_host, dest_port, source, policy)
        .await
}

pub async fn listen_packet(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    settings: DokodemoSettings,
    listen_port: u16,
    tproxy_enabled: bool,
) -> Result<()> {
    let listen_addr = format!("127.0.0.1:{}", listen_port); // Use the inbound's listen port
    // Note: Caller `InboundManager` creates the listener usually?
    // `InboundManager` handles TCP listener. For UDP, it might delegate or we create here.
    // In `InboundManager`, it spawns tasks.
    // If we want to support TProxy, we need to create the socket with specific options *before* bind.

    let socket = if tproxy_enabled {
        #[cfg(target_os = "linux")]
        {
            tproxy::create_tproxy_socket(&listen_addr.parse()?, false)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!("TProxy enabled but not on Linux, falling back to normal UDP");
            UdpSocket::bind(&listen_addr).await?
        }
    } else {
        UdpSocket::bind(&listen_addr).await?
    };

    let socket = std::sync::Arc::new(socket);

    info!("Dokodemo UDP listening on {}", listen_addr);

    let mut buf = [0u8; 65535];
    let _policy = state.policy_manager.get_policy(0);

    loop {
        // We need to read packet.
        // If TProxy, we use recv_from_with_orig_dst.
        // Else recv_from.

        let (len, src, dest) = if tproxy_enabled {
            #[cfg(target_os = "linux")]
            {
                socket.readable().await?;
                match tproxy::recv_from_with_orig_dst(&socket, &mut buf) {
                    Ok((l, s, d)) => (l, s, d),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        warn!("UDP recv error: {}", e);
                        continue;
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let (l, s) = socket.recv_from(&mut buf).await?;
                (l, s, None)
            }
        } else {
            let (l, s) = socket.recv_from(&mut buf).await?;
            (l, s, None)
        };

        // Determine Packet Destination
        let target_addr = if let Some(d) = dest {
            d
        } else {
            // Use settings address
            // Resolve settings.address?
            // Dokodemo usually targets a fixed address if not transparent.
            // We assume IP address in settings for simplicity or verify later.
            if let Ok(ip) = settings.address.parse::<std::net::IpAddr>() {
                std::net::SocketAddr::new(ip, settings.port)
            } else {
                // If domain, we can't create SocketAddr easily without resolve.
                // Packet routing usually expects IP.
                // If domain, we might need to resolve?
                // For UDP, Router expects Packet with dest SocketAddr.
                // Stub: use 0.0.0.0 if fail?
                warn!(
                    "Dokodemo UDP target address is not IP: {}",
                    settings.address
                );
                continue;
            }
        };

        let packet = UdpPacket {
            src,
            dest: target_addr,
            data: buf[..len].to_vec(),
        };

        // Create reply channel for UDP responses
        let (reply_tx, mut reply_rx) =
            tokio::sync::mpsc::channel::<Box<dyn crate::transport::Packet>>(100);

        // Spawn task to handle replies
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            while let Some(response_packet) = reply_rx.recv().await {
                let response_src = response_packet.src();
                let response_dest = response_packet.dest();
                let response_data = response_packet.payload();

                info!(
                    "Dokodemo UDP: Sending response from {} back to {}",
                    response_src, response_dest
                );
                if let Err(e) = socket_clone.send_to(response_data, response_dest).await {
                    warn!("Dokodemo UDP: Failed to send response: {}", e);
                    break;
                }
            }
        });

        // Route Packet to outbound with reply channel
        info!(
            "Dokodemo UDP: Routing packet from {} to {}",
            src, target_addr
        );

        // Get the default outbound handler (usually "direct" or first outbound)
        // For dokodemo, we typically route to the default outbound
        if let Some(handler) = router.get_outbound("direct") {
            if let Err(e) = handler
                .handle_packet(Box::new(packet), Some(reply_tx))
                .await
            {
                warn!("Dokodemo UDP: Failed to route packet: {}", e);
            }
        } else {
            warn!("Dokodemo UDP: No 'direct' outbound handler found");
        }
    }
}
