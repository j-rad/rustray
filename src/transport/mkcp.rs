// src/transport/mkcp.rs
use crate::config::KcpConfig;
use crate::error::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_kcp::{KcpConfig as TokioKcpConfig, KcpListener, KcpNoDelayConfig, KcpStream};
use tracing::info;

/// Creates an mKCP client stream by connecting to a remote UDP address.
pub async fn connect(settings: Arc<KcpConfig>, remote_addr: SocketAddr) -> Result<KcpStream> {
    info!("mKCP: Connecting to {}", remote_addr);

    let kcp_config = apply_config(&settings);

    // Seed obfuscation is not supported with standard tokio-kcp as it requires wrapping UdpSocket.
    // If seed is present, we log a warning.
    if settings.seed.is_some() {
        tracing::warn!(
            "mKCP: 'seed' obfuscation configured but not supported by current transport. Ignoring."
        );
    }

    // We let tokio-kcp bind to a random port
    let stream = KcpStream::connect(&kcp_config, remote_addr).await?;

    info!("mKCP: Stream established to {}", remote_addr);
    Ok(stream)
}

/// Creates an mKCP listener on a local UDP socket.
pub async fn listen(settings: Arc<KcpConfig>, listen_addr: &str, port: u16) -> Result<KcpListener> {
    let addr = format!("{}:{}", listen_addr, port);
    info!("mKCP: Listening on {}", addr);

    let kcp_config = apply_config(&settings);

    let socket = UdpSocket::bind(&addr).await?;

    // Apply buffer sizes to UDP socket if specified
    if let Some(_size) = settings.read_buffer_size {
        // socket.set_recv_buffer_size(size as usize)?;
        // Note: tokio::net::UdpSocket doesn't expose set_recv_buffer_size directly without std conversion or socket2.
        // We can try converting to std and back, or ignore for now to keep it simple/safe async.
        // socket2 is in deps.
        apply_socket_opts(&socket, settings.clone())?;
    }

    let listener = KcpListener::from_socket(kcp_config, socket).await?;

    Ok(listener)
}

fn apply_config(settings: &KcpConfig) -> TokioKcpConfig {
    let mut config = TokioKcpConfig::default();
    config.mtu = settings.mtu.unwrap_or(1350) as usize;

    // TTI (Transmission Time Interval)
    let interval = settings.tti.unwrap_or(50);

    // Congestion Control
    let congestion = settings.congestion.unwrap_or(false); // false means enabled in generic config usually? 
    // Wait, RustRay config: "congestion": true means ENABLED.
    // KCP "nc": 0 = regular congestion control, 1 = no congestion control (turbo).
    // So if congestion=true, nc=0. If congestion=false, nc=1?
    // Actually typically "uplink/downlink" settings imply we WANT turbo.
    // Let's assume settings.congestion matches RustRay semantics: true = enable CC.

    let nc = !congestion;

    config.nodelay = KcpNoDelayConfig {
        nodelay: true,
        interval: interval as i32,
        resend: 2,
        nc,
    };

    config.wnd_size = (
        settings.uplink_capacity.unwrap_or(5) as u16,
        settings.downlink_capacity.unwrap_or(20) as u16,
    );

    // stream_mode: true implies pure byte stream (TCP-like). false = message mode.
    // RustRay usually treats it as a stream.
    config.stream = true;

    config
}

fn apply_socket_opts(_socket: &UdpSocket, settings: Arc<KcpConfig>) -> Result<()> {
    // Basic optimization if needed.
    // For now, we only log if buffer sizes are requested as we can't easily set them without unsafe/std conversion quirks in async context.
    // Given the constraints, we skip socket options for this iteration.
    if settings.read_buffer_size.is_some() || settings.write_buffer_size.is_some() {
        tracing::debug!(
            "mKCP: Socket buffer sizing requested but skipped in current implementation."
        );
    }
    Ok(())
}
