// src/transport/mod.rs
use crate::app::dns::DnsServer;
use crate::config::StreamSettings;
use crate::error::Result;
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
// use tracing::debug;

// --- Modules ---
pub mod db_mimic;
pub mod ech;
pub mod flow_j_cdn;
pub mod flow_j_fec;
pub mod flow_j_mqtt;
pub mod flow_j_multiport;
pub mod flow_j_reality;
#[cfg(feature = "tonic")]
pub mod grpc; // Added gRPC module
pub mod mkcp;
pub mod mqtt;
pub mod mux;
pub mod paqet;
pub mod pqc;
pub mod prefix_stream;
#[cfg(feature = "quic")]
pub mod quic;
pub mod reality;
pub mod slipstream;
pub mod speed_tester;
pub mod splice;
pub mod splithttp;
pub mod stats;
pub mod tls;
pub mod tls_camouflage;
pub mod tls_fragment;
pub mod tproxy;
pub mod utls;
pub mod websocket;

/// A trait that combines AsyncRead, AsyncWrite, Unpin, and Send.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {
    fn as_any(&self) -> &dyn Any;
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A type-erased, dynamic stream that can be read from and written to.
pub type BoxedStream = Box<dyn AsyncStream>;

pub trait Packet: Send + Sync {
    fn src(&self) -> SocketAddr;
    fn dest(&self) -> SocketAddr;
    fn payload(&self) -> &[u8];
}

pub struct UdpPacket {
    pub src: SocketAddr,
    pub dest: SocketAddr,
    pub data: Vec<u8>,
}

impl Packet for UdpPacket {
    fn src(&self) -> SocketAddr {
        self.src
    }
    fn dest(&self) -> SocketAddr {
        self.dest
    }
    fn payload(&self) -> &[u8] {
        &self.data
    }
}

/// --- Master Outbound Connection Function ---
pub async fn connect(
    settings: &StreamSettings,
    dns_server: Arc<DnsServer>,
    host: &str,
    port: u16,
) -> Result<BoxedStream> {
    // Early exit for transports that handle their own dialing (SplitHTTP, MQTT)
    if settings.network == "splithttp" {
        let splithttp_settings = settings.splithttp_settings.as_ref().ok_or_else(|| {
            anyhow::anyhow!("SplitHTTP network selected but no splithttpSettings")
        })?;

        let protocol = if settings.security == "tls" {
            "https"
        } else {
            "http"
        };
        let path = if splithttp_settings.path.starts_with('/') {
            &splithttp_settings.path
        } else {
            "/"
        }; // Default path if empty? Or prepend /

        // Ensure path starts with /
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };

        let url = format!("{}://{}:{}{}", protocol, host, port, path);
        let stream = splithttp::SplitHttpStream::connect(&url).await?;
        return Ok(Box::new(stream) as BoxedStream);
    }

    if settings.network == "mqtt" {
        let mqtt_settings = settings
            .mqtt_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MQTT network selected but no mqttSettings"))?;

        let transport = mqtt::MqttTransport::new(
            &mqtt_settings.broker,
            "rustray-client",
            &mqtt_settings.upload_topic,
        )
        .await?;
        let stream = transport.create_stream().await?;
        return Ok(Box::new(stream) as BoxedStream);
    }

    #[cfg(feature = "tonic")]
    if settings.network == "grpc" {
        let grpc_settings = settings
            .grpc_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("gRPC network selected but no grpcSettings"))?;

        // Construct config
        let config = grpc::GrpcConfig {
            service_name: grpc_settings.service_name.clone(),
            host: host.to_string(), // Default host
            multi_mode: grpc_settings.multi_mode,
            idle_timeout: std::time::Duration::from_secs(grpc_settings.idle_timeout.unwrap_or(60)),
            health_check_timeout: std::time::Duration::from_secs(20),
            permit_without_stream: false,
            initial_windows_size: 65535,
        };

        // If "security" is TLS, we might need to handle TLS inside gRPC or wrap?
        // Tonic handles TLS if the URL scheme is https.
        // But our `settings.security` separates it.

        // Address construction
        let scheme = if settings.security == "tls" {
            "https"
        } else {
            "http"
        };
        let address = format!("{}://{}:{}", scheme, host, port);

        let stream = grpc::GrpcStream::connect(address, config).await?;
        return Ok(Box::new(stream) as BoxedStream);
    }

    if settings.network == "slipstream" {
        let slipstream_settings = settings.slipstream_settings.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Slipstream network selected but no slipstreamSettings")
        })?;

        let stream = slipstream::SlipstreamTunnel::connect(slipstream_settings).await?;
        return Ok(Box::new(stream) as BoxedStream);
    }

    /*
    if settings.network == "paqet" {
        let paqet_settings = settings
            .paqet_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Paqet network selected but no paqetSettings"))?;

        let addrs = dns_server.resolve_ip(host).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("No IP found for Paqet connection"));
        }
        let remote_addr = SocketAddr::new(addrs[0], port);

        // Note: paqet::connect needs to be implemented or we instantiate PaqetStream here
        // Assuming paqet::PaqetStream::connect exists or similar
        let stream = paqet::PaqetStream::connect(paqet_settings, remote_addr).await?;
        return Ok(Box::new(stream) as BoxedStream);
    }

    if settings.network == "flow-j-multiport" {
        let flow_j_settings = settings.flow_j_multiport_settings.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Flow-J Multiport network selected but no flowJMultiportSettings")
        })?;

        let addrs = dns_server.resolve_ip(host).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!(
                "No IP found for Flow-J Multiport connection"
            ));
        }
        let remote_addr = SocketAddr::new(addrs[0], port);

        return Err(anyhow::anyhow!(
            "Flow-J Multiport connects via QUIC wrapper, not direct stream"
        ));
    }
    */

    if settings.network == "db_mimic" {
        let db_settings = settings
            .db_mimic_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DB Mimic network selected but no dbMimicSettings"))?;

        // Resolve host
        let addrs = dns_server.resolve_ip(host).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("No IP found for DB server"));
        }
        let remote_addr = addrs[0];

        let stream =
            db_mimic::DbMimicStream::connect(&remote_addr.to_string(), port, db_settings).await?;
        return Ok(Box::new(stream) as BoxedStream);
    }

    let (mut base_stream, stream_host) = {
        // 1b. REALITY
        if settings.security == "reality" {
            let reality_settings = settings.reality_settings.as_ref().ok_or_else(|| {
                anyhow::anyhow!("REALITY security selected but no realitySettings")
            })?;

            let reality_host = &reality_settings.server_name;
            let addrs = dns_server.resolve_ip(reality_host).await?;
            if addrs.is_empty() {
                return Err(anyhow::anyhow!("No IP found for REALITY server"));
            }
            let remote_addr = SocketAddr::new(addrs[0], port);
            let stream = TcpStream::connect(remote_addr).await?;

            #[cfg(target_os = "android")]
            {
                use std::os::unix::io::AsRawFd;
                if !crate::android::protect_socket(&stream) {
                    debug!("Failed to protect REALITY socket");
                }
            }

            let base_stream = Box::new(stream) as BoxedStream;

            return reality::connect(base_stream, reality_settings).await;
        }

        // 1c. Standard
        match settings.network.as_str() {
            "" | "tcp" | "ws" | "http" => {
                // Empty string defaults to TCP
                let addrs = dns_server.resolve_ip(host).await?;
                if addrs.is_empty() {
                    return Err(anyhow::anyhow!("No IP found for {}", host));
                }
                let remote_addr = SocketAddr::new(addrs[0], port);
                let stream = TcpStream::connect(remote_addr).await?;

                // Protect socket on Android to bypass VPN interface
                #[cfg(target_os = "android")]
                {
                    use std::os::unix::io::AsRawFd;
                    if !crate::android::protect_socket(&stream) {
                        return Err(anyhow::anyhow!("Failed to protect socket - VPN loop risk"));
                    }
                }

                (Box::new(stream) as BoxedStream, host.to_string())
            }
            "kcp" => {
                let addrs = dns_server.resolve_ip(host).await?;
                if addrs.is_empty() {
                    return Err(anyhow::anyhow!("No IP found"));
                }
                let remote_addr = SocketAddr::new(addrs[0], port);
                let kcp_config = Arc::new(settings.kcp_settings.clone().unwrap_or_default());
                let stream = mkcp::connect(kcp_config, remote_addr).await?;
                (Box::new(stream) as BoxedStream, host.to_string())
            }
            #[cfg(feature = "quic")]
            "quic" => {
                let addrs = dns_server.resolve_ip(host).await?;
                if addrs.is_empty() {
                    return Err(anyhow::anyhow!("No IP found for QUIC connection"));
                }
                let remote_addr = SocketAddr::new(addrs[0], port);

                // Determine server name for TLS (SNI)
                let server_name = settings
                    .tls_settings
                    .as_ref()
                    .and_then(|t| t.server_name.as_deref())
                    .unwrap_or(host);

                // Determine ALPN protocols based on usage
                // h3 for HTTP/3, or custom protocol
                let alpn: Vec<&[u8]> = vec![b"h3"];

                // Connect via QUIC
                let mut quic_conn =
                    quic::connect(remote_addr, server_name, &alpn, settings.multiport.as_ref())
                        .await?;

                // Wait for QUIC connection establishment
                quic_conn.wait_for_established().await?;

                // Open a bidirectional stream
                let stream = quic_conn.open_stream().await?;

                tracing::debug!("QUIC connection established to {}:{}", host, port);
                return Ok(stream);
            }
            #[cfg(not(feature = "quic"))]
            "quic" => {
                return Err(anyhow::anyhow!("QUIC support is not enabled in this build"));
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported outbound network: {}",
                    settings.network
                ));
            }
        }
    };

    // 2. Security (TLS)
    if settings.security == "tls" {
        let tls_settings = settings
            .tls_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS security selected but no tlsSettings"))?;
        let server_name = tls_settings.server_name.as_deref().unwrap_or(host);

        // Uses tls::wrap_tls_client which internally handles uTLS if configured
        base_stream = tls::wrap_tls_client(base_stream, server_name, tls_settings).await?;

        if let Some(frag_settings) = &settings.fragment_settings {
            base_stream =
                tls_fragment::wrap_tls_fragment_client(base_stream, frag_settings).await?;
        }
    }

    // 3. Transport Wrappers
    if let Some(ws_settings) = &settings.ws_settings {
        let stream_host_for_ws = ws_settings.host.as_deref().unwrap_or(&stream_host);
        base_stream =
            websocket::wrap_ws_client(base_stream, stream_host_for_ws, ws_settings).await?;
    }

    Ok(base_stream)
}

pub async fn wrap_inbound_stream(
    mut stream: BoxedStream,
    settings: &StreamSettings,
) -> Result<BoxedStream> {
    if settings.security == "tls" {
        let tls_settings = settings.tls_settings.as_ref().ok_or_else(|| {
            anyhow::anyhow!("TLS security selected but no tlsSettings for inbound")
        })?;
        stream = tls::wrap_tls_server(stream, tls_settings).await?;
    }

    // Wrapper handling for Inbound (Server side)
    if let Some(ws_settings) = &settings.ws_settings {
        stream = websocket::wrap_ws_server(stream, ws_settings).await?;
    }

    Ok(stream)
}

pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match tokio::io::copy_bidirectional(a, b).await {
        Ok((a, b)) => Ok((a, b)),
        Err(e) => Err(anyhow::anyhow!("Copy bidirectional error: {}", e)),
    }
}
