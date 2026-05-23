use crate::app::dns::DnsServer;
use crate::config::StreamSettings;
use crate::error::Result;
pub use crate::protocols::flow_trait;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use tracing::{debug, info, warn, error};
use bytes::BufMut;

// --- Modules ---
pub mod brutal_cc;
pub mod cdn_loop;
pub mod chaffing;
pub mod db_mimic;
pub mod desync;
pub mod dns_codec;
pub mod dns_tunnel;
pub mod ech;
pub mod flow_j_brutal;
pub mod flow_j_cdn;
pub mod flow_j_fec;
pub mod flow_j_mqtt;
pub mod flow_j_multiport;
pub mod flow_j_reality;
pub mod ghost_bucket;
pub mod behavior_synth;
pub mod http_relay;
#[cfg(feature = "tonic")]
pub mod grpc; // Added gRPC module
pub mod jitter;
pub mod mkcp;
pub mod mqtt;
pub mod mqtt_parasite;
pub mod manager;
pub mod mux;
pub mod mitm;
pub mod paqet;
pub mod pqc;
pub mod prefix_stream;
#[cfg(feature = "quic")]
pub mod quic;
pub mod reality;
pub mod reality_v2;
pub mod s3_bridge;
pub mod s3_codec;
pub mod service_masquerade;
pub mod slipstream;
pub mod speed_tester;
pub mod splice;
pub mod splithttp;
pub mod stats;
pub mod tls;
pub mod tls_camouflage;
pub mod tls_fragment;
pub mod tls_mimicry;
pub mod tls_profile;
pub mod tproxy;
pub mod udp_fallback;
pub mod utls;
pub mod websocket;
pub mod sockopt;
pub mod final_mask;
pub mod relay_fronting;
pub mod shadow_mieru;
pub mod weird_uri;
pub mod fallback;

/// A trait that combines AsyncRead, AsyncWrite, Unpin, and Send.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {
    fn as_any(&self) -> &dyn Any;
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncStream for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A type-erased, dynamic transport stream.
pub type BoxedStream = BoxedTrinityTransport;

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
) -> Result<BoxedTrinityTransport> {
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
            settings.tls_settings.as_ref().and_then(|t| t.pqc.as_ref()),
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

        let stream = paqet::PaqetStream::connect(paqet_settings, remote_addr).await?;
        return Ok(Box::new(stream) as BoxedStream);
    } else if settings.network == "flow-j-multiport" {
        let _multiport = settings.multiport.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Flow-J Multiport network selected but no multiport settings")
        })?;

        let addrs = dns_server.resolve_ip(host).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!(
                "No IP found for Flow-J Multiport connection"
            ));
        }
        let _remote_addr = SocketAddr::new(addrs[0], port);

        return Err(anyhow::anyhow!(
            "Flow-J Multiport connects via QUIC wrapper, not direct stream"
        ));
    } else

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

    if settings.network == "relay-fronting" {
        let rf_settings = settings.relay_fronting.as_ref().ok_or_else(|| {
            anyhow::anyhow!("RelayFronting network selected but no relayFronting settings")
        })?;

        let stream = relay_fronting::RelayFrontingStream::new(relay_fronting::RelayFrontingSettings {
            relay_url: rf_settings.relay_url.clone(),
            host: rf_settings.host.clone(),
            sni: rf_settings.sni.clone(),
            interval_ms: rf_settings.interval_ms,
        });
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
                
                let stream = if let Some(ref sockopt) = settings.sockopt {
                    connect_tcp_with_sockopt(remote_addr, sockopt).await?
                } else {
                    TcpStream::connect(remote_addr).await?
                };

                // Protect socket on Android to bypass VPN interface
                #[cfg(target_os = "android")]
                {
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
                    quic::connect(
                        remote_addr,
                        server_name,
                        &alpn,
                        settings.multiport.as_ref(),
                        settings.tls_settings.as_ref().and_then(|t| t.pqc.as_ref()),
                        settings.finalmask.as_ref().and_then(|fm| fm.quic_params.clone()),
                    )
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

    // SMR Wrapper (ShadowMieru)
    if let Some(smr) = &settings.shadow_mieru_settings {
        debug!("SMR: Wrapping client connection with ShadowMieruStream");
        let mut key = [0u8; 16];
        if let Ok(decoded) = hex::decode(&smr.entropy_key) {
            let len = decoded.len().min(16);
            key[..len].copy_from_slice(&decoded[..len]);
        }
        base_stream = Box::new(shadow_mieru::ShadowMieruStream::new(
            base_stream,
            key,
            smr.pacing_mbps * 1_000_000,
            &smr.decoy_profile,
            &smr.padding_profile,
        )) as BoxedStream;
    }

    // 1.5 PQC Wrapper (Phase 1)
    if let Some(pqc) = &settings.pqc
        && pqc.enabled
    {
        debug!("PQC: Wrapping base stream with hybrid handshake");
        let signing_kp = pqc::get_default_signing_kp();
        let server_pk_str = pqc.server_public_key.as_deref().unwrap_or_default();
        let server_pk = hex::decode(server_pk_str).unwrap_or_default();
        base_stream = pqc::wrap_pqc_client(base_stream, &server_pk, &signing_kp).await?;
    }

    // 2. Security (TLS)
    if settings.security == "tls" {
        let tls_settings = settings
            .tls_settings
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS security selected but no tlsSettings"))?;
        let server_name = tls_settings.server_name.as_deref().unwrap_or(host);

        let masquerader = crate::transport::service_masquerade::ServiceMasquerade::new();
        let strategy = masquerader.select(
            Some(server_name),
            settings.masquerade_weights.as_ref(),
            settings.decoy_headers.as_ref(),
        );

        base_stream =
            tls::wrap_tls_client_ext(base_stream, server_name, tls_settings, Some(strategy))
                .await?;

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

    if let Some(ref fm) = settings.finalmask {
        if let Some(ref tcp_settings) = fm.tcp {
            base_stream = final_mask::wrap_tcp_finalmask(base_stream, tcp_settings);
        }
    }

    // Overtls Client Handshake
    if let Some(overtls) = &settings.overtls_settings {
        debug!("Overtls: Performing client GET handshake validation");
        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            overtls.weird_uri, stream_host
        );
        base_stream.write_all(request.as_bytes()).await?;
        base_stream.flush().await?;
        
        let mut buffer = [0u8; 1024];
        let n = base_stream.read(&mut buffer).await?;
        let resp_str = String::from_utf8_lossy(&buffer[..n]);
        if resp_str.starts_with("HTTP/1.1 101") || resp_str.starts_with("HTTP/1.1 200") {
            let mut prefix = bytes::BytesMut::new();
            if let Some(pos) = resp_str.find("\r\n\r\n") {
                if pos + 4 < n {
                    prefix.put_slice(&buffer[(pos + 4)..n]);
                }
            }
            base_stream = Box::new(prefix_stream::PrefixedStream::new(base_stream, prefix)) as BoxedStream;
            debug!("Overtls: Client handshake successful");
        } else {
            return Err(anyhow::anyhow!("Overtls: Server rejected client handshake path"));
        }
    }

    Ok(base_stream)
}

pub async fn wrap_inbound_stream(
    mut stream: BoxedStream,
    settings: &StreamSettings,
) -> Result<BoxedStream> {
    // SMR Wrapper (ShadowMieru)
    if let Some(smr) = &settings.shadow_mieru_settings {
        debug!("SMR: Wrapping inbound connection with ShadowMieruStream");
        let mut key = [0u8; 16];
        if let Ok(decoded) = hex::decode(&smr.entropy_key) {
            let len = decoded.len().min(16);
            key[..len].copy_from_slice(&decoded[..len]);
        }
        stream = Box::new(shadow_mieru::ShadowMieruStream::new(
            stream,
            key,
            smr.pacing_mbps * 1_000_000,
            &smr.decoy_profile,
            &smr.padding_profile,
        )) as BoxedStream;
    }

    if let Some(pqc) = &settings.pqc
        && pqc.enabled
    {
        debug!("PQC: Wrapping inbound stream with hybrid handshake");
        let mut seed = [0u8; 32];
        if let Some(sk_str) = &pqc.secret_key {
            let decoded = hex::decode(sk_str).unwrap_or_default();
            let len = decoded.len().min(32);
            seed[..len].copy_from_slice(&decoded[..len]);
        }
        let server_kp = pqc::HybridKeypair::from_seed(&seed);
        stream = pqc::wrap_pqc_server(stream, &server_kp).await?;
    }
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

    if let Some(ref fm) = settings.finalmask {
        if let Some(ref tcp_settings) = fm.tcp {
            stream = final_mask::wrap_tcp_finalmask(stream, tcp_settings);
        }
    }

    // Overtls server side weird uri check
    if let Some(overtls) = &settings.overtls_settings {
        debug!("Overtls: Performing server GET handshake validation");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let mut buffer = bytes::BytesMut::with_capacity(1024);
        let mut temp = [0u8; 1024];
        
        let mut stream_ref = stream;
        let read_res = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let n = stream_ref.read(&mut temp).await?;
                if n == 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Connection closed"));
                }
                buffer.put_slice(&temp[..n]);
                let s = String::from_utf8_lossy(&buffer);
                if s.contains("\r\n\r\n") {
                    break;
                }
                if buffer.len() >= 1024 {
                    break;
                }
            }
            Ok::<(), std::io::Error>(())
        }).await;

        match read_res {
            Ok(Ok(())) => {
                let req_str = String::from_utf8_lossy(&buffer);
                let path_pattern = format!("GET /{} ", overtls.weird_uri);
                let path_pattern_query = format!("GET /{}?", overtls.weird_uri);
                
                if req_str.contains(&path_pattern) || req_str.contains(&path_pattern_query) {
                    // Authenticated! Respond with 101 Switching Protocols
                    let response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
                    stream_ref.write_all(response.as_bytes()).await?;
                    stream_ref.flush().await?;
                    
                    let mut prefix = bytes::BytesMut::new();
                    if let Some(pos) = req_str.find("\r\n\r\n") {
                        if pos + 4 < buffer.len() {
                            prefix.put_slice(&buffer[(pos + 4)..]);
                        }
                    }
                    stream = Box::new(prefix_stream::PrefixedStream::new(stream_ref, prefix)) as BoxedStream;
                    debug!("Overtls: Server validation successful");
                } else {
                    warn!("Overtls: Unauthenticated probe detected. Redirecting to decoy.");
                    let decoy_addr = overtls.decoy_proxy_addr.clone().unwrap_or_else(|| "127.0.0.1:80".to_string());
                    tokio::spawn(async move {
                        if let Err(e) = fallback::handle_decoy_fallback_with_initial_data(stream_ref, &decoy_addr, buffer).await {
                            error!("Overtls decoy fallback error: {}", e);
                        }
                    });
                    return Err(anyhow::anyhow!("Overtls: Probe redirected to decoy"));
                }
            }
            _ => {
                warn!("Overtls: Handshake timeout or error. Redirecting to decoy.");
                let decoy_addr = overtls.decoy_proxy_addr.clone().unwrap_or_else(|| "127.0.0.1:80".to_string());
                tokio::spawn(async move {
                    if let Err(e) = fallback::handle_decoy_fallback_with_initial_data(stream_ref, &decoy_addr, buffer).await {
                        error!("Overtls decoy fallback error: {}", e);
                    }
                });
                return Err(anyhow::anyhow!("Overtls: Probe redirected to decoy due to handshake timeout/error"));
            }
        }
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
pub mod beacon_scanner;

pub mod dtn;

pub mod webrtc;
pub mod jitter_transport;
pub mod faketcp;

use tokio::net::TcpSocket;
use socket2::Socket;

async fn connect_tcp_with_sockopt(
    addr: SocketAddr,
    settings: &crate::config::Sockopt,
) -> Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let sock_raw = unsafe { Socket::from_raw_fd(socket.as_raw_fd()) };
        sockopt::apply_sockopt(&sock_raw, settings)?;
        std::mem::forget(sock_raw);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let sock_raw = unsafe { Socket::from_raw_socket(socket.as_raw_socket()) };
        sockopt::apply_sockopt(&sock_raw, settings)?;
        std::mem::forget(sock_raw);
    }

    let stream = socket.connect(addr).await?;
    Ok(stream)
}

pub async fn listen_tcp_with_sockopt(
    addr: SocketAddr,
    settings: &crate::config::Sockopt,
) -> Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let sock_raw = unsafe { Socket::from_raw_fd(socket.as_raw_fd()) };
        sockopt::apply_sockopt(&sock_raw, settings)?;
        std::mem::forget(sock_raw);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let sock_raw = unsafe { Socket::from_raw_socket(socket.as_raw_socket()) };
        sockopt::apply_sockopt(&sock_raw, settings)?;
        std::mem::forget(sock_raw);
    }

    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    Ok(listener)
}
