// src/protocols/trojan.rs
//!
//! Trojan Protocol Implementation
//!
//! Trojan is a mechanism to bypass GFW by imitating HTTPS.
//! It uses TLS for encryption and a password hash for authentication.
//!
//! Protocol Format:
//! ```text
//! +-----------------------+---------+----------------+---------+----------+
//! | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
//! +-----------------------+---------+----------------+---------+----------+
//! |       56 bytes        | 2 bytes |    Variable    | 2 bytes | Variable |
//! +-----------------------+---------+----------------+---------+----------+
//!
//! Trojan Request:
//! +-----+------+------+----------+----------+
//! | Cmd | Addr | Port |  ...     |   ...    |
//! +-----+------+------+----------+----------+
//! ```

use crate::app::dns::DnsServer;
use crate::config::{LevelPolicy, StreamSettings, TlsSettings};
use crate::error::Result;
use crate::outbounds::Outbound;
use crate::router::Router;
use crate::transport::{self, BoxedStream};
use async_trait::async_trait;
use sha2::{Digest, Sha224};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

// --- Constants ---

#[allow(dead_code)]
const TROJAN_HASH_LEN: usize = 56;
const CRLF: &[u8] = b"\r\n";

// --- Commands ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 1,
    UdpAssociate = 3,
}

impl Command {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Command::Connect),
            3 => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

// --- Protocol Handling ---

pub struct TrojanInbound;

impl TrojanInbound {
    pub async fn handle_stream(
        mut stream: BoxedStream,
        password: &str,
        router: Arc<Router>,
        fallback_addr: Option<SocketAddr>,
        source: String,
    ) -> Result<()> {
        debug!("Trojan: Handling new inbound stream from {}", source);

        // 1. Read Password Hash (56 bytes) + CRLF (2 bytes) = 58 bytes
        let mut auth_buf = [0u8; 58];

        match stream.read_exact(&mut auth_buf).await {
            Ok(_) => {
                // Verify CRLF
                if &auth_buf[56..58] != CRLF {
                    return Self::fallback(stream, Some(auth_buf.to_vec()), fallback_addr).await;
                }

                // Verify Hash
                let expected_hash = hex::encode(Sha224::digest(password.as_bytes()));
                let received_hash = String::from_utf8_lossy(&auth_buf[0..56]);

                if !received_hash.eq_ignore_ascii_case(&expected_hash) {
                    warn!("Trojan: Invalid password hash: {}", received_hash);
                    return Self::fallback(stream, Some(auth_buf.to_vec()), fallback_addr).await;
                }

                info!("Trojan: Authenticated");
            }
            Err(_) => {
                // Read failed (EOF or error), try fallback with whatever we got?
                return Self::fallback(stream, None, fallback_addr).await;
            }
        }

        // 2. Read Request
        // Cmd(1) + AddrType(1) + Addr + Port(2) + CRLF(2)
        let cmd_byte = stream.read_u8().await?;
        let cmd = Command::from_u8(cmd_byte).ok_or_else(|| anyhow::anyhow!("Invalid Command"))?;

        let addr_type = stream.read_u8().await?;
        let addr = match addr_type {
            1 => {
                // IPv4
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                Address::Ipv4(Ipv4Addr::from(buf))
            }
            3 => {
                // Domain
                let len = stream.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                let domain =
                    String::from_utf8(buf).map_err(|_| anyhow::anyhow!("Invalid domain"))?;
                Address::Domain(domain)
            }
            4 => {
                // IPv6
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
                Address::Ipv6(Ipv6Addr::from(buf))
            }
            _ => return Err(anyhow::anyhow!("Invalid Address Type")),
        };

        let port = stream.read_u16().await?;

        // Read trailing CRLF
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if &crlf != CRLF {
            return Err(anyhow::anyhow!("Invalid Request CRLF"));
        }

        // 3. Route
        let host = match &addr {
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => ip.to_string(),
            Address::Domain(d) => d.clone(),
        };

        debug!("Trojan Request: {:?} {}:{}", cmd, host, port);

        if cmd == Command::UdpAssociate {
            info!("Trojan: Starting UDP ASSOCIATE relay");
            return handle_udp_relay(stream, router, host, port).await;
        }

        let policy = Arc::new(LevelPolicy::default());
        router
            .route_stream(stream, host, port, source, policy)
            .await
    }

    async fn fallback(
        mut stream: BoxedStream,
        prefix: Option<Vec<u8>>,
        fallback_addr: Option<SocketAddr>,
    ) -> Result<()> {
        if let Some(addr) = fallback_addr {
            debug!("Trojan: Fallback to {}", addr);
            let mut remote = tokio::net::TcpStream::connect(addr).await?;

            if let Some(p) = prefix {
                remote.write_all(&p).await?;
            }

            let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
        } else {
            debug!("Trojan: Authentication failed and no fallback configured");
        }
        Ok(())
    }
}

pub struct TrojanOutbound {
    pub address: String,
    pub port: u16,
    pub password: String,
    // Note: StreamSettings should be passed in or associated, but typically Outbound manager configures transport separately.
    // For this implementation, we assume we need to establish the connection ourselves if "handle" doesn't provide the peer connection.
    // But "handle" receives the *client* connection.
    // So we need to dial the Trojan Server.

    // We need dns_server to resolve Trojan Server IP.
    dns_server: Arc<DnsServer>,
    // We need stream settings to know it's TLS.
    // Assuming hardcoded TLS for Trojan protocol definition.
    server_name: Option<String>,
}

impl TrojanOutbound {
    pub fn new(
        address: String,
        port: u16,
        password: String,
        dns_server: Arc<DnsServer>,
        server_name: Option<String>,
    ) -> Self {
        Self {
            address,
            port,
            password,
            dns_server,
            server_name,
        }
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    async fn handle(
        &self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        _policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut out_stream = self.dial(host, port).await?;
        let _ = tokio::io::copy_bidirectional(&mut in_stream, &mut out_stream).await?;
        Ok(())
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        // 1. Establish connection to Trojan Server (TCP + TLS)
        let mut stream_settings = StreamSettings::default();
        stream_settings.security = "tls".to_string();
        stream_settings.tls_settings = Some(TlsSettings {
            server_name: self.server_name.clone().or(Some(self.address.clone())),
            allow_insecure: Some(false),
            ..Default::default()
        });

        let mut server_stream = transport::connect(
            &stream_settings,
            self.dns_server.clone(),
            &self.address,
            self.port,
        )
        .await?;

        // 2. Write Trojan Request
        write_trojan_request(
            &mut server_stream,
            &self.password,
            Command::Connect,
            &host,
            port,
        )
        .await?;

        Ok(server_stream)
    }
}

// Helper to write Trojan request to a stream
pub async fn write_trojan_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    password: &str,
    cmd: Command,
    host: &str,
    port: u16,
) -> Result<()> {
    // Hash
    let hash = hex::encode(Sha224::digest(password.as_bytes()));
    writer.write_all(hash.as_bytes()).await?;
    writer.write_all(CRLF).await?;

    // Cmd
    writer.write_u8(cmd as u8).await?;

    // Addr
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        writer.write_u8(1).await?;
        writer.write_all(&ip.octets()).await?;
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        writer.write_u8(4).await?;
        writer.write_all(&ip.octets()).await?;
    } else {
        writer.write_u8(3).await?;
        writer.write_u8(host.len() as u8).await?;
        writer.write_all(host.as_bytes()).await?;
    }

    // Port
    writer.write_u16(port).await?;

    // CRLF
    writer.write_all(CRLF).await?;

    Ok(())
}

/// Handle UDP relay for Trojan protocol  
/// UDP packets are framed as: [Address Type] [Address] [Port] [Length] [Payload]
async fn handle_udp_relay(
    mut stream: BoxedStream,
    _router: Arc<Router>,
    _host: String,
    _port: u16,
) -> Result<()> {
    use bytes::{BufMut, BytesMut};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    // Bind UDP socket for relaying
    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let local_addr = udp_socket.local_addr()?;
    debug!("Trojan UDP: Bound to {}", local_addr);

    // Send UDP bind success response to client
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;

    // Create channels for bidirectional communication
    let (to_udp_tx, mut to_udp_rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(32);
    let (from_udp_tx, mut from_udp_rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(32);

    // Task 1: Send packets to UDP
    let udp_send = udp_socket.clone();
    tokio::spawn(async move {
        while let Some((payload, addr)) = to_udp_rx.recv().await {
            if let Err(e) = udp_send.send_to(&payload, addr).await {
                warn!("Trojan UDP: Send error: {}", e);
                break;
            }
        }
    });

    // Task 2: Receive packets from UDP
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
                    warn!("Trojan UDP: Receive error: {}", e);
                    break;
                }
            }
        }
    });

    // Main loop: relay between TCP stream and UDP socket
    loop {
        tokio::select! {
            // Read from TCP stream (client -> UDP)
            result = async {
                // Read address type
                let atyp = stream.read_u8().await?;

                let addr_str = match atyp {
                    1 => {
                        // IPv4
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf).await?;
                        std::net::Ipv4Addr::from(buf).to_string()
                    }
                    3 => {
                        // Domain
                        let len = stream.read_u8().await? as usize;
                        let mut buf = vec![0u8; len];
                        stream.read_exact(&mut buf).await?;
                        String::from_utf8(buf).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid domain"))?
                    }
                    4 => {
                        // IPv6
                        let mut buf = [0u8; 16];
                        stream.read_exact(&mut buf).await?;
                        std::net::Ipv6Addr::from(buf).to_string()
                    }
                    _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid address type")),
                };

                let port = stream.read_u16().await?;
                let len = stream.read_u16().await?;
                let mut payload = vec![0u8; len as usize];
                stream.read_exact(&mut payload).await?;
                stream.read_exact(&mut [0u8; 2]).await?; // CRLF

                Ok::<(String, u16, Vec<u8>), std::io::Error>((addr_str, port, payload))
            } => {
                match result {
                    Ok((addr_str, port, payload)) => {
                        let target_addr = format!("{}:{}", addr_str, port);
                        if let Ok(sock_addr) = target_addr.parse() {
                            if to_udp_tx.send((payload, sock_addr)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            // Write to TCP stream (UDP -> client)
            Some((payload, src_addr)) = from_udp_rx.recv() => {
                let mut frame = BytesMut::new();

                // Address type and address
                match src_addr {
                    std::net::SocketAddr::V4(v4) => {
                        frame.put_u8(1); // IPv4
                        frame.put_slice(&v4.ip().octets());
                    }
                    std::net::SocketAddr::V6(v6) => {
                        frame.put_u8(4); // IPv6
                        frame.put_slice(&v6.ip().octets());
                    }
                }

                frame.put_u16(src_addr.port());
                frame.put_u16(payload.len() as u16);
                frame.put_slice(&payload);
                frame.put_slice(CRLF);

                if stream.write_all(&frame).await.is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}
