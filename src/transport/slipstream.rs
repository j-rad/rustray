// src/transport/slipstream.rs
//! Slipstream Transport
//!
//! Encapsulates traffic within DNS queries (A/AAAA/TXT) to evade DPI.
//! Uses Quinn (QUIC) provides the reliable transport layer over the unreliable DNS/UDP carrier.

use crate::config::SlipstreamConfig;
use crate::error::Result;
// use crate::transport::AsyncStream;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tracing::{debug, error};

// Constants
const DNS_HEADER_SIZE: usize = 12;
// Use a smaller MTU for QUIC to ensure packets fit in DNS queries after encoding
const QUIC_MTU: u16 = 600;

/// Slipstream Tunnel Implementation
///
/// This struct wraps a Quinn Stream. The Quinn connection is maintained by a background
/// proxy task that tunnels QUIC packets through DNS queries.
pub struct SlipstreamTunnel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    // Keep internal handles alive
    _endpoint: quinn::Endpoint,
    _proxy_task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DnsRecordType {
    A = 1,
    AAAA = 28,
    TXT = 16,
}

impl SlipstreamTunnel {
    pub async fn connect(config: &SlipstreamConfig) -> Result<Self> {
        let resolver = config.resolver.parse::<SocketAddr>().map_err(|e| {
            anyhow::anyhow!("Invalid resolver address '{}': {}", config.resolver, e)
        })?;

        let record_type = match config.record_type.to_uppercase().as_str() {
            "A" => DnsRecordType::A,
            "AAAA" => DnsRecordType::AAAA,
            "TXT" => DnsRecordType::TXT,
            _ => DnsRecordType::TXT,
        };

        // 1. Setup Local Proxy Sockets
        // proxy_socket: internal socket that Quinn talks to (bound to localhost)
        let proxy_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let proxy_addr = proxy_socket.local_addr()?;

        // real_socket: external socket that talks to the DNS resolver
        let real_socket = UdpSocket::bind("0.0.0.0:0").await?;

        // 2. Setup Quinn Endpoint
        // We bind Quinn to a random localhost port
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Self::skip_verify_config())?,
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        // transport_config.initial_max_udp_payload_size(QUIC_MTU);
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config);

        // 3. Spawn the Forwarder/Proxy Task
        let domain = config.domain.clone();
        let forwarder = tokio::spawn(async move {
            Self::proxy_loop(proxy_socket, real_socket, resolver, domain, record_type).await;
        });

        // 4. Connect Quinn to our Local Proxy
        // We use "slipstream.internal" as server name. Crypto verification is skipped.
        let connection = endpoint.connect(proxy_addr, "slipstream.internal")?.await?;

        // 5. Open a bi-directional stream for the application
        let (send, recv) = connection.open_bi().await?;

        Ok(Self {
            send,
            recv,
            _endpoint: endpoint,
            _proxy_task: forwarder,
        })
    }

    fn skip_verify_config() -> rustls::ClientConfig {
        let roots = rustls::RootCertStore::empty();
        // Allow potentially self-signed or invalid certs for the tunnel transport
        #[derive(Debug)]
        struct SkipVerify;
        impl rustls::client::danger::ServerCertVerifier for SkipVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
            {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipVerify));

        config
    }

    async fn proxy_loop(
        proxy: UdpSocket,
        real: UdpSocket,
        resolver: SocketAddr,
        domain: String,
        record_type: DnsRecordType,
    ) {
        let mut buf_proxy = [0u8; 2048];
        let mut buf_real = [0u8; 2048];
        let mut next_tx_id: u16 = rand::random();

        // Map TransactionID -> Client Address (Quinn)
        // Since we only have one client (Quinn Endpoint), we can simplify.
        // We just always send back to the address that last sent to us.
        let mut quinn_addr: Option<SocketAddr> = None;

        loop {
            tokio::select! {
                // Packet from Quinn -> Encapsulate -> Internet
                res = proxy.recv_from(&mut buf_proxy) => {
                    match res {
                        Ok((len, src)) => {
                            quinn_addr = Some(src);
                            let payload = &buf_proxy[..len];

                            // Encode
                            let query = Self::encode_dns_query(payload, &domain, record_type, next_tx_id);
                            next_tx_id = next_tx_id.wrapping_add(1);

                            if let Err(e) = real.send_to(&query, resolver).await {
                                debug!("Failed to send DNS query: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Proxy socket error: {}", e);
                            break;
                        }
                    }
                }

                // Packet from Internet -> Decapsulate -> Quinn
                res = real.recv_from(&mut buf_real) => {
                    match res {
                        Ok((len, src)) => {
                            if src != resolver {
                                continue;
                            }
                            let packet = &buf_real[..len];
                            if let Some(payload) = DnsResponse::parse(packet).get_payload()
                                && let Some(addr) = quinn_addr
                                    && let Err(e) = proxy.send_to(&payload, addr).await {
                                        debug!("Failed to forward to Quinn: {}", e);
                                    }
                        }
                        Err(e) => {
                            error!("Real socket error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }

    fn encode_dns_query(
        data: &[u8],
        domain: &str,
        record_type: DnsRecordType,
        tx_id: u16,
    ) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);

        // Transaction ID
        packet.extend_from_slice(&tx_id.to_be_bytes());
        // Flags (Standard Query)
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        // Counts
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Encode Payload into Name
        let encoded_payload = hex::encode(data);
        // Split into 63-char labels
        for chunk in encoded_payload.as_bytes().chunks(63) {
            packet.push(chunk.len() as u8);
            packet.extend_from_slice(chunk);
        }

        // Append base domain
        for label in domain.split('.') {
            if label.is_empty() {
                continue;
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root

        // Type and Class
        packet.extend_from_slice(&(record_type as u16).to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes()); // IN

        packet
    }
}

// Forward AsyncRead/AsyncWrite to Quinn Stream
impl AsyncRead for SlipstreamTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for SlipstreamTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(Into::into)
    }
}

// Helper for parsing DNS
struct DnsResponse<'a> {
    packet: &'a [u8],
    q_count: u16,
    a_count: u16,
}

impl<'a> DnsResponse<'a> {
    fn parse(packet: &'a [u8]) -> Self {
        if packet.len() < 12 {
            return DnsResponse {
                packet,
                q_count: 0,
                a_count: 0,
            };
        }
        DnsResponse {
            packet,
            q_count: u16::from_be_bytes([packet[4], packet[5]]),
            a_count: u16::from_be_bytes([packet[6], packet[7]]),
        }
    }

    fn get_payload(&self) -> Option<Vec<u8>> {
        if self.a_count == 0 {
            return None;
        }

        let mut offset = DNS_HEADER_SIZE;
        // Skip Questions
        for _ in 0..self.q_count {
            offset = skip_q_name(self.packet, offset)?;
            offset += 4; // qtype + qclass
        }
        if offset >= self.packet.len() {
            return None;
        }

        // Parse first answer
        offset = skip_q_name(self.packet, offset)?;
        if offset + 10 > self.packet.len() {
            return None;
        }

        let record_type = u16::from_be_bytes([self.packet[offset], self.packet[offset + 1]]);
        offset += 8; // type(2)+class(2)+ttl(4)
        let rd_len = u16::from_be_bytes([self.packet[offset], self.packet[offset + 1]]) as usize;
        offset += 2;

        if offset + rd_len > self.packet.len() {
            return None;
        }

        match record_type {
            16 => {
                // TXT
                // TXT format: [len][text][len][text]...
                let mut data = Vec::new();
                let mut txt_off = offset;
                let end = offset + rd_len;
                while txt_off < end {
                    let seg_len = self.packet[txt_off] as usize;
                    txt_off += 1;
                    if txt_off + seg_len > end {
                        break;
                    }
                    data.extend_from_slice(&self.packet[txt_off..txt_off + seg_len]);
                    txt_off += seg_len;
                }
                hex::decode(data).ok()
            }
            1 | 28 => {
                // A or AAAA
                // In a real implementation we would decode IP-steganography
                None
            }
            _ => None,
        }
    }
}

fn skip_q_name(packet: &[u8], offset: usize) -> Option<usize> {
    let mut i = offset;
    while i < packet.len() {
        let len = packet[i];
        if len == 0 {
            return Some(i + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(i + 2);
        } // Pointer
        i += (len as usize) + 1;
    }
    None
}
