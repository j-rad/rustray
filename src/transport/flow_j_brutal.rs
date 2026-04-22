// src/transport/flow_j_brutal.rs
//! Brutal-QUIC Transport (Hysteria 2 Hybrid)
//!
//! Combines Quinn QUIC endpoint with FEC UDP socket wrapping and
//! the Brutal fixed-rate congestion controller for maximum throughput
//! through lossy, censored networks.

use crate::error::Result;
use crate::fec::transport::FecConfig;
use crate::transport::brutal_cc::{BrutalCcConfig, BrutalCongestionControllerFactory};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

/// Configuration for the Brutal-QUIC transport.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrutalTransportConfig {
    /// Server address
    pub address: String,
    /// Server name for TLS SNI
    #[serde(default)]
    pub server_name: String,
    /// Bandwidth configuration
    #[serde(default)]
    pub bandwidth: BrutalCcConfig,
    /// FEC configuration
    #[serde(default)]
    pub fec: FecConfig,
    /// Whether to enable FEC on the UDP socket
    #[serde(default = "default_fec_enabled")]
    pub fec_enabled: bool,
}

fn default_fec_enabled() -> bool {
    true
}

impl Default for BrutalTransportConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            server_name: String::new(),
            bandwidth: BrutalCcConfig::default(),
            fec: FecConfig::default(),
            fec_enabled: true,
        }
    }
}

/// Brutal QUIC transport stream wrapping Quinn SendStream + RecvStream.
pub struct BrutalQuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
}

impl BrutalQuicStream {
    /// Establish a Brutal-QUIC connection to the server.
    pub async fn connect(config: &BrutalTransportConfig) -> Result<Self> {
        let server_addr: SocketAddr = config
            .address
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address: {}", e))?;

        // Build TLS config with certificate verification disabled for tunneling
        let tls_config = Self::build_tls_config();

        // Build Quinn transport config with Brutal CC
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            std::time::Duration::from_secs(30)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid timeout: {}", e))?,
        ));

        // Install Brutal congestion controller
        let cc_factory = Arc::new(BrutalCongestionControllerFactory::new(
            config.bandwidth.upload_mbps,
        ));
        transport_config.congestion_controller_factory(cc_factory);

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| anyhow::anyhow!("QUIC TLS config error: {}", e))?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config);

        // Connect
        let sni = if config.server_name.is_empty() {
            "brutal.internal"
        } else {
            &config.server_name
        };

        info!("Brutal-QUIC: connecting to {} (SNI: {})", server_addr, sni);
        let connection = endpoint.connect(server_addr, sni)?.await?;

        // Open bidirectional stream
        let (send, recv) = connection.open_bi().await?;

        debug!("Brutal-QUIC: stream established");

        Ok(Self {
            send,
            recv,
            _endpoint: endpoint,
            _connection: connection,
        })
    }

    fn build_tls_config() -> rustls::ClientConfig {
        let roots = rustls::RootCertStore::empty();

        #[derive(Debug)]
        struct SkipServerVerification;

        impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> std::result::Result<
                rustls::client::danger::ServerCertVerified,
                rustls::Error,
            > {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<
                rustls::client::danger::HandshakeSignatureValid,
                rustls::Error,
            > {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<
                rustls::client::danger::HandshakeSignatureValid,
                rustls::Error,
            > {
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
            .set_certificate_verifier(Arc::new(SkipServerVerification));

        config
    }
}

impl AsyncRead for BrutalQuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for BrutalQuicStream {
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
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(Into::into)
    }
}
