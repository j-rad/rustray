// src/transport/tls.rs
//!
//! TLS Transport Layer
//!
//! Provides TLS wrapping for both client and server connections using rustls.
//! Supports various TLS configurations including ALPN, certificate verification,
//! and custom certificate chains.

use crate::config::TlsSettings;
use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use crate::transport::service_masquerade::MasqueradeStrategy;
use crate::transport::tls_mimicry::GhostProtocol;
use crate::transport::utls::{self};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io::{self, BufReader};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

/// Wrap a stream with TLS client encryption
pub async fn wrap_tls_client(
    stream: BoxedTrinityTransport,
    server_name: &str,
    settings: &TlsSettings,
) -> Result<BoxedTrinityTransport> {
    wrap_tls_client_ext(stream, server_name, settings, None).await
}

/// Simple TLS client wrapper using default settings (no uTLS fingerprint, no masquerade).
/// Used by CDN-Loop and REALITY V2 when a quick TLS 1.3 connection is needed.
pub async fn wrap_tls_client_simple(
    stream: BoxedTrinityTransport,
    server_name: &str,
) -> Result<BoxedTrinityTransport> {
    let settings = TlsSettings {
        server_name: Some(server_name.to_string()),
        allow_insecure: Some(false),
        alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
        ..Default::default()
    };
    wrap_tls_client(stream, server_name, &settings).await
}

/// Wrap a stream with TLS client encryption and optional service masquerade
pub async fn wrap_tls_client_ext(
    mut stream: BoxedTrinityTransport,
    server_name: &str,
    settings: &crate::config::TlsSettings,
    masquerade: Option<MasqueradeStrategy<'_>>,
) -> Result<BoxedTrinityTransport> {
    debug!("TLS: Wrapping client connection to {}", server_name);

    if let Some(pqc) = &settings.pqc
        && pqc.enabled
    {
        debug!("TLS: PQC Handshake initiated");
        let server_pk_hex = pqc.server_public_key.as_deref().unwrap_or("");
        let server_pk = hex::decode(server_pk_hex)
            .map_err(|e| anyhow::anyhow!("Invalid PQC server public key hex: {}", e))?;

        // For now, always generate ephemeral Dilithium identity for client
        let signing_kp = crate::transport::pqc::DilithiumKeypair::generate();
        stream = crate::transport::pqc::wrap_pqc_client(stream, &server_pk, &signing_kp).await?;
    }

    if let Some(strategy) = &masquerade
        && let Some(ghost) = &strategy.ghost
        && ghost.protocol.is_pre_tls()
    {
        debug!(
            "Mimicry: Sending pre-TLS ghost header: {}",
            ghost.description
        );
        stream.write_all(&ghost.bytes).await?;

        if ghost.protocol == GhostProtocol::PsqlSslRequest {
            // Postgres expects 'S' (SSL supported)
            let mut resp = [0u8; 1];
            stream.read_exact(&mut resp).await?;
            if resp[0] != b'S' {
                warn!(
                    "Mimicry: Server rejected PsqlSslRequest, expected 'S' but got '{}'",
                    resp[0] as char
                );
            }
        }
    }

    // Determine the connector (Prefer masquerade profile over static settings)
    let connector_opt = if let Some(strategy) = &masquerade {
        debug!(
            "TLS: Using masquerade profile for lane: {:?}",
            strategy.category
        );
        Some(utls::build_from_profile(
            strategy.profile,
            strategy.alpn.clone(),
            Some(server_name.to_string()),
            settings.pqc.as_ref(),
        )?)
    } else if let Some(fingerprint_str) = &settings.fingerprint {
        debug!("TLS: Using static fingerprint: {}", fingerprint_str);
        if fingerprint_str.eq_ignore_ascii_case("custom") {
            Some(utls::build_custom_connector(
                settings.alpn.clone(),
                Some(server_name.to_string()),
                settings.pqc.as_ref(),
            )?)
        } else {
            Some(utls::get_utls_connector(fingerprint_str)?)
        }
    } else {
        None
    };

    if let Some(connector) = connector_opt {
        if settings.allow_insecure.unwrap_or(false) {
            warn!("TLS: allow_insecure is set but might be ignored by uTLS connector");
        }

        let server_name_obj = ServerName::try_from(server_name.to_string())
            .map_err(|_| anyhow::anyhow!("Invalid server name: {}", server_name))?;

        let tls_stream = connector
            .connect(server_name_obj, stream)
            .await
            .map_err(|e| anyhow::anyhow!("uTLS connection failed: {}", e))?;

        debug!("TLS: Handshake completed (uTLS/Profile)");
        let mut final_stream: BoxedTrinityTransport = Box::new(tls_stream);

        // --- Phase 14b: Post-TLS Ghost Injection ---
        if let Some(strategy) = &masquerade
            && let Some(ghost) = &strategy.ghost
            && ghost.protocol.is_post_tls()
        {
            debug!(
                "Mimicry: Injecting post-TLS ghost header: {}",
                ghost.description
            );
            final_stream.write_all(&ghost.bytes).await?;
        }

        return Ok(final_stream);
    }

    // Standard Rustls Logic (Fallback if no profile or fingerprint)
    // Build root certificate store
    let mut root_store = RootCertStore::empty();

    // Add Mozilla's root certificates
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Build client config
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Some(pqc) = &settings.pqc
        && pqc.enabled
    {
        provider.kx_groups = vec![crate::transport::pqc::HybridGroup::X25519MlKem768.rustls_group()];
    }

    let config_builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS: Failed to set protocol versions: {}", e))?;

    let config = if settings.allow_insecure.unwrap_or(false) {
        warn!("TLS: Insecure mode enabled - certificate verification disabled");

        config_builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AllowAnyCert))
            .with_no_client_auth()
    } else {
        config_builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let mut config = config;

    // Set ALPN protocols if configured
    if let Some(alpn) = &settings.alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    let connector = TlsConnector::from(Arc::new(config));

    // Parse server name
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server name: {}", server_name))?;

    let tls_stream = connector.connect(server_name, stream).await?;

    debug!("TLS: Client handshake completed");
    Ok(Box::new(tls_stream) as BoxedTrinityTransport)
}

/// Wrap a stream with TLS server encryption
pub async fn wrap_tls_server(
    mut stream: BoxedTrinityTransport,
    settings: &TlsSettings,
) -> Result<BoxedTrinityTransport> {
    debug!("TLS: Accepting server connection");

    if let Some(pqc) = &settings.pqc
        && pqc.enabled
    {
        debug!("TLS: PQC Server Handshake initiated");
        // Generate ephemeral keypair if persistent storage missing format
        let server_kp = crate::transport::pqc::HybridKeypair::generate();
        stream = crate::transport::pqc::wrap_pqc_server(stream, &server_kp).await?;
    }

    let certs = settings
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No certificates provided for TLS server"))?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("Empty certificate list"));
    }

    // Load certificate chain
    let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
    for cert_config in certs {
        let cert_file = std::fs::File::open(&cert_config.certificate_file)?;
        let mut reader = BufReader::new(cert_file);

        // Parse certificates using the iterator API
        for item in rustls_pemfile::certs(&mut reader) {
            match item {
                Ok(cert) => cert_chain.push(cert),
                Err(e) => {
                    warn!("TLS: Failed to parse certificate: {}", e);
                }
            }
        }
    }

    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!(
            "No certificates found in certificate files"
        ));
    }

    // Load private key
    let key_file = std::fs::File::open(&certs[0].key_file)?;
    let mut reader = BufReader::new(key_file);

    let private_key = {
        let mut keys: Vec<PrivateKeyDer<'static>> = Vec::new();

        // Try reading all private key types
        loop {
            match rustls_pemfile::private_key(&mut reader) {
                Ok(Some(key)) => keys.push(key),
                Ok(None) => break,
                Err(e) => {
                    warn!("TLS: Failed to parse private key: {}", e);
                    // If we fail to read a key, we might be out of sync, or just bad block
                    // PEM parser usually recovers.
                }
            }
        }

        if keys.is_empty() {
            return Err(anyhow::anyhow!("No private key found in key file"));
        }

        keys.remove(0)
    };

    // Build server config
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Some(pqc) = &settings.pqc
        && pqc.enabled
    {
        provider.kx_groups = vec![crate::transport::pqc::HybridGroup::X25519MlKem768.rustls_group()];
    }

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS: Failed to set protocol versions: {}", e))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    // Set ALPN protocols if configured
    if let Some(alpn) = &settings.alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_stream = acceptor.accept(stream).await?;

    debug!("TLS: Server handshake completed");
    Ok(Box::new(tls_stream) as BoxedTrinityTransport)
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> TrinityTransport for tokio_rustls::client::TlsStream<S> {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TlsStream: switch_carrier not supported"))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Err(anyhow::anyhow!("TlsStream: handover not supported"))
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> TrinityTransport for tokio_rustls::server::TlsStream<S> {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "TlsStream: switch_carrier not supported"))
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn handover(self, _new_tal: BoxedTrinityTransport) -> Result<Self> {
        Err(anyhow::anyhow!("TlsStream: handover not supported"))
    }
}

// --- Insecure Certificate Verifier ---

/// A certificate verifier that accepts any certificate
///
/// **WARNING**: This should only be used for testing or with `allow_insecure: true`
#[derive(Debug)]
struct AllowAnyCert;

impl rustls::client::danger::ServerCertVerifier for AllowAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
