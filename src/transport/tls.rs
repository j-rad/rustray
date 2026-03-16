// src/transport/tls.rs
//!
//! TLS Transport Layer
//!
//! Provides TLS wrapping for both client and server connections using rustls.
//! Supports various TLS configurations including ALPN, certificate verification,
//! and custom certificate chains.

use crate::config::TlsSettings;
use crate::error::Result;
use crate::transport::BoxedStream;
use crate::transport::utls::{self};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

/// Wrap a stream with TLS client encryption
pub async fn wrap_tls_client(
    mut stream: BoxedStream,
    server_name: &str,
    settings: &TlsSettings,
) -> Result<BoxedStream> {
    debug!("TLS: Wrapping client connection to {}", server_name);

    if let Some(pqc) = &settings.pqc {
        if pqc.enabled {
            debug!("TLS: PQC Handshake initiated");
            let server_pk_hex = pqc.server_public_key.as_deref().unwrap_or("");
            let server_pk = hex::decode(server_pk_hex)
                .map_err(|e| anyhow::anyhow!("Invalid PQC server public key hex: {}", e))?;

            // For now, always generate ephemeral Dilithium identity for client
            let signing_kp = crate::transport::pqc::DilithiumKeypair::generate();
            stream =
                crate::transport::pqc::wrap_pqc_client(stream, &server_pk, &signing_kp).await?;
        }
    }

    if let Some(fingerprint_str) = &settings.fingerprint {
        debug!("TLS: Using fingerprint: {}", fingerprint_str);

        let connector = if fingerprint_str.eq_ignore_ascii_case("custom") {
            utls::build_custom_connector(settings.alpn.clone(), Some(server_name.to_string()))
                .map_err(|e| anyhow::anyhow!("Failed to build custom uTLS connector: {}", e))?
        } else {
            utls::get_utls_connector(fingerprint_str)
                .map_err(|e| anyhow::anyhow!("Failed to create uTLS connector: {}", e))?
        };

        if settings.allow_insecure.unwrap_or(false) {
            warn!(
                "TLS: allow_insecure is set but might be ignored by uTLS connector in this version"
            );
        }

        let tls_stream = connector
            .connect_async(server_name, stream)
            .await
            .map_err(|e| anyhow::anyhow!("uTLS connection failed: {}", e))?;

        debug!("TLS: uTLS Client handshake completed");
        return Ok(Box::new(tls_stream));
    }

    // Standard Rustls Logic
    // Build root certificate store
    let mut root_store = RootCertStore::empty();

    // Add Mozilla's root certificates
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Build client config
    let config = if settings.allow_insecure.unwrap_or(false) {
        warn!("TLS: Insecure mode enabled - certificate verification disabled");

        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AllowAnyCert))
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
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
    Ok(Box::new(tls_stream))
}

/// Wrap a stream with TLS server encryption
pub async fn wrap_tls_server(
    mut stream: BoxedStream,
    settings: &TlsSettings,
) -> Result<BoxedStream> {
    debug!("TLS: Accepting server connection");

    if let Some(pqc) = &settings.pqc {
        if pqc.enabled {
            debug!("TLS: PQC Server Handshake initiated");
            // Generate ephemeral keypair if persistent storage missing format
            let server_kp = crate::transport::pqc::HybridKeypair::generate();
            stream = crate::transport::pqc::wrap_pqc_server(stream, &server_kp).await?;
        }
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
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    // Set ALPN protocols if configured
    if let Some(alpn) = &settings.alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_stream = acceptor.accept(stream).await?;

    debug!("TLS: Server handshake completed");
    Ok(Box::new(tls_stream))
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
