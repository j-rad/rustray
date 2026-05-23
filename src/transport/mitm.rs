//! MITM (Man-in-the-Middle) Interception Module
//!
//! This module provides the capability to intercept TLS connections by acting as a 
//! transparent proxy that terminates TLS using on-the-fly generated certificates.
//! It uses a root CA certificate to sign domain-specific certificates, allowing
//! the system to inspect or modify encrypted traffic (given the root CA is trusted
//! by the client).
//!
//! ### Key Components
//! - **MitmManager**: Manages the root CA and caches generated server configurations.
//! - **Certificate Generation**: Uses `rcgen` to create X.509 certificates signed by the root CA.
//! - **MitmStream**: A wrapper around a TLS stream that provides the `TrinityTransport` interface.

use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub struct MitmManager {
    ca_cert: Arc<Certificate>,
    ca_key: KeyPair,
    cert_cache: RwLock<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmManager {
    pub fn new(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(ca_key_pem)
            .map_err(|e| anyhow::anyhow!("MITM: Invalid CA key: {}", e))?;
        
        let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .map_err(|e| anyhow::anyhow!("MITM: Invalid CA cert: {}", e))?;
        
        let ca_cert = params.self_signed(&key_pair)
            .map_err(|e| anyhow::anyhow!("MITM: Failed to create CA certificate: {}", e))?;

        Ok(Self {
            ca_cert: Arc::new(ca_cert),
            ca_key: key_pair,
            cert_cache: RwLock::new(HashMap::new()),
        })
    }

    pub fn generate_ca() -> Result<(String, String)> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "RustRay MITM Root CA");
        
        let key_pair = KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("MITM: CA Key generation failed: {}", e))?;
        let cert = params.self_signed(&key_pair)
            .map_err(|e| anyhow::anyhow!("MITM: CA Cert generation failed: {}", e))?;
        
        Ok((cert.pem(), key_pair.serialize_pem()))
    }

    pub async fn get_server_config(&self, domain: &str) -> Result<Arc<ServerConfig>> {
        {
            let cache = self.cert_cache.read().await;
            if let Some(config) = cache.get(domain) {
                return Ok(config.clone());
            }
        }

        let config = self.generate_server_config(domain)?;
        let mut cache = self.cert_cache.write().await;
        cache.insert(domain.to_string(), config.clone());
        Ok(config)
    }

    fn generate_server_config(&self, domain: &str) -> Result<Arc<ServerConfig>> {
        debug!("MITM: Generating certificate for {}", domain);

        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| anyhow::anyhow!("MITM: Cert params error: {}", e))?;
        
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, domain);
        params.is_ca = IsCa::NoCa;

        let key_pair = KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("MITM: Key generation failed: {}", e))?;
        
        // Sign with our CA
        let cert = params.signed_by(&key_pair, &self.ca_cert, &self.ca_key)
            .map_err(|e| anyhow::anyhow!("MITM: Signing failed: {}", e))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("MITM: TLS protocol error: {}", e))?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| anyhow::anyhow!("MITM: TLS Config error: {}", e))?;

        Ok(Arc::new(config))
    }

    pub async fn wrap_stream(
        &self,
        stream: BoxedTrinityTransport,
        domain: &str,
    ) -> Result<BoxedTrinityTransport> {
        let config = self.get_server_config(domain).await?;
        let acceptor = TlsAcceptor::from(config);
        let tls_stream = acceptor.accept(stream).await?;
        Ok(Box::new(tls_stream) as BoxedTrinityTransport)
    }
}

pub struct MitmStream {
    inner: BoxedTrinityTransport,
}

impl MitmStream {
    pub fn new(inner: BoxedTrinityTransport) -> Self {
        Self { inner }
    }
}

impl AsyncRead for MitmStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MitmStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TrinityTransport for MitmStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner.switch_carrier(new_carrier)
    }
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }
    fn handover(self, new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(Self { inner: new_tal })
    }
}

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
