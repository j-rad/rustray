// src/scanner/cloudflare.rs

use crate::error::Result;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tracing::{debug, info};

// If SurrealDB is enabled
#[cfg(feature = "surrealdb")]
use surrealdb::Surreal;
#[cfg(feature = "surrealdb")]
use surrealdb::engine::any::Any;

const CONCURRENCY_LIMIT: usize = 500;
const TIMEOUT_MS: u64 = 2000;

#[derive(Clone)]
pub struct CloudflareScanner {
    semaphore: Arc<Semaphore>,
    pub valid_ips: Arc<DashMap<IpAddr, u128>>, // IP -> Latency(ms)
    scanned_count: Arc<AtomicU64>,
    #[cfg(feature = "surrealdb")]
    db: Option<Surreal<Any>>,
}

impl Default for CloudflareScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudflareScanner {
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(CONCURRENCY_LIMIT)),
            valid_ips: Arc::new(DashMap::new()),
            scanned_count: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "surrealdb")]
            db: None,
        }
    }

    #[cfg(feature = "surrealdb")]
    pub fn with_db(mut self, db: Surreal<Any>) -> Self {
        self.db = Some(db);
        self
    }

    pub async fn scan_cidrs(&self, cidrs: Vec<String>, target_sni: String) -> Result<()> {
        let mut networks = Vec::new();
        for cidr in cidrs {
            if let Ok(net) = cidr.parse::<IpNetwork>() {
                networks.push(net);
            } else {
                info!("Skipping invalid CIDR: {}", cidr);
            }
        }

        // Randomize network order
        networks.shuffle(&mut thread_rng());

        info!(
            "Starting Cloudflare scan on {} networks with SNI: {}",
            networks.len(),
            target_sni
        );

        for net in networks {
            // Collect small chunks of IPs to shuffle, preventing linear scanning pattern
            let mut chunk = Vec::with_capacity(256);

            for ip in net.iter() {
                if let IpAddr::V4(addr) = ip {
                    chunk.push(IpAddr::V4(addr));

                    // Process chunk when full
                    if chunk.len() >= 256 {
                        chunk.shuffle(&mut thread_rng());
                        self.process_chunk(&chunk, &target_sni).await;
                        chunk.clear();
                    }
                }
            }

            // Process remaining
            if !chunk.is_empty() {
                chunk.shuffle(&mut thread_rng());
                self.process_chunk(&chunk, &target_sni).await;
            }
        }
        Ok(())
    }

    async fn process_chunk(&self, ips: &[IpAddr], sni: &str) {
        // We spawn tasks but gate them with the semaphore
        for &ip in ips {
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return, // Scanner dropped
            };

            let scanner = self.clone();
            let sni = sni.to_string();

            tokio::spawn(async move {
                scanner.probe_ip(ip, &sni).await;
                drop(permit);
            });
        }
    }

    async fn probe_ip(&self, ip: IpAddr, sni: &str) {
        self.scanned_count.fetch_add(1, Ordering::Relaxed);

        let start = std::time::Instant::now();

        // 1. TCP Connect
        let stream = match timeout(
            Duration::from_millis(TIMEOUT_MS),
            TcpStream::connect((ip, 443)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return, // Timeout or Connect Error
        };

        // 2. TLS Handshake
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        // Parse SNI
        let domain = match rustls::pki_types::ServerName::try_from(sni.to_string()) {
            Ok(d) => d,
            Err(_) => return,
        };

        // Perform Handshake
        let mut tls_stream = match timeout(
            Duration::from_millis(TIMEOUT_MS),
            connector.connect(domain, stream),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return, // Handshake failed
        };

        // 3. SNI Fronting Verification (HTTP Request)
        // Send a minimal HTTP/1.1 request to verify the server accepts the SNI and talks HTTP
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.68.0\r\nConnection: close\r\n\r\n",
            sni
        );

        if timeout(
            Duration::from_millis(1000),
            tls_stream.write_all(request.as_bytes()),
        )
        .await
        .is_err()
        {
            return;
        }

        let mut buf = [0u8; 1024];
        let n = match timeout(Duration::from_millis(1000), tls_stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return, // Read failed or empty
        };

        let response = String::from_utf8_lossy(&buf[..n]);
        // expecting "HTTP/1.1 200" or "HTTP/1.1 301" etc.
        // If we get "HTTP/1.1 403 Forbidden", it might be filtered.
        // We consider it "Valid SNI Fronting" if we get a standard response header.
        // We specifically check NOT 403 if the requirement implies 403 is "Filtered".
        // But some valid sites return 403 on root.
        // Prompt says: "verify that the Cloudflare edge returns a valid header instead of a filtered 403"
        // This implies valid = !403.

        if response.starts_with("HTTP/1.1 ") || response.starts_with("HTTP/2 ") {
            if !response.contains("403 Forbidden") {
                let duration = start.elapsed().as_millis();
                self.valid_ips.insert(ip, duration);
                debug!("Found clean Cloudflare IP: {} ({}ms)", ip, duration);
                self.persist_result(ip, duration).await;
            } else {
                debug!("Blocked/Filtered (403): {}", ip);
            }
        }
    }

    async fn persist_result(&self, ip: IpAddr, latency: u128) {
        #[cfg(feature = "surrealdb")]
        if let Some(db) = &self.db {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let record = serde_json::json!({
                "ip": ip,
                "latency_ms": latency,
                "timestamp": now,
                "metadata": {
                    "isp": "unknown",
                    "type": "cloudflare"
                }
            });
            // Fire and forget
            let _: std::result::Result<Option<serde::de::IgnoredAny>, _> =
                db.create("cf_scanned_ips").content(record).await;
        }
    }
}
