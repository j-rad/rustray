use crate::config::SlipstreamConfig;
use crate::error::Result;
use crate::transport::slipstream::SlipstreamTunnel;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info};

// If SurrealDB is enabled
#[cfg(feature = "surrealdb")]
use surrealdb::Surreal;
#[cfg(feature = "surrealdb")]
use surrealdb::engine::any::Any;

const CONCURRENCY_LIMIT: usize = 2000;
const TIMEOUT_MS: u64 = 1500;
const POISONED_IPS: &[&str] = &["10.10.34.34", "10.10.34.35", "10.10.34.36"];

#[derive(Clone)]
pub struct DnsScanner {
    semaphore: Arc<Semaphore>,
    pub found_resolvers: Arc<DashMap<IpAddr, ResolverType>>,
    scanned_count: Arc<AtomicU64>,
    #[cfg(feature = "surrealdb")]
    db: Option<Surreal<Any>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ResolverType {
    Clean,
    SlipstreamCapable,
}

impl DnsScanner {
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(CONCURRENCY_LIMIT)),
            found_resolvers: Arc::new(DashMap::new()),
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

    /// Load CIDRs from a file (e.g., assets/iran-ipv4.cidrs)
    pub fn load_iran_cidrs(path: impl AsRef<Path>) -> Result<Vec<String>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut cidrs = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                cidrs.push(trimmed.to_string());
            }
        }
        Ok(cidrs)
    }

    /// Scan a list of CIDRs strings using non-linear shuffling
    pub async fn scan_cidrs(&self, cidrs: Vec<String>) -> Result<()> {
        let mut networks = Vec::new();
        for cidr in cidrs {
            match cidr.parse::<IpNetwork>() {
                Ok(net) => networks.push(net),
                Err(e) => info!("Skipping invalid CIDR {}: {}", cidr, e),
            }
        }

        // Shuffle networks to avoid sequential pattern on the macro level
        networks.shuffle(&mut thread_rng());

        for net in networks {
            // Collect chunks of IPs to shuffle, preventing linear scanning pattern
            let mut chunk = Vec::with_capacity(256);

            for ip in net.iter() {
                if let IpAddr::V4(addr) = ip {
                    chunk.push(IpAddr::V4(addr));
                    if chunk.len() >= 256 {
                        chunk.shuffle(&mut thread_rng());
                        self.process_chunk(&chunk).await;
                        chunk.clear();
                    }
                }
            }

            if !chunk.is_empty() {
                chunk.shuffle(&mut thread_rng());
                self.process_chunk(&chunk).await;
            }
        }
        Ok(())
    }

    async fn process_chunk(&self, ips: &[IpAddr]) {
        for &ip in ips {
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let scanner = self.clone();

            tokio::spawn(async move {
                scanner.probe_ip(ip).await;
                drop(permit);
            });
        }
    }

    async fn probe_ip(&self, ip: IpAddr) {
        self.scanned_count.fetch_add(1, Ordering::Relaxed);

        // 1. Basic DNS Check (UDP 53) via google.com
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return,
        };

        if socket.connect((ip, 53)).await.is_err() {
            return;
        }

        let query = build_simple_query("google.com");
        if socket.send(&query).await.is_err() {
            return;
        }

        let mut buf = [0u8; 512];
        let res = timeout(Duration::from_millis(TIMEOUT_MS), socket.recv(&mut buf)).await;

        match res {
            Ok(Ok(n)) => {
                let response = &buf[..n];
                if verify_response_integrity(response) {
                    self.found_resolvers.insert(ip, ResolverType::Clean);
                    debug!("Found clean resolver: {}", ip);
                    self.persist_result(ip, ResolverType::Clean).await;

                    // 2. Slipstream Check (0-RTT)
                    if self.probe_slipstream(ip).await {
                        self.found_resolvers
                            .insert(ip, ResolverType::SlipstreamCapable);
                        info!("Found Slipstream-capable resolver: {}", ip);
                        self.persist_result(ip, ResolverType::SlipstreamCapable)
                            .await;
                    }
                } else {
                    debug!("Poisoned/Invalid response from: {}", ip);
                }
            }
            _ => { /* Timeout or Error */ }
        }
    }

    async fn persist_result(&self, ip: IpAddr, rtype: ResolverType) {
        #[cfg(feature = "surrealdb")]
        if let Some(db) = &self.db {
            // Using SystemTime for timestamp
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let record = serde_json::json!({
                "ip": ip,
                "type": rtype,
                "timestamp": now,
                "metadata": {
                    "isp": "unknown", // Need GeoIP lookup integration for actual ISP
                }
            });
            // Fire and forget
            let _: std::result::Result<Option<serde::de::IgnoredAny>, _> =
                db.create("dns_resolvers").content(record).await;
        }
    }

    async fn probe_slipstream(&self, ip: IpAddr) -> bool {
        let config = SlipstreamConfig {
            resolver: format!("{}:53", ip),
            domain: "slipstream.best".to_string(),
            record_type: "TXT".to_string(),
            ..Default::default()
        };

        let mut tunnel = match SlipstreamTunnel::connect(&config).await {
            Ok(t) => t,
            Err(_) => return false,
        };

        let probe_payload = b"slipstream-check";
        if timeout(
            Duration::from_millis(TIMEOUT_MS),
            tunnel.write_all(probe_payload),
        )
        .await
        .is_err()
        {
            return false;
        }

        let mut response_buf = [0u8; 32];
        match timeout(
            Duration::from_millis(TIMEOUT_MS),
            tunnel.read(&mut response_buf),
        )
        .await
        {
            Ok(Ok(n)) => &response_buf[..n] == probe_payload,
            _ => false,
        }
    }
}

// Simple query builder (Transaction ID 0x1234, recursion desired)
fn build_simple_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&[0x12, 0x34]); // ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    for part in domain.split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // Root null
    packet.extend_from_slice(&[0x00, 0x01]); // Type A
    packet.extend_from_slice(&[0x00, 0x01]); // Class IN
    packet
}

fn verify_response_integrity(response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }
    if response[0] != 0x12 || response[1] != 0x34 {
        return false;
    } // ID Match

    let rcode = response[3] & 0x0F;
    if rcode != 0 {
        return false;
    } // Must be NoError

    // Simple poisoning check
    for poison in POISONED_IPS {
        if let Ok(ip) = poison.parse::<std::net::Ipv4Addr>() {
            if find_subsequence(response, &ip.octets()).is_some() {
                return false;
            }
        }
    }
    true
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
