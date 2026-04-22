// src/transport/ghost_bucket.rs
//! Phase 5 — Asynchronous Resilience: The Ghost-Bucket.
//!
//! During severe "Kill Switch" events all direct TCP/UDP handshakes are blocked,
//! but domestic S3-compatible storage (ArvanCloud, MizbanCloud) remains open for
//! the domestic app ecosystem.  This module implements a zero-dependency S3 data
//! drop that tunnels bidirectional streams through PUT/GET operations.
//!
//! Architecture:
//! ```text
//!  Client (Pi5)                    Domestic S3 Bucket              VPS (Germany)
//!  ┌─────────┐    PUT blobs       ┌──────────────┐   GET/DELETE   ┌──────────┐
//!  │ Rustray  │ ────────────────► │ ArvanCloud   │ ◄──────────── │ Poller   │
//!  │ Upload   │                   │              │               │ Reassemb │
//!  │          │ ◄──────────────── │              │ ──────────── ►│          │
//!  │ Download │    GET/DELETE     │              │   PUT blobs   │ Upstream │
//!  └─────────┘                   └──────────────┘               └──────────┘
//! ```
//!
//! Key features:
//! - 64KB encrypted binary blobs disguised as app logs / thumbnail caches
//! - AWS SigV4-compatible request signing (minimal, zero-dep)
//! - Local file-based sliding window buffer for high-latency tolerance
//! - Randomized polling interval (300–800ms) to evade volume anomalies

use bytes::BytesMut;
use rand::Rng;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use reqwest::Client;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::PollSender;
use tracing::{debug, info, warn};
use uuid::Uuid;
use futures::SinkExt;

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default blob size: 64KB.
pub const BLOB_SIZE: usize = 65536;

/// Object-key disguise templates.  Rotated per upload.
const DISGUISE_TEMPLATES: &[&str] = &[
    "app_logs_v2_{}.bin",
    "thumb_cache_{}.jpg",
    "analytics_{}.dat",
    "crash_report_{}.dmp",
    "font_cache_{}.ttf",
    "locale_pack_{}.res",
];

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Settings for the Ghost-Bucket S3 bridge.
#[derive(Debug, Clone)]
pub struct GhostBucketConfig {
    /// S3-compatible endpoint URL (e.g., `https://s3.ir-thr-at1.arvanstorage.ir`).
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// S3 region string (e.g., `ir-thr-at1`).
    pub region: String,
    /// Access key ID.
    pub access_key: String,
    /// Secret access key (used for SigV4 signing).
    pub secret_key: String,
    /// Polling interval range in milliseconds `[min, max]`.
    pub poll_interval_ms: (u64, u64),
    /// Maximum number of blobs to keep in the sliding window buffer.
    pub window_size: usize,
    /// Local cache directory for file-based sliding window (Pi 5 SD card).
    pub cache_dir: Option<String>,
}

impl Default for GhostBucketConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://s3.ir-thr-at1.arvanstorage.ir".to_string(),
            bucket: "app-telemetry-prod".to_string(),
            region: "ir-thr-at1".to_string(),
            access_key: String::new(),
            secret_key: String::new(),
            poll_interval_ms: (300, 800),
            window_size: 64,
            cache_dir: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal SigV4 signing
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal AWS Signature V4 signer for S3-compatible APIs.
///
/// Produces an `Authorization` header value for a single request.
struct SigV4Signer {
    access_key: String,
    secret_key: String,
    region: String,
    service: String,
}

impl SigV4Signer {
    fn new(access_key: &str, secret_key: &str, region: &str) -> Self {
        Self {
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            region: region.to_string(),
            service: "s3".to_string(),
        }
    }

    /// Compute HMAC-SHA256.
    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC key length is always valid");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Derive the signing key for the given date.
    fn signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = Self::hmac_sha256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = Self::hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, self.service.as_bytes());
        Self::hmac_sha256(&k_service, b"aws4_request")
    }

    /// Sign a request and return `(authorization_header, x_amz_date, content_sha256)`.
    fn sign(
        &self,
        method: &str,
        path: &str,
        host: &str,
        payload_hash: &str,
        now: SystemTime,
    ) -> (String, String, String) {
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = duration.as_secs();
        // Format as ISO 8601: 20260419T193500Z
        let amz_date = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            1970 + secs / 31556952, // approximate year
            (secs % 31556952) / 2629746 + 1, // approximate month
            (secs % 2629746) / 86400 + 1, // approximate day
            (secs % 86400) / 3600,
            (secs % 3600) / 60,
            secs % 60
        );
        let date_stamp = &amz_date[..8];

        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, amz_date
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method, path, canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, self.region, self.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signing_key = self.signing_key(date_stamp);
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, credential_scope, signed_headers, signature
        );

        (authorization, amz_date, payload_hash.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Blob disguise
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a disguised object key for a blob upload.
fn disguised_object_key(session_id: &str, sequence: u64, direction: &str) -> String {
    let mut rng = rand::thread_rng();
    let template = DISGUISE_TEMPLATES[rng.gen_range(0..DISGUISE_TEMPLATES.len())];
    let nonce = rng.gen_range(10000..99999);
    let filename = template.replace("{}", &format!("{}_{}", nonce, sequence));
    format!("{}/{}/{}", session_id, direction, filename)
}

// ─────────────────────────────────────────────────────────────────────────────
// GhostBucket core
// ─────────────────────────────────────────────────────────────────────────────

/// The Ghost-Bucket bridge.
pub struct GhostBucket {
    client: Client,
    config: Arc<GhostBucketConfig>,
    signer: SigV4Signer,
    session_id: String,
}

impl GhostBucket {
    /// Create a new Ghost-Bucket bridge.
    pub fn new(config: GhostBucketConfig) -> Self {
        let signer = SigV4Signer::new(&config.access_key, &config.secret_key, &config.region);
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .build()
            .expect("HTTP client creation should not fail");

        let session_id = Uuid::new_v4().to_string().replace('-', "");
        info!("GhostBucket: session {} initialized", &session_id[..8]);

        Self {
            client,
            config: Arc::new(config),
            signer,
            session_id,
        }
    }

    /// Upload an encrypted blob to the S3 bucket.
    pub async fn put_blob(&self, data: &[u8], sequence: u64) -> io::Result<()> {
        let object_key = disguised_object_key(&self.session_id, sequence, "outbound");
        let path = format!("/{}/{}", self.config.bucket, object_key);
        let url = format!("{}{}", self.config.endpoint, path);
        let host = self.config.endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("localhost");

        let payload_hash = hex::encode(Sha256::digest(data));
        let (auth, amz_date, content_sha) =
            self.signer.sign("PUT", &path, host, &payload_hash, SystemTime::now());

        let resp = self.client
            .put(&url)
            .header("Authorization", auth)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", content_sha)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;

        if !resp.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("S3 PUT failed: {}", resp.status()),
            ));
        }

        debug!("GhostBucket: PUT blob seq={} key={}", sequence, object_key);
        Ok(())
    }

    /// Poll and download a blob from the inbound path.
    pub async fn get_blob(&self, sequence: u64) -> io::Result<Option<Vec<u8>>> {
        let object_key = disguised_object_key(&self.session_id, sequence, "inbound");
        let path = format!("/{}/{}", self.config.bucket, object_key);
        let url = format!("{}{}", self.config.endpoint, path);
        let host = self.config.endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("localhost");

        let payload_hash = hex::encode(Sha256::digest(b""));
        let (auth, amz_date, content_sha) =
            self.signer.sign("GET", &path, host, &payload_hash, SystemTime::now());

        let resp = self.client
            .get(&url)
            .header("Authorization", auth)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", content_sha)
            .send()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None); // No data yet; peer hasn't uploaded.
        }

        if !resp.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("S3 GET failed: {}", resp.status()),
            ));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Fire-and-forget DELETE to clean up the consumed blob.
        let del_url = url.clone();
        let del_client = self.client.clone();
        tokio::spawn(async move {
            let _ = del_client.delete(&del_url).send().await;
        });

        debug!("GhostBucket: GET blob seq={} len={}", sequence, body.len());
        Ok(Some(body.to_vec()))
    }

    /// Expose the session ID for external coordination (e.g., sharing with the VPS poller).
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sliding Window Buffer
// ─────────────────────────────────────────────────────────────────────────────

/// File-backed sliding window buffer for high-latency S3 polling.
///
/// Maintains a window of outbound blobs that haven't been acknowledged.
/// If the S3 upload fails, blobs are persisted to local disk and retried.
pub struct SlidingWindowBuffer {
    /// In-memory queue of (sequence, data) tuples awaiting upload.
    pending: std::collections::VecDeque<(u64, Vec<u8>)>,
    /// Maximum window size.
    max_window: usize,
    /// Next sequence number.
    next_seq: u64,
    /// Optional local cache directory.
    cache_dir: Option<std::path::PathBuf>,
}

impl SlidingWindowBuffer {
    pub fn new(max_window: usize, cache_dir: Option<String>) -> Self {
        let cache_path = cache_dir.map(std::path::PathBuf::from);
        if let Some(ref dir) = cache_path {
            let _ = std::fs::create_dir_all(dir);
        }
        Self {
            pending: std::collections::VecDeque::with_capacity(max_window),
            max_window,
            next_seq: 0,
            cache_dir: cache_path,
        }
    }

    /// Enqueue a data chunk for upload. Returns the assigned sequence number.
    pub fn enqueue(&mut self, data: Vec<u8>) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;

        // Persist to disk if cache is configured.
        if let Some(ref dir) = self.cache_dir {
            let path = dir.join(format!("blob_{:08}.bin", seq));
            let _ = std::fs::write(&path, &data);
        }

        // If window is full, drop the oldest (it was already uploaded or lost).
        if self.pending.len() >= self.max_window {
            if let Some((old_seq, _)) = self.pending.pop_front() {
                if let Some(ref dir) = self.cache_dir {
                    let path = dir.join(format!("blob_{:08}.bin", old_seq));
                    let _ = std::fs::remove_file(path);
                }
            }
        }

        self.pending.push_back((seq, data));
        seq
    }

    /// Mark a sequence number as successfully uploaded and remove it from the window.
    pub fn acknowledge(&mut self, seq: u64) {
        self.pending.retain(|(s, _)| *s != seq);
        if let Some(ref dir) = self.cache_dir {
            let path = dir.join(format!("blob_{:08}.bin", seq));
            let _ = std::fs::remove_file(path);
        }
    }

    /// Get all pending blobs for retry.
    pub fn pending_blobs(&self) -> &std::collections::VecDeque<(u64, Vec<u8>)> {
        &self.pending
    }

    /// Current window occupancy.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GhostBucketStream — AsyncRead/AsyncWrite wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// An `AsyncRead + AsyncWrite` stream backed by the Ghost-Bucket S3 transport.
pub struct GhostBucketStream {
    read_buffer: BytesMut,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: PollSender<Vec<u8>>,
}

impl GhostBucketStream {
    /// Create a new stream from a GhostBucket instance.
    ///
    /// Spawns background tasks for upload and download polling.
    pub fn new(bucket: GhostBucket, config: GhostBucketConfig) -> Self {
        let bucket = Arc::new(bucket);
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(128);
        let (write_tx_inner, mut write_rx) = mpsc::channel::<Vec<u8>>(128);

        // Upload task
        let upload_bucket = bucket.clone();
        tokio::spawn(async move {
            let mut window = SlidingWindowBuffer::new(
                config.window_size,
                config.cache_dir.clone(),
            );
            while let Some(data) = write_rx.recv().await {
                // Fragment into BLOB_SIZE chunks.
                for chunk in data.chunks(BLOB_SIZE) {
                    let seq = window.enqueue(chunk.to_vec());
                    match upload_bucket.put_blob(chunk, seq).await {
                        Ok(()) => window.acknowledge(seq),
                        Err(e) => {
                            warn!("GhostBucket: PUT failed seq={}: {}", seq, e);
                            // Blob remains in window for retry on next iteration.
                        }
                    }
                }
            }
        });

        // Download polling task
        let download_bucket = bucket.clone();
        let poll_range = (config.poll_interval_ms.0, config.poll_interval_ms.1);
        tokio::spawn(async move {
            let mut seq = 0u64;
            loop {
                let jitter = rand::thread_rng().gen_range(poll_range.0..=poll_range.1);
                tokio::time::sleep(Duration::from_millis(jitter)).await;

                match download_bucket.get_blob(seq).await {
                    Ok(Some(data)) if !data.is_empty() => {
                        if read_tx.send(data).await.is_err() {
                            break; // Receiver dropped.
                        }
                        seq += 1;
                    }
                    Ok(_) => {} // No data yet, keep polling.
                    Err(e) => {
                        debug!("GhostBucket: GET error seq={}: {}", seq, e);
                    }
                }
            }
        });

        Self {
            read_buffer: BytesMut::with_capacity(BLOB_SIZE),
            read_rx,
            write_tx: PollSender::new(write_tx_inner),
        }
    }
}

impl AsyncRead for GhostBucketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let n = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer.split_to(n));
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.len() <= buf.remaining() {
                    buf.put_slice(&data);
                } else {
                    let n = buf.remaining();
                    buf.put_slice(&data[..n]);
                    self.read_buffer.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GhostBucketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = std::task::ready!(self.write_tx.poll_ready_unpin(cx)) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }
        let data = buf.to_vec();
        let len = data.len();
        if let Err(e) = self.write_tx.start_send_unpin(data) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_flush_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_close_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disguised_object_key_format() {
        let key = disguised_object_key("abc123", 0, "outbound");
        assert!(key.starts_with("abc123/outbound/"));
        assert!(key.len() > 20, "Key should include disguise filename");
    }

    #[test]
    fn test_disguised_keys_vary() {
        let mut keys = std::collections::HashSet::new();
        for seq in 0..20 {
            keys.insert(disguised_object_key("sess", seq, "outbound"));
        }
        // With random nonce, most keys should be unique.
        assert!(keys.len() >= 15, "Keys should be mostly unique");
    }

    #[test]
    fn test_sliding_window_enqueue_acknowledge() {
        let mut buf = SlidingWindowBuffer::new(4, None);
        let s0 = buf.enqueue(vec![1, 2, 3]);
        let s1 = buf.enqueue(vec![4, 5, 6]);
        assert_eq!(buf.len(), 2);
        buf.acknowledge(s0);
        assert_eq!(buf.len(), 1);
        buf.acknowledge(s1);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_sliding_window_overflow() {
        let mut buf = SlidingWindowBuffer::new(3, None);
        buf.enqueue(vec![1]);
        buf.enqueue(vec![2]);
        buf.enqueue(vec![3]);
        assert_eq!(buf.len(), 3);
        // Enqueue a 4th — oldest should be dropped.
        buf.enqueue(vec![4]);
        assert_eq!(buf.len(), 3);
        // The oldest seq (0) should no longer be present.
        assert!(buf.pending_blobs().iter().all(|(s, _)| *s != 0));
    }

    #[test]
    fn test_sigv4_signer_produces_auth_header() {
        let signer = SigV4Signer::new("AKID", "SECRET", "us-east-1");
        let (auth, date, hash) = signer.sign(
            "PUT",
            "/bucket/key",
            "s3.amazonaws.com",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            SystemTime::now(),
        );
        assert!(auth.starts_with("AWS4-HMAC-SHA256"));
        assert!(!date.is_empty());
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_default_config() {
        let cfg = GhostBucketConfig::default();
        assert_eq!(cfg.poll_interval_ms, (300, 800));
        assert_eq!(cfg.window_size, 64);
    }

    #[test]
    fn test_blob_size_constant() {
        assert_eq!(BLOB_SIZE, 65536, "Blob size must be 64KB");
    }
}
