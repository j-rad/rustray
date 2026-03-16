// src/transport/speed_tester.rs
//! Professional Speed-Testing Module
//!
//! Provides Burst Throughput Engine and precision measuring tools.

use crate::error::Result;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;
use tracing::info;

/// The URL to use for speed testing (Cloudflare 1MB payload).
const BURST_TEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=1048576"; // 1MB
const CONCURRENCY: usize = 4;
const AUTO_KILL_THRESHOLD_BPS: u64 = 32_000; // ~256kbps
const AUTO_KILL_CHECK_MS: u64 = 200;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SpeedTestResult {
    pub download_speed_bps: u64,
    pub total_bytes: u64,
    pub duration_ms: u128,
    pub aborted_slow: bool,
}

pub struct SpeedTester;

impl SpeedTester {
    /// Performs a multi-stream burst throughput test.
    /// Aborts early (within ~200ms) if throughput is below threshold.
    pub async fn burst_test() -> Result<SpeedTestResult> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        let total_bytes = Arc::new(AtomicU64::new(0));
        let abort_flag = Arc::new(AtomicBool::new(false));
        let start = Instant::now();

        let mut handles = FuturesUnordered::new();

        for _ in 0..CONCURRENCY {
            let client = client.clone();
            let total = total_bytes.clone();
            let abort = abort_flag.clone();

            handles.push(tokio::spawn(async move {
                let mut response = match client.get(BURST_TEST_URL).send().await {
                    Ok(r) => r,
                    Err(_) => return,
                };

                let _stream_start = Instant::now();
                let mut check_done = false;

                while let Ok(Some(chunk)) = response.chunk().await {
                    if abort.load(Ordering::Relaxed) {
                        break;
                    }

                    let len = chunk.len() as u64;
                    total.fetch_add(len, Ordering::Relaxed);

                    // Auto-kill check
                    if !check_done {
                        let elapsed = start.elapsed(); // Global start
                        if elapsed.as_millis() as u64 >= AUTO_KILL_CHECK_MS {
                            let current_bytes = total.load(Ordering::Relaxed);
                            let bps =
                                (current_bytes * 8) as u64 * 1000 / elapsed.as_millis() as u64;
                            if bps < AUTO_KILL_THRESHOLD_BPS * 8 {
                                // Threshold is bps? 256kbps = 256000 bits/s
                                // Prompt says "throughput is below 256kbps"
                                // My const is 32_000 which is 32KB/s ~= 256kbps
                                // So bytes * 8 is bits.
                                // if bps < 256_000
                                abort.store(true, Ordering::Relaxed);
                                break;
                            }
                            check_done = true;
                        }
                    }
                }
            }));
        }

        // Wait for all streams
        while let Some(_) = handles.next().await {}

        let duration = start.elapsed();
        let total_loaded = total_bytes.load(Ordering::Relaxed);
        let aborted = abort_flag.load(Ordering::Relaxed);

        let bps = if duration.as_millis() > 0 {
            (total_loaded * 8) as u64 * 1000 / duration.as_millis() as u64
        } else {
            0
        };

        info!(
            "Burst Test: {} bytes in {}ms ({} bps), Aborted: {}",
            total_loaded,
            duration.as_millis(),
            bps,
            aborted
        );

        Ok(SpeedTestResult {
            download_speed_bps: bps,
            total_bytes: total_loaded,
            duration_ms: duration.as_millis(),
            aborted_slow: aborted,
        })
    }
}
