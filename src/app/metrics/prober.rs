// src/app/metrics/prober.rs
use crate::error::Result;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PrecisionMetrics {
    pub ttfb_ms: u64,
    pub jitter_ms: f64,
    pub packet_loss_rate: f64,
    pub isp_detected: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdaptiveShaping {
    pub mss: u16,
    pub flow_j_jitter_multiplier: f64,
}

pub struct Prober;

impl Prober {
    /// Calculate Jitter using RFC 3550 formula (smoothed absolute difference of latencies)
    /// J(i) = J(i-1) + (|D(i-1, i)| - J(i-1)) / 16
    pub fn calculate_jitter(latencies: &[u128]) -> f64 {
        if latencies.len() < 2 {
            return 0.0;
        }

        let mut jitter = 0.0;
        for i in 1..latencies.len() {
            let diff = (latencies[i] as i128 - latencies[i - 1] as i128).abs() as f64;
            jitter = jitter + (diff - jitter) / 16.0;
        }
        jitter
    }

    /// Measure Time to First Byte (TTFB) and estimated Jitter via TCP ping sequence
    pub async fn probe_connection(addr: &str, count: usize) -> Result<PrecisionMetrics> {
        let mut latencies = Vec::with_capacity(count);
        let mut ttfb_sum = 0;
        let mut success = 0;

        for _ in 0..count {
            let start = Instant::now();
            match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    // Send a byte to clear buffers/trigger ACK
                    // Ideally we measure application layer Handshake TTFB
                    // For TCP, connect time = RTT.
                    // For HTTP, write request -> read first byte.

                    // Simple TCP Connect measurement:
                    let rtt = start.elapsed().as_millis();
                    latencies.push(rtt);
                    ttfb_sum += rtt as u64; // Using Connect time as proxy for TTFB/RTT here
                    success += 1;

                    let _ = stream.shutdown().await;
                }
                _ => {
                    // Timeout or error, count as loss?
                    // Latency not recorded.
                }
            }
            // Small gap
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let loss_rate = if count > 0 {
            1.0 - (success as f64 / count as f64)
        } else {
            0.0
        };

        let avg_ttfb = if success > 0 {
            ttfb_sum / success as u64
        } else {
            0
        };
        let jitter = Self::calculate_jitter(&latencies);

        // ISP Profiling: Detect MCI and apply adaptive shaping
        // In a real implementation, we'd look up the ASN of 'addr'.
        let isp_detected = if addr.contains("mci.ir") || addr.contains("1.1.1.1") {
            Some("MCI".to_string())
        } else {
            None
        };

        Ok(PrecisionMetrics {
            ttfb_ms: avg_ttfb,
            jitter_ms: jitter,
            packet_loss_rate: loss_rate,
            isp_detected,
        })
    }

    /// Update shaping parameters based on detected ISP metrics.
    /// For MCI: Clamp MSS to 1200 and increase Flow-J jitter.
    pub fn get_adaptive_shaping(metrics: &PrecisionMetrics) -> AdaptiveShaping {
        let mut shaping = AdaptiveShaping {
            mss: 1460, // Default TCP MSS
            flow_j_jitter_multiplier: 1.0,
        };

        if let Some(isp) = &metrics.isp_detected
            && isp == "MCI" {
                // Adversarial hardening for MCI: clamp MSS to hide fingerprint
                // and increase jitter to defeat AI timing classifiers.
                shaping.mss = 1200;
                shaping.flow_j_jitter_multiplier = 2.5;
            }

        shaping
    }
}
