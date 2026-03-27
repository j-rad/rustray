// src/transport/brutal_cc.rs
//! Brutal Congestion Controller for Quinn (QUIC)
//!
//! Implements `quinn::congestion::Controller` with a fixed-rate pacing model.
//! Ignores loss signals — maintains a constant sending rate regardless of
//! network conditions, relying on FEC for loss recovery.

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Configuration for the Brutal congestion controller.
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrutalCcConfig {
    /// Target upload bandwidth in Mbps
    pub upload_mbps: u64,
    /// Target download bandwidth in Mbps
    pub download_mbps: u64,
}

impl Default for BrutalCcConfig {
    fn default() -> Self {
        Self {
            upload_mbps: 100,
            download_mbps: 100,
        }
    }
}

/// Pacing gain multiplier (1.25x target rate for burst headroom)
const PACING_GAIN: f64 = 1.25;
/// Minimum congestion window in bytes (4 packets × 1200 MTU)
const MIN_CWND: u64 = 4 * 1200;

/// A fixed-rate congestion controller that maintains constant throughput
/// regardless of packet loss, designed for use with FEC.
pub struct BrutalCongestionController {
    /// Target send rate in bytes/second
    target_rate_bps: u64,
    /// Current window in bytes
    window: u64,
    /// Smoothed RTT estimate in microseconds
    srtt_us: AtomicU64,
    /// Bytes acknowledged in current epoch
    bytes_acked: u64,
    /// Epoch start time
    epoch_start: Instant,
}

impl BrutalCongestionController {
    pub fn new(upload_mbps: u64) -> Self {
        let target_rate_bps = upload_mbps * 1_000_000 / 8;
        // Initial window: 100ms worth of data at target rate
        let initial_window = (target_rate_bps / 10).max(MIN_CWND);

        Self {
            target_rate_bps,
            window: initial_window,
            srtt_us: AtomicU64::new(50_000), // 50ms initial
            bytes_acked: 0,
            epoch_start: Instant::now(),
        }
    }

    fn recalculate_window(&mut self) {
        let srtt_secs = self.srtt_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        if srtt_secs > 0.0 {
            // Window = target_rate × RTT × pacing_gain
            let w = (self.target_rate_bps as f64 * srtt_secs * PACING_GAIN) as u64;
            self.window = w.max(MIN_CWND);
        }
    }
}

impl Controller for BrutalCongestionController {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bytes_acked += bytes;

        // Update SRTT from Quinn's estimator
        let rtt_us = rtt.get().as_micros() as u64;
        if rtt_us > 0 {
            self.srtt_us.store(rtt_us, Ordering::Relaxed);
        }

        self.recalculate_window();
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // Brutal mode: ignore congestion signals entirely.
        // FEC handles loss recovery. We never reduce the window.
        self.recalculate_window();
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {
        // No adjustment needed for fixed-rate
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            target_rate_bps: self.target_rate_bps,
            window: self.window,
            srtt_us: AtomicU64::new(self.srtt_us.load(Ordering::Relaxed)),
            bytes_acked: self.bytes_acked,
            epoch_start: self.epoch_start,
        })
    }

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory for creating BrutalCongestionController instances for Quinn endpoints.
#[derive(Debug, Clone)]
pub struct BrutalCongestionControllerFactory {
    upload_mbps: u64,
}

impl BrutalCongestionControllerFactory {
    pub fn new(upload_mbps: u64) -> Self {
        Self { upload_mbps }
    }
}

impl ControllerFactory for BrutalCongestionControllerFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalCongestionController::new(self.upload_mbps))
    }
}
