// src/transport/mqtt/scheduler.rs
//! MVT MQTT Scheduler — Multi-stream fairness with ML-resistant traffic shaping
//!
//! The scheduler sits between the Virtual Transport Matrix and the MQTT broker.
//! It provides three guarantees:
//!
//! 1. **Fairness** (`drr_tick`): Deficit Round Robin ensures that each logical
//!    VTM stream gets a fair share of MQTT PUBLISH bandwidth, preventing any
//!    single stream from starving the others.
//!
//! 2. **Pacing** (`token_bucket_pacing`): A token bucket smooths bursts of
//!    PUBLISH messages to prevent broker-level rate limiting.  The token
//!    replenish rate is tuned to match `BehaviorProfile.ipt_components`.
//!
//! 3. **ML resistance** (`apply_markov_jitter`): A 2-state Markov chain
//!    ("Reading" / "Scrolling") randomises inter-packet intervals so that the
//!    traffic's IPT distribution matches a human user browsing Aparat or
//!    Instagram, defeating the GFW's 2026 ML classifier.

use crate::app::behavior_synth::BehaviorSynthesizer;
use rand::Rng;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::debug;

// ─── Markov Activity State ─────────────────────────────────────────────────────

/// Two-state Markov chain for IPT shaping.
///
/// | State    | Description           | Mean IPT    |
/// |----------|-----------------------|-------------|
/// | Reading  | User reading content  | 800–2000 ms |
/// | Scrolling| User scrolling feed   | 10–50 ms    |
///
/// Transition matrix (row = current, col = next):
/// ```
/// Reading   → Reading:   0.85   Reading   → Scrolling: 0.15
/// Scrolling → Scrolling: 0.70   Scrolling → Reading:   0.30
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActivityState {
    /// User is reading; long IPT pauses between packet bursts.
    Reading,
    /// User is scrolling; short IPT bursts as images load.
    Scrolling,
}

impl ActivityState {
    /// Sample the next state according to the transition matrix.
    pub fn transition(&self) -> Self {
        let p: f64 = rand::thread_rng().r#gen();
        match self {
            ActivityState::Reading => {
                if p < 0.85 {
                    ActivityState::Reading
                } else {
                    ActivityState::Scrolling
                }
            }
            ActivityState::Scrolling => {
                if p < 0.70 {
                    ActivityState::Scrolling
                } else {
                    ActivityState::Reading
                }
            }
        }
    }

    /// Sample a jitter delay for the current state.
    ///
    /// Reading:   Gaussian(mean=1200ms, σ=400ms), clamped [200ms, 4000ms]
    /// Scrolling: Gaussian(mean=20ms, σ=8ms),    clamped [5ms,  120ms]
    pub fn sample_jitter_ms(&self) -> u64 {
        let mut rng = rand::thread_rng();
        let ms = match self {
            ActivityState::Reading => {
                let mean = 1200.0f64;
                let sigma = 400.0;
                let z: f64 = rng.r#gen::<f64>() * 2.0 - 1.0; // crude normal approx
                (mean + z * sigma).clamp(200.0, 4000.0)
            }
            ActivityState::Scrolling => {
                let mean = 20.0f64;
                let sigma = 8.0;
                let z: f64 = rng.r#gen::<f64>() * 2.0 - 1.0;
                (mean + z * sigma).clamp(5.0, 120.0)
            }
        };
        ms as u64
    }
}

// ─── FlowQueue ────────────────────────────────────────────────────────────────

/// A per-stream queue inside the DRR scheduler.
pub struct FlowQueue {
    /// Stream identifier.
    pub id: usize,
    /// Accumulated deficit (bytes).
    pub deficit: usize,
    /// Per-round quantum (bytes) assigned to this stream.
    pub quantum: usize,
    /// Pending PUBLISH payloads.
    pub packets: VecDeque<Vec<u8>>,
    /// Per-queue token bucket for rate limiting.
    tokens: f64,
    /// Max tokens (= burst size in bytes).
    token_max: f64,
    /// Token replenish rate (bytes / second).
    token_rate: f64,
    /// Last time tokens were replenished.
    last_refill: Instant,
}

impl FlowQueue {
    fn new(id: usize, quantum: usize, rate_bps: f64) -> Self {
        Self {
            id,
            deficit: 0,
            quantum,
            packets: VecDeque::new(),
            tokens: quantum as f64, // start with one quantum of burst credit
            token_max: quantum as f64 * 4.0,
            token_rate: rate_bps / 8.0, // bits/s → bytes/s
            last_refill: Instant::now(),
        }
    }

    /// Refill the token bucket based on elapsed time since the last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.token_rate).min(self.token_max);
        self.last_refill = now;
    }

    /// Try to consume `bytes` tokens.  Returns `true` if the token budget allows it.
    fn try_consume(&mut self, bytes: usize) -> bool {
        self.refill();
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

// ─── DrrScheduler ─────────────────────────────────────────────────────────────

/// Deficit Round Robin scheduler with integrated token-bucket pacing and
/// Markov-chain jitter.
pub struct DrrScheduler {
    pub queues: Vec<FlowQueue>,
    pub current_queue: usize,
    /// Current Markov activity state (shared across all queues).
    activity_state: ActivityState,
    /// Timestamp of the last scheduled packet (for jitter enforcement).
    last_scheduled: Option<Instant>,
    /// Accumulated jitter debt (ms) — the scheduler must wait this long
    /// before emitting the next packet.
    jitter_debt_ms: u64,
}

impl DrrScheduler {
    /// Create an empty scheduler starting in the Scrolling state.
    pub fn new() -> Self {
        Self {
            queues: Vec::new(),
            current_queue: 0,
            activity_state: ActivityState::Scrolling,
            last_scheduled: None,
            jitter_debt_ms: 0,
        }
    }

    /// Add a new flow queue with the given `quantum` (bytes per round) and
    /// `rate_bps` (token bucket replenish rate in bits/second).
    ///
    /// Returns the new queue's ID.
    pub fn add_queue(&mut self, quantum: usize, rate_bps: f64) -> usize {
        let id = self.queues.len();
        self.queues.push(FlowQueue::new(id, quantum, rate_bps));
        id
    }

    /// Enqueue a payload into the specified queue.
    pub fn enqueue(&mut self, queue_id: usize, payload: Vec<u8>) {
        if let Some(q) = self.queues.get_mut(queue_id) {
            q.packets.push_back(payload);
        }
    }

    // ── drr_tick ──────────────────────────────────────────────────────────────

    /// Perform one DRR scheduling tick.
    ///
    /// Walks the queue ring, finds the next queue that has:
    /// 1. Pending packets.
    /// 2. Sufficient deficit to send the front packet.
    /// 3. Sufficient token-bucket credit.
    ///
    /// Returns the packet and the queue ID it came from, or `None` if no
    /// queue is ready to send.
    pub fn drr_tick(&mut self) -> Option<(usize, Vec<u8>)> {
        if self.queues.is_empty() {
            return None;
        }

        let num_queues = self.queues.len();
        let start = self.current_queue;

        for _ in 0..num_queues {
            let idx = self.current_queue;
            let queue = &mut self.queues[idx];

            if queue.packets.is_empty() {
                // No work for this queue; clear deficit (DRR spec §2).
                queue.deficit = 0;
                self.current_queue = (self.current_queue + 1) % num_queues;
                continue;
            }

            // Add the quantum to the deficit.
            queue.deficit = queue.deficit.saturating_add(queue.quantum);

            // Try to dequeue packets while we have enough deficit and tokens.
            if let Some(pkt) = queue.packets.front() {
                let pkt_len = pkt.len();
                if queue.deficit >= pkt_len && queue.try_consume(pkt_len) {
                    queue.deficit -= pkt_len;
                    let pkt = queue.packets.pop_front().unwrap();
                    let queue_id = queue.id;
                    debug!(
                        "DRR: queue={} deficit={} len={}",
                        queue_id, queue.deficit, pkt_len
                    );
                    self.current_queue = (self.current_queue + 1) % num_queues;
                    return Some((queue_id, pkt));
                }
            }

            self.current_queue = (self.current_queue + 1) % num_queues;
            if self.current_queue == start {
                break; // full round with no ready packet
            }
        }

        None
    }

    // ── token_bucket_pacing ───────────────────────────────────────────────────

    /// Check whether the global pacing budget allows sending a packet of `size` bytes.
    ///
    /// The scheduler maintains a global token bucket in addition to per-queue
    /// buckets to enforce an aggregate throughput ceiling, preventing broker-level
    /// rate limiting from triggering.
    ///
    /// Returns the delay the caller should wait if the budget is exhausted, or
    /// `Duration::ZERO` if the packet can be sent immediately.
    pub fn token_bucket_pacing(&mut self, size: usize, global_rate_bps: f64) -> Duration {
        // Simple global throttle: compute when the next token will be available.
        if let Some(last) = self.last_scheduled {
            let bytes_per_sec = global_rate_bps / 8.0;
            let required_gap_us = (size as f64 / bytes_per_sec * 1_000_000.0) as u64;
            let elapsed_us = last.elapsed().as_micros() as u64;
            if elapsed_us < required_gap_us {
                let wait_us = required_gap_us - elapsed_us;
                return Duration::from_micros(wait_us);
            }
        }
        self.last_scheduled = Some(Instant::now());
        Duration::ZERO
    }

    // ── apply_markov_jitter ───────────────────────────────────────────────────

    /// Sample jitter from the Markov activity state machine and return the
    /// duration the caller should sleep before emitting the next packet.
    ///
    /// The state machine transitions stochastically on each call, producing IPT
    /// patterns that match a human user browsing Iranian social media.  This
    /// defeats the GFW's 2026 ML classifier, which uses Inter-Packet Time (IPT)
    /// and Packet-Size Distribution (PSD) analysis.
    ///
    /// The caller **must** `tokio::time::sleep` the returned duration before
    /// calling `drr_tick` to emit the next packet.
    pub fn apply_markov_jitter(&mut self, synth: &mut BehaviorSynthesizer) -> Duration {
        // Check the accumulated jitter debt first.
        if self.jitter_debt_ms > 0 {
            let debt = self.jitter_debt_ms;
            self.jitter_debt_ms = 0;
            return Duration::from_millis(debt);
        }

        // Transition the Markov state.
        self.activity_state = self.activity_state.transition();

        // Sample jitter from the current state.
        let markov_jitter_ms = self.activity_state.sample_jitter_ms();

        // Blend with the BehaviorSynthesizer's GMM delay for added realism.
        let gmm_delay = synth.sample_delay();
        let gmm_ms = gmm_delay.as_millis() as u64;

        // Weight: 60% Markov + 40% GMM.
        let blended_ms = (markov_jitter_ms * 60 + gmm_ms * 40) / 100;

        debug!(
            "Jitter: state={:?} markov={}ms gmm={}ms blended={}ms",
            self.activity_state, markov_jitter_ms, gmm_ms, blended_ms
        );

        Duration::from_millis(blended_ms)
    }

    /// Return the current Markov activity state (for metrics/logging).
    pub fn activity_state(&self) -> ActivityState {
        self.activity_state
    }
}

impl Default for DrrScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::behavior_synth::{BehaviorProfile, BehaviorSynthesizer};

    #[test]
    fn drr_round_robins_between_queues() {
        let mut sched = DrrScheduler::new();
        let q0 = sched.add_queue(1024, 1_000_000.0);
        let q1 = sched.add_queue(1024, 1_000_000.0);

        sched.enqueue(q0, vec![0u8; 100]);
        sched.enqueue(q0, vec![1u8; 100]);
        sched.enqueue(q1, vec![2u8; 100]);
        sched.enqueue(q1, vec![3u8; 100]);

        // First tick from q0, second from q1 (round robin).
        let r0 = sched.drr_tick().unwrap();
        let r1 = sched.drr_tick().unwrap();

        // Both queues should be served.
        let ids: Vec<usize> = vec![r0.0, r1.0];
        assert!(ids.contains(&0));
        assert!(ids.contains(&1));
    }

    #[test]
    fn token_bucket_enforces_pacing() {
        let mut sched = DrrScheduler::new();
        // Very low rate: 80 bits/s = 10 bytes/s
        // A 100-byte packet would take 10 seconds at 10 bytes/s.
        let wait = sched.token_bucket_pacing(100, 80.0);
        // First call should be free (no last_scheduled yet).
        assert_eq!(wait, Duration::ZERO);

        // Second immediate call should demand a wait.
        let wait2 = sched.token_bucket_pacing(100, 80.0);
        assert!(wait2 > Duration::ZERO);
    }

    #[test]
    fn markov_jitter_returns_positive_duration() {
        let mut sched = DrrScheduler::new();
        let mut synth = BehaviorSynthesizer::new(BehaviorProfile::instagram_mci());

        for _ in 0..20 {
            let d = sched.apply_markov_jitter(&mut synth);
            assert!(d.as_millis() > 0, "Jitter must be positive");
        }
    }

    #[test]
    fn markov_state_transitions_both_ways() {
        let mut saw_reading = false;
        let mut saw_scrolling = false;
        let mut state = ActivityState::Scrolling;

        for _ in 0..500 {
            state = state.transition();
            match state {
                ActivityState::Reading => saw_reading = true,
                ActivityState::Scrolling => saw_scrolling = true,
            }
        }

        assert!(saw_reading, "Must visit Reading state in 500 transitions");
        assert!(
            saw_scrolling,
            "Must visit Scrolling state in 500 transitions"
        );
    }

    #[test]
    fn activity_jitter_bounded() {
        for _ in 0..200 {
            let r = ActivityState::Reading.sample_jitter_ms();
            assert!(
                (200..=4000).contains(&r),
                "Reading jitter {} out of range",
                r
            );
            let s = ActivityState::Scrolling.sample_jitter_ms();
            assert!(
                (5..=120).contains(&s),
                "Scrolling jitter {} out of range",
                s
            );
        }
    }
}
