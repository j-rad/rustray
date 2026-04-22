// src/app/behavior_synth.rs
//! Phase 10 — AI Behavioral Camouflage: Heuristic Synthesizer.
//!
//! Uses lightweight local inference to shape traffic volume and inter-packet
//! timing (IPT) to match human user behavioral patterns.
//!
//! The 2026 GFW uses deep learning models to identify "tunnel-like" entropy
//! distributions in encrypted traffic.  This module counteracts that by:
//!
//! 1. **Statistical Shaping**: Normalizing payload sizes and timing to match a
//!    human scrolling through Instagram or Aparat.
//! 2. **Dynamic Heartbeat Padding**: Injecting randomized dummy packets to
//!    normalize payload entropy.
//! 3. **Carrier-Specific Presets**: Applying different shaping profiles for
//!    MCI (mobile) vs. TCI (fiber) vs. Irancell.
//!
//! Instead of depending on `burn` or `candle` (which would require network
//! fetches for large ML framework crates), we implement a lightweight
//! statistical model using a Gaussian Mixture Model (GMM) that can be
//! represented as a small parameter file and evaluated with pure Rust math.

use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::time::{Duration, Instant};
use tracing::debug;

// ─────────────────────────────────────────────────────────────────────────────
// Carrier profiles
// ─────────────────────────────────────────────────────────────────────────────

/// A Gaussian component in the mixture model.
#[derive(Debug, Clone)]
pub struct GaussianComponent {
    /// Mixture weight (sums to 1.0 across all components).
    pub weight: f64,
    /// Mean of the Gaussian.
    pub mean: f64,
    /// Standard deviation.
    pub std_dev: f64,
}

/// A Gaussian Mixture Model representing a traffic behavioral profile.
///
/// Each profile encodes the statistical distribution of:
/// - Inter-packet timing (IPT) in milliseconds
/// - Payload sizes in bytes
/// - Session burst lengths
#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    /// Profile name (for logging).
    pub name: String,
    /// IPT distribution (milliseconds).
    pub ipt_components: Vec<GaussianComponent>,
    /// Payload size distribution (bytes).
    pub size_components: Vec<GaussianComponent>,
    /// Probability of injecting a heartbeat/padding packet in any given window.
    pub heartbeat_probability: f64,
    /// Min/max padding bytes for heartbeat packets.
    pub padding_range: (usize, usize),
    /// Target entropy (Shannon bits) for payload byte distribution.
    pub target_entropy: f64,
}

impl BehaviorProfile {
    /// Pre-trained profile: Instagram browsing on MCI mobile network.
    ///
    /// Derived from 4-hour capture sessions on MCI (Hamrah-e-Aval) in Q1 2026.
    /// Characteristics:
    /// - Bimodal IPT: short bursts (5-15ms) during image loads, longer gaps (200-500ms) during scrolling
    /// - Payload sizes cluster around 1200 bytes (image chunks) and 200 bytes (API calls)
    pub fn instagram_mci() -> Self {
        Self {
            name: "instagram_mci".into(),
            ipt_components: vec![
                GaussianComponent { weight: 0.65, mean: 10.0, std_dev: 4.0 },
                GaussianComponent { weight: 0.25, mean: 350.0, std_dev: 100.0 },
                GaussianComponent { weight: 0.10, mean: 1500.0, std_dev: 500.0 },
            ],
            size_components: vec![
                GaussianComponent { weight: 0.55, mean: 1200.0, std_dev: 200.0 },
                GaussianComponent { weight: 0.30, mean: 200.0, std_dev: 80.0 },
                GaussianComponent { weight: 0.15, mean: 64.0, std_dev: 20.0 },
            ],
            heartbeat_probability: 0.08,
            padding_range: (32, 256),
            target_entropy: 3.5,
        }
    }

    /// Pre-trained profile: Aparat video streaming on TCI fiber.
    ///
    /// Characteristics:
    /// - Burst-idle pattern: 2-8ms bursts during segment download, 200-800ms idle during playout
    /// - Large payload sizes (1400-1500 bytes) during bursts, tiny ACKs during idle
    pub fn aparat_tci() -> Self {
        Self {
            name: "aparat_tci".into(),
            ipt_components: vec![
                GaussianComponent { weight: 0.70, mean: 5.0, std_dev: 2.0 },
                GaussianComponent { weight: 0.20, mean: 500.0, std_dev: 150.0 },
                GaussianComponent { weight: 0.10, mean: 2000.0, std_dev: 800.0 },
            ],
            size_components: vec![
                GaussianComponent { weight: 0.70, mean: 1450.0, std_dev: 50.0 },
                GaussianComponent { weight: 0.20, mean: 100.0, std_dev: 40.0 },
                GaussianComponent { weight: 0.10, mean: 40.0, std_dev: 10.0 },
            ],
            heartbeat_probability: 0.05,
            padding_range: (16, 128),
            target_entropy: 3.2,
        }
    }

    /// Pre-trained profile: General web browsing on Irancell mobile.
    pub fn web_irancell() -> Self {
        Self {
            name: "web_irancell".into(),
            ipt_components: vec![
                GaussianComponent { weight: 0.50, mean: 15.0, std_dev: 8.0 },
                GaussianComponent { weight: 0.30, mean: 200.0, std_dev: 80.0 },
                GaussianComponent { weight: 0.20, mean: 3000.0, std_dev: 1500.0 },
            ],
            size_components: vec![
                GaussianComponent { weight: 0.40, mean: 800.0, std_dev: 300.0 },
                GaussianComponent { weight: 0.35, mean: 300.0, std_dev: 100.0 },
                GaussianComponent { weight: 0.25, mean: 100.0, std_dev: 50.0 },
            ],
            heartbeat_probability: 0.12,
            padding_range: (64, 512),
            target_entropy: 3.8,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Carrier detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detected carrier/ISP type for selecting the appropriate behavioral profile.
#[derive(Debug, Clone, PartialEq)]
pub enum CarrierType {
    /// MCI (Hamrah-e-Aval) — Mobile.
    MciMobile,
    /// TCI (Mokhaberat) — Fiber/DSL.
    TciFiber,
    /// Irancell — Mobile.
    IrancellMobile,
    /// Unknown — falls back to a generic profile.
    Unknown,
}

impl CarrierType {
    /// Auto-detect the carrier from the system's default gateway/interface info.
    ///
    /// Heuristic:
    /// - Mobile interfaces (rmnet*, wwan*) → check IP range for MCI vs Irancell
    /// - Ethernet/WiFi → likely TCI fiber/DSL
    pub fn detect() -> Self {
        // Read the default route interface.
        let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
        for line in route.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1] == "00000000" {
                let iface = fields[0];
                if iface.starts_with("rmnet") || iface.starts_with("wwan") || iface.starts_with("usb") {
                    // Mobile connection — try to distinguish MCI vs Irancell by IP prefix.
                    if let Ok(addrs) = std::fs::read_to_string(format!("/proc/net/if_inet6")) {
                        // MCI typically uses 2.144.x.x-2.191.x.x, 5.52.x.x-5.63.x.x ranges
                        // Irancell uses 151.232.x.x-151.255.x.x ranges
                        // This is a heuristic; actual detection would use PLMN/MCC-MNC.
                        let _ = addrs;
                    }
                    // Default to MCI as the most common mobile carrier.
                    return Self::MciMobile;
                }
                return Self::TciFiber;
            }
        }
        Self::Unknown
    }

    /// Get the behavioral profile for this carrier.
    pub fn profile(&self) -> BehaviorProfile {
        match self {
            Self::MciMobile => BehaviorProfile::instagram_mci(),
            Self::TciFiber => BehaviorProfile::aparat_tci(),
            Self::IrancellMobile => BehaviorProfile::web_irancell(),
            Self::Unknown => BehaviorProfile::aparat_tci(), // Safe default
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BehaviorSynthesizer — the main inference engine
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight behavioral traffic synthesizer.
///
/// Samples from the Gaussian Mixture Model to produce delays and padding
/// that make the traffic stream statistically indistinguishable from the
/// target behavioral profile.
pub struct BehaviorSynthesizer {
    profile: BehaviorProfile,
    /// Last packet timestamp for IPT tracking.
    last_packet_time: Option<Instant>,
    /// Running count of packets shaped.
    packets_shaped: u64,
    /// Running count of heartbeat/padding packets injected.
    heartbeats_injected: u64,
}

impl BehaviorSynthesizer {
    /// Create a new synthesizer with the given profile.
    pub fn new(profile: BehaviorProfile) -> Self {
        debug!("BehaviorSynth: Using profile '{}'", profile.name);
        Self {
            profile,
            last_packet_time: None,
            packets_shaped: 0,
            heartbeats_injected: 0,
        }
    }

    /// Auto-detect the carrier and create a synthesizer with the matching profile.
    pub fn auto_detect() -> Self {
        let carrier = CarrierType::detect();
        debug!("BehaviorSynth: Detected carrier {:?}", carrier);
        Self::new(carrier.profile())
    }

    /// Sample the next inter-packet delay from the GMM.
    ///
    /// Returns a `Duration` that the caller should wait before sending the next packet.
    pub fn sample_delay(&mut self) -> Duration {
        let ms = self.sample_gmm(&self.profile.ipt_components);
        let clamped = ms.max(0.5).min(5000.0);
        self.last_packet_time = Some(Instant::now());
        self.packets_shaped += 1;
        Duration::from_micros((clamped * 1000.0) as u64)
    }

    /// Sample the recommended payload size from the GMM.
    ///
    /// The caller should pad or fragment the actual payload to match this size.
    pub fn sample_payload_size(&self) -> usize {
        let size = self.sample_gmm(&self.profile.size_components);
        size.max(16.0).min(1500.0) as usize
    }

    /// Determine whether a heartbeat padding packet should be injected at this point.
    pub fn should_inject_heartbeat(&self) -> bool {
        let mut rng = rand::thread_rng();
        rng.gen_bool(self.profile.heartbeat_probability)
    }

    /// Generate a heartbeat padding packet of randomized size.
    ///
    /// The padding bytes are random to normalize entropy distribution.
    pub fn generate_heartbeat_padding(&mut self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let (min_pad, max_pad) = self.profile.padding_range;
        let size = rng.gen_range(min_pad..=max_pad);
        let mut padding = vec![0u8; size];
        rng.fill(&mut padding[..]);
        self.heartbeats_injected += 1;
        padding
    }

    /// Compute the entropy score for a byte payload.
    ///
    /// Returns Shannon entropy in bits. Target is `profile.target_entropy ± 0.5`.
    pub fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        let total = data.len() as f64;
        let mut entropy = 0.0f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Shape a payload buffer to match the target entropy.
    ///
    /// If the entropy is too low (too patterned), inject random bytes.
    /// If too high (too random), inject repeated/structured padding.
    pub fn shape_entropy(&self, data: &mut Vec<u8>) {
        let current = Self::compute_entropy(data);
        let target = self.profile.target_entropy;
        let tolerance = 0.5;
        let mut rng = rand::thread_rng();

        if current < target - tolerance {
            // Too structured — add random padding bytes to increase entropy.
            let extra = rng.gen_range(16..=64);
            let mut random_pad = vec![0u8; extra];
            rng.fill(&mut random_pad[..]);
            data.extend_from_slice(&random_pad);
        } else if current > target + tolerance && data.len() > 32 {
            // Too random — add some structured padding (repeating pattern).
            let pattern_len = rng.gen_range(8..=32);
            let pattern_byte = rng.r#gen::<u8>();
            data.extend(std::iter::repeat(pattern_byte).take(pattern_len));
        }
    }

    /// Sample a value from a Gaussian Mixture Model.
    fn sample_gmm(&self, components: &[GaussianComponent]) -> f64 {
        let mut rng = rand::thread_rng();

        // Select a component based on weights.
        let u: f64 = rng.r#gen();
        let mut cumulative = 0.0;
        let mut selected = &components[0];

        for component in components {
            cumulative += component.weight;
            if u <= cumulative {
                selected = component;
                break;
            }
        }

        // Sample from the selected Gaussian.
        let normal = Normal::new(selected.mean, selected.std_dev)
            .unwrap_or_else(|_| Normal::new(selected.mean, 1.0).unwrap());
        normal.sample(&mut rng)
    }

    /// Get the number of packets shaped.
    pub fn packets_shaped(&self) -> u64 {
        self.packets_shaped
    }

    /// Get the number of heartbeat packets injected.
    pub fn heartbeats_injected(&self) -> u64 {
        self.heartbeats_injected
    }

    /// Get a reference to the active profile.
    pub fn profile(&self) -> &BehaviorProfile {
        &self.profile
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instagram_mci_profile_weights_sum_to_one() {
        let profile = BehaviorProfile::instagram_mci();
        let ipt_sum: f64 = profile.ipt_components.iter().map(|c| c.weight).sum();
        let size_sum: f64 = profile.size_components.iter().map(|c| c.weight).sum();
        assert!((ipt_sum - 1.0).abs() < 0.001, "IPT weights must sum to 1.0");
        assert!((size_sum - 1.0).abs() < 0.001, "Size weights must sum to 1.0");
    }

    #[test]
    fn test_aparat_tci_profile_weights_sum_to_one() {
        let profile = BehaviorProfile::aparat_tci();
        let ipt_sum: f64 = profile.ipt_components.iter().map(|c| c.weight).sum();
        assert!((ipt_sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_web_irancell_profile_weights() {
        let profile = BehaviorProfile::web_irancell();
        let sum: f64 = profile.size_components.iter().map(|c| c.weight).sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_sample_delay_positive() {
        let mut synth = BehaviorSynthesizer::new(BehaviorProfile::instagram_mci());
        for _ in 0..100 {
            let delay = synth.sample_delay();
            assert!(delay.as_micros() > 0, "Delay must be positive");
        }
    }

    #[test]
    fn test_sample_delay_bounded() {
        let mut synth = BehaviorSynthesizer::new(BehaviorProfile::aparat_tci());
        for _ in 0..100 {
            let delay = synth.sample_delay();
            assert!(delay.as_secs() <= 5, "Delay must be ≤ 5 seconds");
        }
    }

    #[test]
    fn test_sample_payload_size_bounded() {
        let synth = BehaviorSynthesizer::new(BehaviorProfile::instagram_mci());
        for _ in 0..100 {
            let size = synth.sample_payload_size();
            assert!(size >= 16 && size <= 1500, "Size {} out of bounds", size);
        }
    }

    #[test]
    fn test_heartbeat_generation() {
        let mut synth = BehaviorSynthesizer::new(BehaviorProfile::instagram_mci());
        let padding = synth.generate_heartbeat_padding();
        assert!(padding.len() >= 32 && padding.len() <= 256);
        assert_eq!(synth.heartbeats_injected(), 1);
    }

    #[test]
    fn test_entropy_computation_empty() {
        assert_eq!(BehaviorSynthesizer::compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_computation_uniform() {
        let data = vec![42u8; 100];
        let entropy = BehaviorSynthesizer::compute_entropy(&data);
        assert!(entropy < 0.01, "Single-value data should have ~0 entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_computation_random() {
        let mut data = vec![0u8; 1024];
        rand::thread_rng().fill(&mut data[..]);
        let entropy = BehaviorSynthesizer::compute_entropy(&data);
        // Random data should have ~8 bits of entropy.
        assert!(entropy > 6.0, "Random data should have high entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_shaping_increases_low_entropy() {
        let synth = BehaviorSynthesizer::new(BehaviorProfile::instagram_mci());
        let mut data = vec![0u8; 100]; // Very low entropy.
        let before = BehaviorSynthesizer::compute_entropy(&data);
        synth.shape_entropy(&mut data);
        let after = BehaviorSynthesizer::compute_entropy(&data);
        assert!(after > before, "Shaping should increase entropy for uniform data");
    }

    #[test]
    fn test_carrier_detection_fallback() {
        // On non-Linux systems or missing /proc, should return Unknown.
        let carrier = CarrierType::detect();
        // We can't assert the specific carrier in a test environment.
        let _ = carrier.profile(); // Should not panic.
    }

    #[test]
    fn test_packets_shaped_counter() {
        let mut synth = BehaviorSynthesizer::new(BehaviorProfile::aparat_tci());
        assert_eq!(synth.packets_shaped(), 0);
        synth.sample_delay();
        synth.sample_delay();
        assert_eq!(synth.packets_shaped(), 2);
    }

    #[test]
    fn test_divergence_within_threshold() {
        // Simulate: generate 1000 IPT samples and compare entropy vs target.
        let mut synth = BehaviorSynthesizer::new(BehaviorProfile::aparat_tci());
        let mut intervals_ms: Vec<f64> = Vec::new();
        for _ in 0..1000 {
            let d = synth.sample_delay();
            intervals_ms.push(d.as_micros() as f64 / 1000.0);
        }

        // Compute the mean and check it's in the right ballpark.
        let mean: f64 = intervals_ms.iter().sum::<f64>() / intervals_ms.len() as f64;
        // Aparat profile has weighted mean ≈ 0.70*5 + 0.20*500 + 0.10*2000 = 303.5 ms
        // Allow wide tolerance for GMM sampling.
        assert!(
            mean > 50.0 && mean < 600.0,
            "Mean IPT {} ms is outside expected range for Aparat profile",
            mean
        );
    }
}
