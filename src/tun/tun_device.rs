// src/tun/tun_device.rs
//! High-Performance TUN Device using tun-rs
//!
//! Cross-platform TUN device wrapper with async Tokio integration.
//! Supports dynamic MTU profiles for different network environments.
//! Includes an `AutoTuner` for ISP-aware MSS clamping based on
//! observed packet loss and retransmission metrics.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use tracing::{debug, info, warn};

// ============================================================================
// MTU Profiles
// ============================================================================

/// MTU Profile for different network environments.
///
/// - `Cellular`: Conservative MTU (1400) for mobile/cellular networks.
/// - `Standard`: Standard MTU (1500) for typical ethernet networks.
/// - `Jumbo`: Jumbo frames (9000) for high-performance LAN/Data Center.
/// - `Custom`: User-defined MTU value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum MtuProfile {
    /// 1400 MTU - Conservative for cellular/mobile networks
    #[default]
    Cellular,
    /// 1500 MTU - Standard ethernet MTU
    Standard,
    /// 9000 MTU - Jumbo frames for high-performance LAN/DC
    Jumbo,
    /// Custom MTU value
    Custom(u16),
}

impl MtuProfile {
    /// Get the raw MTU value for this profile
    pub fn mtu(&self) -> u16 {
        match self {
            MtuProfile::Cellular => 1400,
            MtuProfile::Standard => 1500,
            MtuProfile::Jumbo => 9000,
            MtuProfile::Custom(mtu) => *mtu,
        }
    }

    /// Calculate Maximum Segment Size (MSS) for IPv4.
    /// MSS = MTU - IP Header (20 bytes) - TCP Header (20 bytes)
    pub fn mss_ipv4(&self) -> u16 {
        self.mtu().saturating_sub(40)
    }

    /// Calculate Maximum Segment Size (MSS) for IPv6.
    /// MSS = MTU - IPv6 Header (40 bytes) - TCP Header (20 bytes)
    pub fn mss_ipv6(&self) -> u16 {
        self.mtu().saturating_sub(60)
    }

    /// Get the recommended buffer size for this MTU profile.
    /// Adds 64 bytes overhead for safety margin.
    pub fn buffer_size(&self) -> usize {
        self.mtu() as usize + 64
    }
}


impl From<u16> for MtuProfile {
    fn from(mtu: u16) -> Self {
        match mtu {
            1400 => MtuProfile::Cellular,
            1500 => MtuProfile::Standard,
            9000 => MtuProfile::Jumbo,
            other => MtuProfile::Custom(other),
        }
    }
}

// ============================================================================
// TUN Configuration
// ============================================================================

/// TUN device configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "tun0")
    pub name: String,
    /// IPv4 address for the TUN interface
    pub address: Ipv4Addr,
    /// IPv4 netmask (e.g., "255.255.255.0")
    pub netmask: Ipv4Addr,
    /// Optional IPv6 address
    pub address_v6: Option<Ipv6Addr>,
    /// IPv6 prefix length (e.g., 64)
    pub prefix_v6: u8,
    /// MTU profile for dynamic sizing
    pub mtu_profile: MtuProfile,
    /// Enable packet information header
    pub packet_info: bool,
    /// File descriptor for Android VPN Service (optional)
    #[cfg(target_os = "android")]
    pub fd: Option<i32>,
}

impl TunConfig {
    /// Create a new TunConfig with the specified MTU profile
    pub fn with_mtu_profile(profile: MtuProfile) -> Self {
        Self {
            mtu_profile: profile,
            ..Default::default()
        }
    }

    /// Get the MTU value from the profile
    pub fn mtu(&self) -> u16 {
        self.mtu_profile.mtu()
    }

    /// Get the MSS value for IPv4
    pub fn mss_ipv4(&self) -> u16 {
        self.mtu_profile.mss_ipv4()
    }

    /// Get the MSS value for IPv6
    pub fn mss_ipv6(&self) -> u16 {
        self.mtu_profile.mss_ipv6()
    }

    /// Get recommended buffer size
    pub fn buffer_size(&self) -> usize {
        self.mtu_profile.buffer_size()
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "rustray0".to_string(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            address_v6: Some("fd00::1".parse().unwrap()),
            prefix_v6: 64,
            mtu_profile: MtuProfile::Cellular, // Conservative for cellular networks
            packet_info: false,
            #[cfg(target_os = "android")]
            fd: None,
        }
    }
}

// ============================================================================
// TUN Device
// ============================================================================

/// High-performance TUN device wrapper using tun-rs
pub struct TunDevice {
    device: tun_rs::AsyncDevice,
    config: TunConfig,
}

impl TunDevice {
    /// Create a new TUN device with configuration
    pub async fn create(config: TunConfig) -> anyhow::Result<Self> {
        let mtu = config.mtu();
        info!(
            "Creating TUN device: {} (MTU: {}, Profile: {:?})",
            config.name, mtu, config.mtu_profile
        );

        #[cfg(target_os = "android")]
        let device = {
            use std::os::unix::io::FromRawFd;
            if let Some(fd) = config.fd {
                unsafe { tun_rs::AsyncDevice::from_raw_fd(fd) }
            } else {
                return Err(anyhow::anyhow!("Android TUN requires a file descriptor"));
            }
        };

        #[cfg(not(target_os = "android"))]
        let device = {
            let mut builder = tun_rs::DeviceBuilder::new()
                .ipv4(config.address, config.netmask, None)
                .mtu(mtu);

            #[cfg(target_os = "linux")]
            {
                builder = builder.name(&config.name);
            }

            #[cfg(target_os = "macos")]
            {
                builder = builder.name("utun");
            }

            // Add IPv6 if configured
            if let Some(v6) = config.address_v6 {
                builder = builder.ipv6(v6, config.prefix_v6);
            }

            builder.build_async()?
        };

        info!(
            "TUN device created: {} (IPv4: {}/{}, MSS-v4: {}, MSS-v6: {})",
            config.name,
            config.address,
            config.netmask,
            config.mss_ipv4(),
            config.mss_ipv6()
        );

        if let Some(v6) = config.address_v6 {
            info!("TUN device IPv6: {}/{}", v6, config.prefix_v6);
        }

        Ok(Self { device, config })
    }

    /// Read a raw IP packet from the TUN device using poll-based API
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.readable().await?;
        match self.device.try_recv(buf) {
            Ok(n) => {
                debug!("TUN: Received {} bytes", n);
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // False positive - try again
                Box::pin(self.recv(buf)).await
            }
            Err(e) => Err(e),
        }
    }

    /// Write a raw IP packet to the TUN device using poll-based API
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.writable().await?;
        match self.device.try_send(buf) {
            Ok(n) => {
                debug!("TUN: Sent {} bytes", n);
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // False positive - try again
                Box::pin(self.send(buf)).await
            }
            Err(e) => Err(e),
        }
    }

    /// Get the TUN device configuration
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Get device name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get MTU
    pub fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    /// Get MTU profile
    pub fn mtu_profile(&self) -> MtuProfile {
        self.config.mtu_profile
    }

    /// Get the underlying async device
    pub fn inner(&self) -> &tun_rs::AsyncDevice {
        &self.device
    }

    /// Consume and return the underlying async device
    pub fn into_inner(self) -> tun_rs::AsyncDevice {
        self.device
    }

    /// Update the MTU dynamically
    pub fn set_mtu(&mut self, mtu: u16) -> std::io::Result<()> {
        self.device.set_mtu(mtu)?;
        self.config.mtu_profile = MtuProfile::Custom(mtu);
        info!("Dynamically updated MTU to {}", mtu);
        Ok(())
    }

    /// Update the MTU profile dynamically
    pub fn update_mtu_profile(&mut self, profile: MtuProfile) -> std::io::Result<()> {
        let mtu = profile.mtu();
        self.set_mtu(mtu)?;
        self.config.mtu_profile = profile;
        info!("Dynamically updated MTU profile to {:?}", profile);
        Ok(())
    }
}

// ============================================================================
// TUN Reader/Writer
// ============================================================================

/// Wrapper for concurrent TUN read operations
pub struct TunReader {
    device: Arc<tun_rs::AsyncDevice>,
    mtu: Arc<AtomicU16>,
}

impl TunReader {
    pub fn new(device: Arc<tun_rs::AsyncDevice>, mtu: Arc<AtomicU16>) -> Self {
        Self { device, mtu }
    }

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.readable().await?;
        match self.device.try_recv(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Box::pin(self.recv(buf)).await,
            Err(e) => Err(e),
        }
    }

    pub fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }
}

/// Wrapper for concurrent TUN write operations
pub struct TunWriter {
    device: Arc<tun_rs::AsyncDevice>,
    mtu: Arc<AtomicU16>,
}

impl TunWriter {
    pub fn new(device: Arc<tun_rs::AsyncDevice>, mtu: Arc<AtomicU16>) -> Self {
        Self { device, mtu }
    }

    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.writable().await?;
        match self.device.try_send(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Box::pin(self.send(buf)).await,
            Err(e) => Err(e),
        }
    }

    pub fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }
}

/// Controller for updating TUN settings dynamically after splitting
pub struct TunControl {
    device: Arc<tun_rs::AsyncDevice>,
    mtu: Arc<AtomicU16>,
}

impl TunControl {
    pub fn new(device: Arc<tun_rs::AsyncDevice>, mtu: Arc<AtomicU16>) -> Self {
        Self { device, mtu }
    }

    pub fn set_mtu(&self, mtu: u16) -> std::io::Result<()> {
        self.device.set_mtu(mtu)?;
        self.mtu.store(mtu, Ordering::SeqCst);
        Ok(())
    }

    pub fn update_mtu_profile(&self, profile: MtuProfile) -> std::io::Result<()> {
        self.set_mtu(profile.mtu())
    }
}

/// Create reader/writer/control tuple from a TUN device
pub fn split_device(device: TunDevice) -> (TunReader, TunWriter, TunControl) {
    let mtu_val = device.mtu();
    let mtu = Arc::new(AtomicU16::new(mtu_val));
    let device = Arc::new(device.into_inner());
    (
        TunReader::new(device.clone(), mtu.clone()),
        TunWriter::new(device.clone(), mtu.clone()),
        TunControl::new(device, mtu),
    )
}

// ============================================================================
// ISP-Aware TUN Initialization
// ============================================================================

/// Wire together an `ISPProfileManager` result with `TunConfig`.
///
/// Called at startup once the user's carrier has been detected (via STUN
/// probes or cached GeoIP ASN).
pub fn apply_isp_params(config: &mut TunConfig, params: crate::config::EffectiveMtuMss) {
    config.mtu_profile = MtuProfile::Custom(params.mtu);
    info!(
        "ISP params applied: MTU={} MSS-v4={} MSS-v6={}",
        params.mtu, params.mss_ipv4, params.mss_ipv6
    );
}

// ============================================================================
// AutoTuner — Dynamic MTU/MSS Clamping
// ============================================================================

/// Threshold above which the AutoTuner considers the link throttled.
const LOSS_THRESHOLD_PERCENT: f64 = 10.0;

/// The defensive MSS value when ISP throttling is detected.
const CLAMPED_MSS: u16 = 1200;

/// Page size for aligned buffer allocations (4 KiB).
const PAGE_ALIGN: usize = 4096;

/// Dynamic MTU/MSS tuner that monitors packet loss and retransmission
/// metrics and automatically clamps MSS when the link appears throttled.
///
/// Works alongside `smoltcp` metrics: the TUN loop calls
/// [`AutoTuner::record_packet`] for each packet and
/// [`AutoTuner::record_retransmission`] for each retransmit event.
/// Periodically calling [`AutoTuner::evaluate`] checks whether the observed
/// loss ratio exceeds `LOSS_THRESHOLD_PERCENT` and, if so, clamps the MSS
/// to 1200 to reduce fragmentation on hostile ISP links.
#[derive(Debug)]
pub struct AutoTuner {
    /// Total packets transmitted in the current measurement window.
    total_packets: AtomicU64,
    /// Retransmissions / drops observed in the current window.
    retransmissions: AtomicU64,
    /// Whether MSS has been clamped due to high loss.
    is_clamped: std::sync::atomic::AtomicBool,
    /// Current effective MSS.
    effective_mss: AtomicU16,
    /// Original (un-clamped) MSS for restoration.
    original_mss: u16,
}

/// Snapshot of AutoTuner metrics.
#[derive(Debug, Clone, Copy)]
pub struct AutoTunerStats {
    pub total_packets: u64,
    pub retransmissions: u64,
    pub loss_percent: f64,
    pub is_clamped: bool,
    pub effective_mss: u16,
}

impl AutoTuner {
    /// Create a new AutoTuner with a baseline MSS.
    pub fn new(baseline_mss: u16) -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            retransmissions: AtomicU64::new(0),
            is_clamped: std::sync::atomic::AtomicBool::new(false),
            effective_mss: AtomicU16::new(baseline_mss),
            original_mss: baseline_mss,
        }
    }

    /// Record that a packet was sent.
    #[inline]
    pub fn record_packet(&self) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a retransmission / loss event occurred.
    #[inline]
    pub fn record_retransmission(&self) {
        self.retransmissions.fetch_add(1, Ordering::Relaxed);
    }

    /// Report multiple retransmissions at once (e.g. from a smoltcp poll cycle).
    #[inline]
    pub fn record_retransmissions(&self, count: u64) {
        self.retransmissions.fetch_add(count, Ordering::Relaxed);
    }

    /// Evaluate the current loss ratio and adjust MSS if necessary.
    ///
    /// Returns `true` if the MSS was just clamped (transition event),
    /// `false` if no change occurred.
    pub fn evaluate(&self) -> bool {
        let total = self.total_packets.load(Ordering::Relaxed);
        let retrans = self.retransmissions.load(Ordering::Relaxed);

        if total == 0 {
            return false;
        }

        let loss_pct = (retrans as f64 / total as f64) * 100.0;

        if loss_pct > LOSS_THRESHOLD_PERCENT && !self.is_clamped.load(Ordering::Relaxed) {
            warn!(
                "ISP Throttling detected: {:.1}% packet loss ({}/{} packets). Clamping MSS to {}",
                loss_pct, retrans, total, CLAMPED_MSS
            );
            self.effective_mss.store(CLAMPED_MSS, Ordering::SeqCst);
            self.is_clamped.store(true, Ordering::SeqCst);
            return true;
        }

        // If loss drops below threshold and we were clamped, restore.
        if loss_pct <= LOSS_THRESHOLD_PERCENT && self.is_clamped.load(Ordering::Relaxed) {
            info!(
                "Packet loss normalised ({:.1}%). Restoring MSS to {}",
                loss_pct, self.original_mss
            );
            self.effective_mss
                .store(self.original_mss, Ordering::SeqCst);
            self.is_clamped.store(false, Ordering::SeqCst);
        }

        false
    }

    /// Reset counters for the next measurement window.
    pub fn reset_window(&self) {
        self.total_packets.store(0, Ordering::Relaxed);
        self.retransmissions.store(0, Ordering::Relaxed);
    }

    /// Get the current effective MSS.
    #[inline]
    pub fn effective_mss(&self) -> u16 {
        self.effective_mss.load(Ordering::Relaxed)
    }

    /// Check whether MSS is currently clamped.
    #[inline]
    pub fn is_clamped(&self) -> bool {
        self.is_clamped.load(Ordering::Relaxed)
    }

    /// Return a snapshot of current metrics.
    pub fn stats(&self) -> AutoTunerStats {
        let total = self.total_packets.load(Ordering::Relaxed);
        let retrans = self.retransmissions.load(Ordering::Relaxed);
        let loss = if total > 0 {
            (retrans as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        AutoTunerStats {
            total_packets: total,
            retransmissions: retrans,
            loss_percent: loss,
            is_clamped: self.is_clamped.load(Ordering::Relaxed),
            effective_mss: self.effective_mss.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// 4KB-Aligned Buffer Allocation
// ============================================================================

/// Allocate a `Vec<u8>` of at least `size` bytes, rounded up to a 4 KiB
/// page boundary.
///
/// This uses a simple over-allocate strategy that is fully safe.
/// The resulting Vec will be page-size-rounded, though the allocator
/// may place it at an arbitrary alignment. For true DMA-level alignment,
/// pair with `memmap2` or a platform-specific allocator.
pub fn alloc_aligned_buffer(size: usize) -> Vec<u8> {
    // Round up to next page boundary.
    let aligned_size = (size + PAGE_ALIGN - 1) & !(PAGE_ALIGN - 1);
    vec![0u8; aligned_size]
}

/// Allocate a page-rounded buffer and log its alignment status.
pub fn alloc_page_aligned_buffer(size: usize) -> Vec<u8> {
    let buf = alloc_aligned_buffer(size);
    let addr = buf.as_ptr() as usize;
    if !addr.is_multiple_of(PAGE_ALIGN) {
        debug!(
            "Buffer at {:#x} not page-aligned (offset {}). \
             Performance may be sub-optimal on DMA paths.",
            addr,
            addr % PAGE_ALIGN
        );
    } else {
        debug!(
            "Allocated page-aligned buffer at {:#x} ({} bytes)",
            addr,
            buf.len()
        );
    }
    buf
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtu_profile_values() {
        assert_eq!(MtuProfile::Cellular.mtu(), 1400);
        assert_eq!(MtuProfile::Standard.mtu(), 1500);
        assert_eq!(MtuProfile::Jumbo.mtu(), 9000);
        assert_eq!(MtuProfile::Custom(2000).mtu(), 2000);
    }

    #[test]
    fn test_mss_calculation() {
        // IPv4: MTU - 40 (20 IP + 20 TCP)
        assert_eq!(MtuProfile::Cellular.mss_ipv4(), 1360);
        assert_eq!(MtuProfile::Standard.mss_ipv4(), 1460);
        assert_eq!(MtuProfile::Jumbo.mss_ipv4(), 8960);

        // IPv6: MTU - 60 (40 IP + 20 TCP)
        assert_eq!(MtuProfile::Cellular.mss_ipv6(), 1340);
        assert_eq!(MtuProfile::Standard.mss_ipv6(), 1440);
        assert_eq!(MtuProfile::Jumbo.mss_ipv6(), 8940);
    }

    #[test]
    fn test_buffer_size() {
        assert_eq!(MtuProfile::Cellular.buffer_size(), 1464);
        assert_eq!(MtuProfile::Standard.buffer_size(), 1564);
        assert_eq!(MtuProfile::Jumbo.buffer_size(), 9064);
    }

    #[test]
    fn test_mtu_profile_from_u16() {
        assert_eq!(MtuProfile::from(1400), MtuProfile::Cellular);
        assert_eq!(MtuProfile::from(1500), MtuProfile::Standard);
        assert_eq!(MtuProfile::from(9000), MtuProfile::Jumbo);
        assert_eq!(MtuProfile::from(2000), MtuProfile::Custom(2000));
    }

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.mtu(), 1400); // Cellular-optimized
        assert!(config.address_v6.is_some()); // Dual-stack
        assert_eq!(config.mtu_profile, MtuProfile::Cellular);
    }

    #[test]
    fn test_tun_config_with_jumbo() {
        let config = TunConfig::with_mtu_profile(MtuProfile::Jumbo);
        assert_eq!(config.mtu(), 9000);
        assert_eq!(config.mss_ipv4(), 8960);
        assert_eq!(config.mss_ipv6(), 8940);
        assert_eq!(config.buffer_size(), 9064);
    }

    // ── AutoTuner Tests ──

    #[test]
    fn test_autotuner_no_packets_no_clamp() {
        let tuner = AutoTuner::new(1360);
        assert!(!tuner.evaluate());
        assert!(!tuner.is_clamped());
        assert_eq!(tuner.effective_mss(), 1360);
    }

    #[test]
    fn test_autotuner_low_loss_no_clamp() {
        let tuner = AutoTuner::new(1360);
        // 5% loss → should NOT clamp
        for _ in 0..100 {
            tuner.record_packet();
        }
        for _ in 0..5 {
            tuner.record_retransmission();
        }
        assert!(!tuner.evaluate());
        assert!(!tuner.is_clamped());
        assert_eq!(tuner.effective_mss(), 1360);
    }

    #[test]
    fn test_autotuner_high_loss_clamps() {
        let tuner = AutoTuner::new(1360);
        // 15% loss → SHOULD clamp
        for _ in 0..100 {
            tuner.record_packet();
        }
        for _ in 0..15 {
            tuner.record_retransmission();
        }
        assert!(tuner.evaluate()); // Returns true on transition
        assert!(tuner.is_clamped());
        assert_eq!(tuner.effective_mss(), CLAMPED_MSS);
    }

    #[test]
    fn test_autotuner_restores_after_improvement() {
        let tuner = AutoTuner::new(1360);
        // First: high loss → clamp
        for _ in 0..100 {
            tuner.record_packet();
        }
        tuner.record_retransmissions(15);
        tuner.evaluate();
        assert!(tuner.is_clamped());

        // Reset window and report low loss → should restore
        tuner.reset_window();
        for _ in 0..100 {
            tuner.record_packet();
        }
        tuner.record_retransmissions(2);
        tuner.evaluate();
        assert!(!tuner.is_clamped());
        assert_eq!(tuner.effective_mss(), 1360);
    }

    #[test]
    fn test_autotuner_stats_snapshot() {
        let tuner = AutoTuner::new(1460);
        for _ in 0..200 {
            tuner.record_packet();
        }
        tuner.record_retransmissions(30);
        let stats = tuner.stats();
        assert_eq!(stats.total_packets, 200);
        assert_eq!(stats.retransmissions, 30);
        assert!((stats.loss_percent - 15.0).abs() < 0.01);
    }

    #[test]
    fn test_autotuner_window_reset() {
        let tuner = AutoTuner::new(1360);
        for _ in 0..50 {
            tuner.record_packet();
        }
        tuner.record_retransmissions(10);
        tuner.reset_window();
        let stats = tuner.stats();
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.retransmissions, 0);
    }

    // ── Aligned Buffer Tests ──

    #[test]
    fn test_alloc_aligned_buffer_size() {
        let buf = alloc_aligned_buffer(1500);
        // Should be rounded up to 4096
        assert_eq!(buf.len(), PAGE_ALIGN);
    }

    #[test]
    fn test_alloc_aligned_buffer_exact_page() {
        let buf = alloc_aligned_buffer(4096);
        assert_eq!(buf.len(), 4096);
    }

    #[test]
    fn test_alloc_aligned_buffer_larger_than_page() {
        let buf = alloc_aligned_buffer(5000);
        assert_eq!(buf.len(), 8192); // Rounded up to 2 pages
    }
}
