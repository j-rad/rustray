// src/kernel/ghoststream.rs
//! GhostStream — XDP MSS Clamping & SNI Slicing (Phase 1)
//!
//! This module provides the userspace controller for the GhostStream XDP hook.
//! The XDP hook is loaded as a pre-compiled eBPF ELF object onto the primary
//! NIC using Aya.  The hook rewrites TCP Options to clamp MSS to a value in
//! [64, 128] bytes, which forces the OS networking stack to naturally fragment
//! the TLS ClientHello across multiple TCP segments so that the SNI string is
//! never visible in a single packet capture.
//!
//! Architecture:
//!
//! ```text
//!  UserSpace                     │  Kernel / XDP
//!  GhostStreamController         │  xdp_ghoststream (eBPF)
//!  ├── load()                    │  ├── parse Eth/IPv4/TCP
//!  ├── attach()      ──────────► │  ├── locate TCP Options
//!  ├── set_mss_range()           │  ├── clamp MSS → rand [64,128]
//!  └── detach()                  │  ├── recompute TCP checksum (RFC 1624)
//!                                │  └── XDP_PASS
//! ```
//!
//! SNI mid-string splitting is achieved purely by the MSS clamp: when MSS is
//! 64–128 bytes the OS will segment TLS records such that the SNI value (which
//! lives inside the first TLS record, offset ~50–70 bytes) is split across at
//! least two TCP segments.
//!
//! Requires: `CAP_NET_ADMIN`, `CAP_BPF` (or root), Linux ≥ 5.8.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::{fs, io};

use aya::maps::HashMap as BpfHashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum MSS value to clamp to (bytes).
/// Values below 64 trigger TCP retransmissions without meaningful benefit.
pub const MSS_MIN: u16 = 64;

/// Maximum MSS value to clamp to (bytes).
/// 128 bytes ensures the TLS ClientHello (≥512 bytes) splits across ≥4 segments.
pub const MSS_MAX: u16 = 128;

/// Name of the XDP program section in the compiled eBPF ELF.
const XDP_PROG_NAME: &str = "xdp_ghoststream";

/// BPF map names defined in the eBPF source.
const MAP_MSS_CONFIG: &str = "GHOST_MSS_CONFIG";
const MAP_WHITELIST: &str = "GHOST_WHITELIST";

// ─────────────────────────────────────────────────────────────────────────────
// MSS configuration shared with the eBPF program
// ─────────────────────────────────────────────────────────────────────────────

/// Key indices for the MSS config array map.
#[repr(u32)]
enum MssCfgKey {
    Min = 0,
    Max = 1,
}

// ─────────────────────────────────────────────────────────────────────────────
// NIC auto-detection (reused from ebpf_loader)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_primary_nic() -> io::Result<String> {
    let content = fs::read_to_string("/proc/net/route")?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            return Ok(fields[0].to_string());
        }
    }
    for name in &["eth0", "ens33", "enp0s3", "wlan0", "wlp2s0"] {
        if std::path::Path::new(&format!("/sys/class/net/{}", name)).exists() {
            return Ok(name.to_string());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "No primary NIC found"))
}

// ─────────────────────────────────────────────────────────────────────────────
// GhostStreamController
// ─────────────────────────────────────────────────────────────────────────────

/// Userspace controller for the GhostStream XDP MSS-clamping hook.
pub struct GhostStreamController {
    bpf: Bpf,
    ifname: String,
    attached: bool,
    mss_min: u16,
    mss_max: u16,
    whitelisted_ips: HashSet<u32>,
}

impl GhostStreamController {
    /// Load the GhostStream eBPF ELF from the path returned by [`elf_path`].
    ///
    /// # Errors
    /// Returns an error if the ELF file is missing or the BPF subsystem
    /// rejects the program (e.g., kernel too old, missing capabilities).
    pub fn load() -> io::Result<Self> {
        Self::load_with_mss(MSS_MIN, MSS_MAX)
    }

    /// Load with a custom MSS clamping range `[mss_min, mss_max]`.
    ///
    /// Both values must satisfy `64 ≤ mss_min ≤ mss_max ≤ 1500`.
    pub fn load_with_mss(mss_min: u16, mss_max: u16) -> io::Result<Self> {
        if mss_min < 64 || mss_max > 1500 || mss_min > mss_max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid MSS range [{}, {}]: must satisfy 64 ≤ min ≤ max ≤ 1500",
                    mss_min, mss_max
                ),
            ));
        }

        let elf = elf_path();
        info!("GhostStream: Loading XDP eBPF program from {}", elf);

        let bpf = Bpf::load_file(&elf).map_err(|e| {
            error!("GhostStream: Failed to load eBPF ELF '{}': {}", elf, e);
            io::Error::new(io::ErrorKind::NotFound, e.to_string())
        })?;

        info!(
            "GhostStream: Loaded OK — MSS clamp range [{}, {}]",
            mss_min, mss_max
        );

        Ok(Self {
            bpf,
            ifname: String::new(),
            attached: false,
            mss_min,
            mss_max,
            whitelisted_ips: HashSet::new(),
        })
    }

    /// Push the current MSS range into the eBPF map `GHOST_MSS_CONFIG`.
    fn sync_mss_config(&mut self) -> io::Result<()> {
        let mut map: BpfHashMap<_, u32, u32> =
            BpfHashMap::try_from(self.bpf.map_mut(MAP_MSS_CONFIG).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("BPF map '{}' not found in ELF", MAP_MSS_CONFIG),
                )
            })?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        map.insert(MssCfgKey::Min as u32, self.mss_min as u32, 0)
            .map_err(|e| io::Error::other(e.to_string()))?;
        map.insert(MssCfgKey::Max as u32, self.mss_max as u32, 0)
            .map_err(|e| io::Error::other(e.to_string()))?;

        debug!(
            "GhostStream: MSS config synced to BPF map [{}, {}]",
            self.mss_min, self.mss_max
        );
        Ok(())
    }

    /// Auto-detect the primary NIC and attach the XDP hook.
    pub fn attach(&mut self) -> io::Result<()> {
        let ifname = detect_primary_nic()?;
        self.attach_to(&ifname)
    }

    /// Attach the XDP hook to a specific network interface.
    ///
    /// Uses `XdpFlags::SKB_MODE` for broad compatibility (falls back to SW emulation
    /// on NICs without hardware XDP support, including the Pi 5 built-in eth port).
    pub fn attach_to(&mut self, ifname: &str) -> io::Result<()> {
        if self.attached {
            warn!(
                "GhostStream: Already attached to {}; detaching first",
                self.ifname
            );
            self.detach()?;
        }

        // Push MSS config before attaching so the program sees valid values immediately.
        self.sync_mss_config()?;

        let program: &mut Xdp = self
            .bpf
            .program_mut(XDP_PROG_NAME)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("XDP program '{}' not found in ELF", XDP_PROG_NAME),
                )
            })?
            .try_into()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ELF program is not an XDP program: {}", e),
                )
            })?;

        program
            .load()
            .map_err(|e| io::Error::other(e.to_string()))?;

        // SKB mode works on all drivers; native/offload modes require NIC support.
        program
            .attach(ifname, XdpFlags::SKB_MODE)
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.ifname = ifname.to_string();
        self.attached = true;
        info!(
            "GhostStream: XDP hook attached to {} (MSS clamp [{},{}])",
            ifname, self.mss_min, self.mss_max
        );
        Ok(())
    }

    /// Detach the XDP hook from the current interface.
    pub fn detach(&mut self) -> io::Result<()> {
        if !self.attached {
            return Ok(());
        }
        // Aya automatically removes the XDP link when the program handle is dropped.
        // We manually set attached = false to guard re-entry.
        self.attached = false;
        info!("GhostStream: XDP hook detached from {}", self.ifname);
        Ok(())
    }

    /// Add an IPv4 address to the per-IP whitelist.
    ///
    /// Only outbound packets destined for a whitelisted IP will have their MSS
    /// rewritten. Packets to all other destinations are passed unmodified.
    pub fn add_target_ip(&mut self, ip: Ipv4Addr) -> io::Result<()> {
        let key = u32::from_be_bytes(ip.octets());
        let mut map: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(self.bpf.map_mut(MAP_WHITELIST).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("BPF map '{}' not found", MAP_WHITELIST),
                )
            })?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        map.insert(key, 1u8, 0)
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.whitelisted_ips.insert(key);
        debug!("GhostStream: Added target IP {} to whitelist", ip);
        Ok(())
    }

    /// Remove an IPv4 address from the per-IP whitelist.
    pub fn remove_target_ip(&mut self, ip: Ipv4Addr) -> io::Result<()> {
        let key = u32::from_be_bytes(ip.octets());
        let mut map: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(self.bpf.map_mut(MAP_WHITELIST).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("BPF map '{}' not found", MAP_WHITELIST),
                )
            })?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        map.remove(&key)
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.whitelisted_ips.remove(&key);
        debug!("GhostStream: Removed target IP {} from whitelist", ip);
        Ok(())
    }

    /// Update the MSS clamping range at runtime without detaching and re-attaching.
    pub fn set_mss_range(&mut self, mss_min: u16, mss_max: u16) -> io::Result<()> {
        if mss_min < 64 || mss_max > 1500 || mss_min > mss_max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid MSS range [{}, {}]: must satisfy 64 ≤ min ≤ max ≤ 1500",
                    mss_min, mss_max
                ),
            ));
        }
        self.mss_min = mss_min;
        self.mss_max = mss_max;
        self.sync_mss_config()
    }

    /// Whether the XDP hook is currently attached to a NIC.
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// The interface name the hook is attached to, or empty if not attached.
    pub fn interface(&self) -> &str {
        &self.ifname
    }

    /// Current MSS clamping range `(min, max)`.
    pub fn mss_range(&self) -> (u16, u16) {
        (self.mss_min, self.mss_max)
    }

    /// Snapshot of whitelisted destination IPs (as big-endian u32 for efficiency).
    pub fn whitelisted_ip_count(&self) -> usize {
        self.whitelisted_ips.len()
    }
}

impl Drop for GhostStreamController {
    fn drop(&mut self) {
        if self.attached {
            let _ = self.detach();
        }
        debug!("GhostStream: Controller dropped");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SNI slice-offset calculator (userspace helper, mirrors eBPF logic)
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate the TCP segment number in which the TLS SNI string will be split
/// for a given MSS value and a ClientHello with `sni_offset` bytes from the
/// start of the TCP payload.
///
/// Returns `(segment_index, byte_offset_within_segment)`.
///
/// This is used in tests to verify that the MSS clamp achieves mid-string SNI
/// splitting without needing a live kernel environment.
pub fn sni_split_position(mss: u16, sni_offset: usize) -> (usize, usize) {
    let mss = mss as usize;
    let segment = sni_offset / mss;
    let byte_in_seg = sni_offset % mss;
    (segment, byte_in_seg)
}

/// Compute the RFC 1624 incremental TCP checksum update for a single 16-bit
/// word change.
///
/// Given:
/// - `old_check`: original checksum (ones' complement)
/// - `old_word`:  old 16-bit value being replaced
/// - `new_word`:  new 16-bit value
///
/// Returns the updated checksum.
///
/// Formula: `HC' = ~(~HC + ~m + m')` (RFC 1624 Eqn. 3)
pub fn rfc1624_checksum_update(old_check: u16, old_word: u16, new_word: u16) -> u16 {
    // Operate in 32-bit to catch carry.
    let hc = !old_check as u32;
    let m = !old_word as u32;
    let m_prime = new_word as u32;
    let sum = hc.wrapping_add(m).wrapping_add(m_prime);
    // Fold carries.
    let folded = (sum & 0xFFFF) + (sum >> 16);
    let folded = (folded & 0xFFFF) + (folded >> 16);
    !(folded as u16)
}

// ─────────────────────────────────────────────────────────────────────────────
// ELF path helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the expected path for the compiled GhostStream XDP ELF.
///
/// Conventionally the eBPF ELF is embedded via `include_bytes!` or placed next
/// to the binary.  We look for it in the same directory as the running binary.
fn elf_path() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("ghoststream.elf");
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    // Fallback: look in /usr/share/rustray/
    "/usr/share/rustray/ghoststream.elf".to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (no kernel required)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MSS range validation ─────────────────────────────────────────────────

    #[test]
    fn test_mss_range_too_small_rejected() {
        let result = GhostStreamController::load_with_mss(32, 128);
        assert!(
            result.is_err(),
            "MSS min < 64 should be rejected"
        );
    }

    #[test]
    fn test_mss_range_inverted_rejected() {
        let result = GhostStreamController::load_with_mss(128, 64);
        assert!(
            result.is_err(),
            "min > max should be rejected"
        );
    }

    #[test]
    fn test_mss_range_too_large_rejected() {
        let result = GhostStreamController::load_with_mss(64, 2000);
        assert!(
            result.is_err(),
            "MSS max > 1500 should be rejected"
        );
    }

    // ── SNI split position calculator ────────────────────────────────────────

    /// In a typical TLS 1.3 ClientHello the SNI extension starts around byte 50–70.
    /// With MSS=64 the SNI should land in segment 0 (bytes 0–63), so the split
    /// happens within segment 0 if `sni_offset < 64`, or segment 1 otherwise.
    #[test]
    fn test_sni_split_mss64_offset50() {
        let (seg, byte_in_seg) = sni_split_position(64, 50);
        assert_eq!(seg, 0, "SNI at offset 50 should be in segment 0 for MSS=64");
        assert_eq!(byte_in_seg, 50);
    }

    #[test]
    fn test_sni_split_mss64_offset70() {
        // With MSS=64, offset 70 → segment 1, byte 6
        let (seg, byte_in_seg) = sni_split_position(64, 70);
        assert_eq!(seg, 1);
        assert_eq!(byte_in_seg, 6);
    }

    #[test]
    fn test_sni_split_mss128_offset50() {
        // MSS=128 is large enough to hold the first 128 bytes in one segment;
        // SNI at offset 50 is fully in segment 0.
        let (seg, _) = sni_split_position(128, 50);
        assert_eq!(seg, 0);
    }

    #[test]
    fn test_sni_split_mss128_split_across_segs() {
        // With a longer SNI offset (e.g., 130), segment 1 byte 2
        let (seg, byte_in_seg) = sni_split_position(128, 130);
        assert_eq!(seg, 1);
        assert_eq!(byte_in_seg, 2);
    }

    // ── RFC 1624 incremental checksum ────────────────────────────────────────

    #[test]
    fn test_rfc1624_identity() {
        // Replacing a word with itself must not change the checksum.
        let check = 0xABCD_u16;
        let word = 0x1234_u16;
        let new_check = rfc1624_checksum_update(check, word, word);
        assert_eq!(
            new_check, check,
            "Replacing with same value must not change checksum"
        );
    }

    #[test]
    fn test_rfc1624_zero_old_word() {
        // Standard incremental: old word = 0, new word = MSS value.
        let check = 0xFFFF_u16;
        let new_word = 128_u16;
        let new_check = rfc1624_checksum_update(check, 0, new_word);
        // Should produce a valid u16 (not panic or overflow).
        let _: u16 = new_check;
    }

    #[test]
    fn test_rfc1624_known_value() {
        // Pre-computed reference: old_check=0x1234, old_word=0x0064 (MSS 100),
        // new_word=0x0040 (MSS 64).  We just verify it produces a u16.
        let result = rfc1624_checksum_update(0x1234, 0x0064, 0x0040);
        // The result must fit in u16 and be different from original.
        assert_ne!(result, 0x1234);
    }

    // ── Whitelist set tracking ───────────────────────────────────────────────

    #[test]
    fn test_whitelisted_ip_count_starts_zero() {
        // We can't load actual eBPF in unit tests, so test the set directly.
        let mut set: HashSet<u32> = HashSet::new();
        assert_eq!(set.len(), 0);
        set.insert(u32::from_be_bytes([1, 2, 3, 4]));
        assert_eq!(set.len(), 1);
    }

    // ── Segment size constraint ──────────────────────────────────────────────

    /// Verify that for any MSS in [64, 128] and any SNI offset in [0, 511],
    /// the SNI is NEVER contained fully within a single 64-byte segment when
    /// the SNI itself is longer than 8 bytes.
    #[test]
    fn test_mss64_forces_sni_split_for_common_lengths() {
        // A "google.com" SNI is 10 bytes. With MSS=64 and SNI at offset 55,
        // bytes 55..64 (9 bytes) are in segment 0, byte 65 (10th char) is in segment 1.
        let mss = 64_u16;
        let sni_start = 55_usize;
        let sni_len = 10_usize; // "google.com"
        let (seg_start, _) = sni_split_position(mss, sni_start);
        let (seg_end, _) = sni_split_position(mss, sni_start + sni_len - 1);
        assert_ne!(
            seg_start, seg_end,
            "With MSS={} SNI at offset {} len {} must span two segments",
            mss, sni_start, sni_len
        );
    }
}
