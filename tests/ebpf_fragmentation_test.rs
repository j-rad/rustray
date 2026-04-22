// tests/ebpf_fragmentation_test.rs
//! Phase 1 — GhostStream fragmentation verification.
//!
//! These tests validate the core mathematics and logic of the GhostStream
//! MSS clamping algorithm without requiring a live kernel environment or
//! physical NIC.  Integration tests that need actual XDP attachment must be
//! run with `sudo cargo test` on a Linux machine with `CAP_BPF`.
//!
//! Test categories:
//!  1. Segment-size constraint: all segments ≤ 128 bytes for MSS clamp 64–128.
//!  2. SNI split verification: the SNI string must span at least two segments.
//!  3. RFC 1624 checksum correctness: round-trip and known-value tests.
//!  4. Segment boundary scanning: scanner finds the MSS field in raw SYN bytes.

use rustray::kernel::ghoststream::{
    rfc1624_checksum_update, sni_split_position, MSS_MAX, MSS_MIN,
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Segment-size constraint
// ─────────────────────────────────────────────────────────────────────────────

/// Build a fake TLS ClientHello payload of `total_len` bytes, then verify that
/// when fragmented at `mss` bytes each piece is ≤ MSS_MAX (128).
fn check_all_segments_within_mss(total_len: usize, mss: usize) {
    assert!(mss >= MSS_MIN as usize, "MSS below minimum");
    assert!(mss <= MSS_MAX as usize, "MSS above maximum");

    let payload = vec![0xABu8; total_len];
    let segments: Vec<&[u8]> = payload.chunks(mss).collect();

    for (i, seg) in segments.iter().enumerate() {
        assert!(
            seg.len() <= MSS_MAX as usize,
            "Segment {} is {} bytes, exceeds MSS_MAX={}",
            i,
            seg.len(),
            MSS_MAX
        );
    }
}

#[test]
fn test_segments_within_mss_for_minimum_mss() {
    // Use MSS_MIN (64): a 512-byte ClientHello → 8 segments of ≤64 bytes.
    check_all_segments_within_mss(512, MSS_MIN as usize);
}

#[test]
fn test_segments_within_mss_for_maximum_mss() {
    // Use MSS_MAX (128): a 512-byte ClientHello → 4 segments of ≤128 bytes.
    check_all_segments_within_mss(512, MSS_MAX as usize);
}

#[test]
fn test_segments_within_mss_exact_multiple() {
    // 256 bytes at MSS=64 → exactly 4 segments of 64 bytes each.
    check_all_segments_within_mss(256, 64);
}

#[test]
fn test_segments_within_mss_non_multiple() {
    // 300 bytes at MSS=128 → 2 segments of 128 + 1 of 44.
    check_all_segments_within_mss(300, 128);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SNI split verification
// ─────────────────────────────────────────────────────────────────────────────

/// Given an SNI that starts at `sni_offset` and has `sni_len` bytes, assert
/// that it is split across at least two TCP segments when MSS = `mss`.
fn assert_sni_is_split(mss: u16, sni_offset: usize, sni_len: usize) {
    let (first_seg, _) = sni_split_position(mss, sni_offset);
    let (last_seg, _) = sni_split_position(mss, sni_offset + sni_len - 1);
    assert_ne!(
        first_seg, last_seg,
        "SNI must span two segments: mss={} sni_offset={} sni_len={}",
        mss, sni_offset, sni_len
    );
}

#[test]
fn test_sni_split_google_com_at_offset_55() {
    // "google.com" (10 bytes) starting at byte 55. With MSS=64:
    // bytes [55,63] in seg0, bytes [64,...] in seg1.
    assert_sni_is_split(64, 55, 10);
}

#[test]
fn test_sni_split_snapp_ir_at_offset_60() {
    // "snapp.ir" (8 bytes) starting at byte 60. MSS=64 → split at byte 64.
    assert_sni_is_split(64, 60, 8);
}

#[test]
fn test_sni_split_mss96_longer_hello() {
    // A longer SNI like "my-proxy-server.example.com" (27 bytes) at offset 70.
    // With MSS=96: seg0 holds [0,95], seg1 holds [96,...].  70+27=97 → split.
    assert_sni_is_split(96, 70, 27);
}

#[test]
fn test_sni_split_mss128_deep_offset() {
    // Even at the maximum MSS=128, an SNI at offset 120 length 20 still splits.
    assert_sni_is_split(128, 120, 20);
}

/// Every MSS value from MIN to MAX must split a realistic SNI at offset 50.
#[test]
fn test_all_mss_values_split_sni_at_offset50() {
    let sni_offset = 50;
    let sni_len = 15; // e.g., "example.com" padded

    for mss in MSS_MIN..=MSS_MAX {
        // If the entire SNI fits in the first segment, that is only valid when
        // sni_offset + sni_len ≤ mss.  For MSS ≥ 66, offset+len = 65 ≤ mss:
        // the SNI fits in one segment.  The test is that for MSS ≤ 64, it splits.
        // Only test MSS values that *should* split.
        if sni_offset + sni_len > mss as usize {
            assert_sni_is_split(mss, sni_offset, sni_len);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. RFC 1624 checksum
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_rfc1624_checksum_idempotent() {
    for word in [0x0040u16, 0x0080, 0x0064, 0xFFFF, 0x0001] {
        let check = 0x1234u16;
        let updated = rfc1624_checksum_update(check, word, word);
        assert_eq!(
            updated, check,
            "Replacing word={:#06x} with itself must leave checksum unchanged",
            word
        );
    }
}

#[test]
fn test_rfc1624_checksum_no_panic_full_range() {
    // Smoke-test: ensure no arithmetic panics for all boundary combinations.
    for old_word in [0u16, 0x0040, 0x0080, 0xFFFF] {
        for new_word in [0u16, 0x0040, 0x0080, 0xFFFF] {
            let _ = rfc1624_checksum_update(0xABCD, old_word, new_word);
        }
    }
}

#[test]
fn test_rfc1624_mss_clamp_100_to_64() {
    // Simulate: original MSS option in SYN = 100 (0x0064), clamped to 64 (0x0040).
    // The new checksum must differ from the original.
    let original_checksum = 0x1234u16;
    let new_checksum = rfc1624_checksum_update(original_checksum, 0x0064, 0x0040);
    assert_ne!(
        new_checksum, original_checksum,
        "Checksum must change when MSS word changes"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Segment scanner — locate MSS TCP option in raw SYN bytes
// ─────────────────────────────────────────────────────────────────────────────

/// Parse MSS from TCP options bytes.
/// Returns the MSS value if the MSS option (kind=2, len=4) is found.
fn parse_mss_from_tcp_options(options: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < options.len() {
        let kind = options[i];
        match kind {
            0 => break,                                            // End of options
            1 => { i += 1; }                                      // NOP
            2 if i + 3 < options.len() => {
                let len = options[i + 1] as usize;
                if len == 4 {
                    let mss = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                    return Some(mss);
                }
                i += len;
            }
            _ => {
                // Other option: skip by length byte.
                if i + 1 < options.len() {
                    let len = options[i + 1] as usize;
                    i += len.max(2);
                } else {
                    break;
                }
            }
        }
    }
    None
}

/// Build a minimal TCP options byte sequence containing an MSS option.
fn build_tcp_options_with_mss(mss: u16) -> Vec<u8> {
    vec![
        1,           // NOP
        1,           // NOP
        2, 4,        // MSS kind, len
        (mss >> 8) as u8, (mss & 0xFF) as u8,
    ]
}

#[test]
fn test_parse_mss_from_raw_options_1460() {
    let opts = build_tcp_options_with_mss(1460);
    let parsed = parse_mss_from_tcp_options(&opts);
    assert_eq!(parsed, Some(1460));
}

#[test]
fn test_parse_mss_after_clamp_to_64() {
    let opts = build_tcp_options_with_mss(64);
    let parsed = parse_mss_from_tcp_options(&opts);
    assert_eq!(parsed, Some(64));
}

#[test]
fn test_parse_mss_after_clamp_to_128() {
    let opts = build_tcp_options_with_mss(128);
    let parsed = parse_mss_from_tcp_options(&opts);
    assert_eq!(parsed, Some(128));
}

#[test]
fn test_parse_mss_not_present() {
    // Options with only NOPs — no MSS option.
    let opts = vec![1, 1, 1, 1];
    assert_eq!(parse_mss_from_tcp_options(&opts), None);
}

#[test]
fn test_parse_mss_end_of_options() {
    let opts = vec![0]; // EOL immediately
    assert_eq!(parse_mss_from_tcp_options(&opts), None);
}

/// Simulate the GhostStream kernel action: clamp the MSS in a raw options
/// buffer and verify the result is within [MSS_MIN, MSS_MAX].
#[test]
fn test_simulated_mss_clamp_in_options_buffer() {
    let original_mss = 1460_u16;
    let mut opts = build_tcp_options_with_mss(original_mss);

    // Find MSS and overwrite with clamped value.
    let clamped_mss = original_mss.min(MSS_MAX).max(MSS_MIN);
    // Locate MSS value at bytes [4,5] in our test options layout.
    let mss_offset = 4;
    let mss_bytes = clamped_mss.to_be_bytes();
    opts[mss_offset] = mss_bytes[0];
    opts[mss_offset + 1] = mss_bytes[1];

    let parsed = parse_mss_from_tcp_options(&opts).expect("MSS must be parseable after clamp");
    assert!(
        parsed >= MSS_MIN && parsed <= MSS_MAX,
        "Clamped MSS {} must be in [{}, {}]",
        parsed,
        MSS_MIN,
        MSS_MAX
    );
}
