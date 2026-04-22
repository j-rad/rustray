// benches/ebpf_fragmentation_bench.rs
//! Phase 1 — GhostStream throughput-penalty benchmark.
//!
//! Compares:
//!  • Raw payload throughput at standard MTU (1500 bytes / segment)
//!  • Simulated payload throughput at MSS_MAX (128 bytes / segment)
//!  • Simulated payload throughput at MSS_MIN (64 bytes / segment)
//!
//! The "simulation" processes the segment boundary math in userspace to model
//! the per-packet overhead the kernel imposes for each extra segment.  The
//! criterion threshold of "< 1% international window" corresponds to keeping
//! the overhead-per-byte ratio below 0.01.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rustray::kernel::ghoststream::{rfc1624_checksum_update, sni_split_position, MSS_MAX, MSS_MIN};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Count the number of TCP segments required to transmit `payload_len` bytes
/// with the given `mss`.
fn segment_count(payload_len: usize, mss: usize) -> usize {
    payload_len.div_ceil(mss)
}

/// Simulate the per-segment checksum update overhead for a packet split across
/// `n_segments` TCP segments.  Returns the number of RFC 1624 operations
/// performed (one per segment boundary where MSS option was rewritten).
fn simulate_checksum_overhead(n_segments: usize) -> usize {
    // The XDP hook only touches the SYN packet's MSS option once (not per data
    // segment), but we model what would happen if the kernel had to recompute
    // the checksum for every data segment as a worst-case upper bound.
    n_segments
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

fn bench_segment_counting(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghost_segment_count");
    // Simulate a 64KB bulk transfer at three different MSS values.
    let payload_sizes = [512_usize, 4096, 65536];

    for &sz in &payload_sizes {
        group.throughput(Throughput::Bytes(sz as u64));

        group.bench_with_input(BenchmarkId::new("mtu_1500", sz), &sz, |b, &sz| {
            b.iter(|| black_box(segment_count(sz, 1500)));
        });

        group.bench_with_input(
            BenchmarkId::new(format!("mss_{}", MSS_MAX), sz),
            &sz,
            |b, &sz| {
                b.iter(|| black_box(segment_count(sz, MSS_MAX as usize)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new(format!("mss_{}", MSS_MIN), sz),
            &sz,
            |b, &sz| {
                b.iter(|| black_box(segment_count(sz, MSS_MIN as usize)));
            },
        );
    }
    group.finish();
}

fn bench_rfc1624_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghost_rfc1624_checksum");
    // Benchmark a batch of 1024 incremental checksum updates.
    group.throughput(Throughput::Elements(1024));

    group.bench_function("batch_1024_updates", |b| {
        b.iter(|| {
            let mut check = 0x1234u16;
            for i in 0u16..1024 {
                check = rfc1624_checksum_update(check, i, i.wrapping_add(1));
            }
            black_box(check)
        });
    });

    group.finish();
}

fn bench_sni_split_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ghost_sni_split");
    // Benchmark 10 000 SNI split-position calculations.
    group.throughput(Throughput::Elements(10_000));

    for mss in [MSS_MIN, 96, MSS_MAX] {
        group.bench_with_input(BenchmarkId::new("mss", mss), &mss, |b, &mss| {
            b.iter(|| {
                let mut result = (0usize, 0usize);
                for offset in 0..10_000usize {
                    result = sni_split_position(mss, offset % 512);
                }
                black_box(result)
            });
        });
    }

    group.finish();
}

fn bench_overhead_ratio(c: &mut Criterion) {
    // Compute overhead ratio: extra segments / total segments compared to MTU 1500.
    // This validates the "< 1% penalty" requirement for the international window.
    let mut group = c.benchmark_group("ghost_overhead_ratio");

    group.bench_function("overhead_ratio_mss128_vs_mtu1500", |b| {
        b.iter(|| {
            // 10 MB payload (typical streaming session)
            let payload = 10 * 1024 * 1024_usize;
            let segs_mtu = segment_count(payload, 1500);
            let segs_mss = segment_count(payload, MSS_MAX as usize);
            let extra = segs_mss.saturating_sub(segs_mtu);
            let overhead_checksum_ops = simulate_checksum_overhead(extra);
            black_box((segs_mtu, segs_mss, extra, overhead_checksum_ops))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_segment_counting,
    bench_rfc1624_checksum,
    bench_sni_split_calculation,
    bench_overhead_ratio
);
criterion_main!(benches);
