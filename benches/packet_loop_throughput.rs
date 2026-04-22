// benches/packet_loop_throughput.rs
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rustray::tun::{is_core_healthy, set_core_healthy};

// Simulate a packet processing loop with Kill-Switch check
fn bench_kill_switch_impact_atomic(c: &mut Criterion) {
    set_core_healthy(true);

    c.bench_function("packet_loop_kill_switch_check_atomic", |b| {
        b.iter(|| {
            // Atomic load check
            if black_box(is_core_healthy()) {
                // Simulate processing overhead (minimal)
                black_box(1 + 1);
            }
        })
    });
}

fn bench_kill_switch_overhead_baseline(c: &mut Criterion) {
    c.bench_function("packet_loop_baseline_no_check", |b| {
        b.iter(|| {
            // No check
            black_box(1 + 1);
        })
    });
}

fn bench_mtu_standard_vs_jumbo(c: &mut Criterion) {
    let mut group = c.benchmark_group("mtu_throughput");

    group.bench_function("standard_mtu_1500", |b| {
        let mtu = 1500;
        let mut buffer = vec![0u8; mtu as usize];
        b.iter(|| {
            // Simulate packet processing overhead proportional to buffer size
            for i in 0..mtu as usize {
                buffer[i] = black_box(i as u8);
            }
            black_box(&buffer);
        })
    });

    group.bench_function("jumbo_mtu_9000", |b| {
        let mtu = 9000;
        let mut buffer = vec![0u8; mtu as usize];
        b.iter(|| {
            // Simulate packet processing overhead proportional to buffer size
            for i in 0..mtu as usize {
                buffer[i] = black_box(i as u8);
            }
            black_box(&buffer);
        })
    });
    group.finish();
}

fn bench_shared_buffer_pool_throughput(c: &mut Criterion) {
    use rustray::tun::SharedBufferPool;
    use std::sync::Arc;

    let pool = Arc::new(SharedBufferPool::with_capacity(256, 2048));

    c.bench_function("shared_buffer_pool_acquire_release_throughput", |b| {
        b.iter(|| {
            // Acquire and release a buffer
            let mut buf = pool.acquire();
            buf.set_len(1500);
            black_box(buf.as_slice());
            // drop(buf) happens automatically, releasing back to pool
        })
    });
}

criterion_group!(
    benches,
    bench_kill_switch_impact_atomic,
    bench_kill_switch_overhead_baseline,
    bench_mtu_standard_vs_jumbo,
    bench_shared_buffer_pool_throughput
);
criterion_main!(benches);
