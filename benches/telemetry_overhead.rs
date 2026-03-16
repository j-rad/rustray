// benches/telemetry_overhead.rs
use criterion::{Criterion, criterion_group, criterion_main};
use rustray::app::metrics::prober::Prober;

fn bench_jitter_calculation(c: &mut Criterion) {
    let latencies = vec![100, 105, 102, 110, 98, 103, 101, 108, 99, 104]; // 10 samples
    c.bench_function("calc_jitter_10_samples", |b| {
        b.iter(|| {
            Prober::calculate_jitter(&latencies);
        })
    });
}

criterion_group!(benches, bench_jitter_calculation);
criterion_main!(benches);
