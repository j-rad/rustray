// benches/brutal_pacing_bench.rs
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use quinn::congestion::Controller;
use rustray::transport::brutal_cc::BrutalCongestionController;
use std::time::Instant;

fn bench_brutal_cc_congestion(c: &mut Criterion) {
    let mut cc = BrutalCongestionController::new(100);
    let start = Instant::now();

    c.bench_function("brutal_on_congestion_event", |b| {
        b.iter(|| {
            cc.on_congestion_event(
                black_box(start),
                black_box(start),
                black_box(false),
                black_box(1400),
            )
        })
    });
}

criterion_group!(benches, bench_brutal_cc_congestion);
criterion_main!(benches);
