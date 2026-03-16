use criterion::{Criterion, criterion_group, criterion_main};
use rustray::ffi::EngineManager;

fn bench_ffi_stats(c: &mut Criterion) {
    let engine = EngineManager::new();
    // Simulate engine start (mocking, or just skip since we test stats retrieval overhead)

    c.bench_function("ffi_get_stats_json", |b| {
        b.iter(|| {
            engine.get_stats_json();
        })
    });
}

fn bench_db_mimic_ttfb_math(c: &mut Criterion) {
    use rand_distr::{Distribution, Normal};
    c.bench_function("db_mimic_ttfb_math", |b| {
        let normal = Normal::new(15.0, 5.0).unwrap();
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let delay_ms: f64 = normal.sample(&mut rng);
            let _ = delay_ms.max(0.0);
        })
    });
}

criterion_group!(benches, bench_ffi_stats, bench_db_mimic_ttfb_math);
criterion_main!(benches);
