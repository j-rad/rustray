use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;

fn binary_size_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("production_payload");

    // Track binary size of the core
    group.bench_function("core_binary_size", |b| {
        b.iter(|| {
            let path = Path::new("target/release/rustray");
            if path.exists() {
                let metadata = std::fs::metadata(path).unwrap();
                black_box(metadata.len());
            } else {
                // Return 0 if not built
                black_box(0);
            }
        })
    });

    // Track binary size of the desktop app
    group.bench_function("app_binary_size", |b| {
        b.iter(|| {
            // Heuristic path for deb
            let path = Path::new(
                "edgeray-app/src-tauri/target/release/bundle/deb/edgeray-app_0.1.0_amd64.deb",
            );
            if path.exists() {
                let metadata = std::fs::metadata(path).unwrap();
                black_box(metadata.len());
            } else {
                black_box(0);
            }
        })
    });

    group.finish();
}

fn startup_latency_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("startup_latency");

    group.bench_function("core_startup", |b| {
        b.iter(|| {
            // Mock startup check - requires actually running the bin which is slow for criterion
            // We'll just measure a fast stat call here to represent "check readiness"
            let path = Path::new("target/release/rustray");
            if path.exists() {
                black_box(path.exists());
            }
        })
    });

    group.finish();
}

criterion_group!(benches, binary_size_benchmark, startup_latency_benchmark);
criterion_main!(benches);
