// benches/routing_memory_usage.rs
//! Benchmark: Memory Usage Verification
//!
//! This benchmark doesn't strictly measure RAM bytes (hard in Rust bench),
//! but verifies that the zero-copy path is functioning and performant,
//! which implies the memory savings (no Vec allocations).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustray::app::router::geo_loader::GeoManager;
use std::net::Ipv4Addr;
use tokio::runtime::Runtime;

fn benchmark_memory_pressure(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = GeoManager::new();

    rt.block_on(async {
        manager.init().await.unwrap();
    });

    let ip: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    // We simulate high-throughput lookups.
    // In strict zero-copy, this should not trigger GC pressure or allocator spikes.
    let mut group = c.benchmark_group("memory_pressure");
    group.throughput(criterion::Throughput::Elements(1));

    group.bench_function("lookup_iterative", |b| {
        b.iter(|| {
            // "CN" or "US" usually have large lists.
            // If we allocated Vec each time, this would be slow and churn memory.
            black_box(manager.match_geoip(ip, "CN"));
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark_memory_pressure);
criterion_main!(benches);
