use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rustray::app::router::geo_loader::GeoManager;
use std::net::Ipv4Addr;
use tokio::runtime::Runtime;

fn benchmark_geoip_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = GeoManager::new();

    // Initialize (loads mmap)
    rt.block_on(async {
        manager.init().await.unwrap();
    });

    let ip: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    c.bench_function("geoip_lookup_us", |b| {
        b.iter(|| {
            // Check if 8.8.8.8 is in US (Should be true)
            black_box(manager.match_geoip(ip, "US"))
        })
    });

    c.bench_function("geoip_lookup_cn", |b| {
        b.iter(|| {
            // Check if 8.8.8.8 is in CN (Should be false)
            black_box(manager.match_geoip(ip, "CN"))
        })
    });

    // Test Iranian Fast Path
    let ir_ip: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::new(2, 144, 0, 1)); // Shatel
    c.bench_function("geoip_lookup_ir_fastpath", |b| {
        b.iter(|| black_box(manager.match_geoip(ir_ip, "IR")))
    });
}

fn benchmark_geosite_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = GeoManager::new();

    rt.block_on(async {
        manager.init().await.unwrap();
    });

    c.bench_function("geosite_lookup_google", |b| {
        b.iter(|| black_box(manager.match_geosite("www.google.com", "google")))
    });
}

criterion_group!(benches, benchmark_geoip_lookup, benchmark_geosite_lookup);
criterion_main!(benches);
