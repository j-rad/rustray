// benches/geo_mmap_vs_vec.rs
//! Benchmark: Memory-mapped geo asset loading vs Vec-based loading
//!
//! This benchmark compares the performance characteristics of:
//! - Memory-mapped IO (current implementation)
//! - Hypothetical Vec-based full load
//!
//! Run with: cargo bench --bench geo_mmap_vs_vec

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::fs;
use std::path::Path;

// Simulated mmap-style access
fn bench_mmap_style_access(path: &Path) -> usize {
    if !path.exists() {
        return 0;
    }

    // Memory-map the file (zero-copy)
    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };

    // Simulate index building (what geo_loader does)
    let mut count = 0;
    let mut offset = 0;
    while offset < mmap.len() {
        // Simulate reading a few bytes at random offsets
        if offset + 100 < mmap.len() {
            let _slice = &mmap[offset..offset + 100];
            count += 1;
        }
        offset += 1000; // Skip ahead
    }

    count
}

// Simulated Vec-based full load
fn bench_vec_style_load(path: &Path) -> usize {
    if !path.exists() {
        return 0;
    }

    // Load entire file into Vec (full copy)
    let data = fs::read(path).unwrap();

    // Simulate same access pattern
    let mut count = 0;
    let mut offset = 0;
    while offset < data.len() {
        if offset + 100 < data.len() {
            let _slice = &data[offset..offset + 100];
            count += 1;
        }
        offset += 1000;
    }

    count
}

fn benchmark_geo_loading(c: &mut Criterion) {
    // Try to find geoip.dat in common locations
    let test_paths = [
        "./geoip.dat",
        "/usr/share/rustray/geoip.dat",
        "/usr/local/share/xray/geoip.dat",
    ];

    let test_file = test_paths
        .iter()
        .find(|p| Path::new(p).exists())
        .map(Path::new);

    if let Some(path) = test_file {
        let file_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        println!("Benchmarking with file: {:?} ({} bytes)", path, file_size);

        c.bench_function("mmap_access", |b| {
            b.iter(|| bench_mmap_style_access(black_box(path)))
        });

        c.bench_function("vec_load", |b| {
            b.iter(|| bench_vec_style_load(black_box(path)))
        });
    } else {
        println!("No geoip.dat found, skipping benchmark");
        println!("Place geoip.dat in current directory to run benchmarks");
    }
}

criterion_group!(benches, benchmark_geo_loading);
criterion_main!(benches);
