//! Final Performance Benchmarks
//!
//! Comprehensive throughput and latency benchmarks comparing release build
//! against baseline and measuring critical path performance.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

/// Benchmark: Raw TCP proxy throughput simulation
/// Measures the overhead of data copying through the proxy path
fn bench_data_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // Test different payload sizes
    for size in [1024, 8192, 65536, 262144].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(format!("copy_{}kb", size / 1024), &data, |b, data| {
            b.iter(|| {
                let mut output = vec![0u8; data.len()];
                output.copy_from_slice(black_box(data));
                black_box(output)
            })
        });
    }

    group.finish();
}

/// Benchmark: VLESS header parsing overhead
fn bench_vless_header_parse(c: &mut Criterion) {
    // Simulated VLESS header (version + UUID + addon length + command + address)
    let vless_header = [
        0x01, // version
        // UUID (16 bytes)
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0, 0x00, // addon length
        0x01, // command (TCP)
        0x00, 0x50, // port (80)
        0x01, // address type (IPv4)
        0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
    ];

    c.bench_function("vless_header_parse", |b| {
        b.iter(|| {
            // Simulate parsing the header
            let version = black_box(vless_header[0]);
            let uuid_slice = black_box(&vless_header[1..17]);
            let addon_len = black_box(vless_header[17]) as usize;
            let command = black_box(vless_header[18 + addon_len]);
            black_box((version, uuid_slice, command))
        })
    });
}

/// Benchmark: Connection state tracking overhead
fn bench_connection_tracking(c: &mut Criterion) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let counters = Arc::new((
        AtomicU64::new(0), // bytes_up
        AtomicU64::new(0), // bytes_down
        AtomicU64::new(0), // active_conns
    ));

    c.bench_function("atomic_stats_update", |b| {
        let c = counters.clone();
        b.iter(|| {
            c.0.fetch_add(1024, Ordering::Relaxed);
            c.1.fetch_add(2048, Ordering::Relaxed);
            c.2.fetch_add(1, Ordering::Relaxed);
            black_box(())
        })
    });
}

/// Benchmark: JSON stats serialization
fn bench_stats_serialization(c: &mut Criterion) {
    #[derive(serde::Serialize)]
    struct StatsSnapshot {
        bytes_uploaded: u64,
        bytes_downloaded: u64,
        active_connections: u64,
        total_connections: u64,
        last_update: u64,
        connection_state: u64,
        errors: u64,
    }

    let stats = StatsSnapshot {
        bytes_uploaded: 1_000_000_000,
        bytes_downloaded: 2_500_000_000,
        active_connections: 150,
        total_connections: 50000,
        last_update: 1704326400000,
        connection_state: 2,
        errors: 0,
    };

    c.bench_function("stats_json_serialize", |b| {
        b.iter(|| black_box(serde_json::to_string(&stats).unwrap()))
    });
}

/// Benchmark: IP address parsing (for routing decisions)
fn bench_ip_parsing(c: &mut Criterion) {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut group = c.benchmark_group("ip_parsing");

    group.bench_function("ipv4_parse", |b| {
        b.iter(|| black_box("192.168.1.100".parse::<Ipv4Addr>().unwrap()))
    });

    group.bench_function("ipv6_parse", |b| {
        b.iter(|| black_box("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
    });

    group.bench_function("ipaddr_generic", |b| {
        b.iter(|| black_box("192.168.1.100".parse::<IpAddr>().unwrap()))
    });

    group.finish();
}

/// Benchmark: Base64 encoding/decoding (for config handling)
fn bench_base64(c: &mut Criterion) {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let data = vec![0u8; 1024];
    let encoded = STANDARD.encode(&data);

    let mut group = c.benchmark_group("base64");

    group.throughput(Throughput::Bytes(1024));
    group.bench_function("encode_1kb", |b| {
        b.iter(|| black_box(STANDARD.encode(&data)))
    });

    group.bench_function("decode_1kb", |b| {
        b.iter(|| black_box(STANDARD.decode(&encoded).unwrap()))
    });

    group.finish();
}

/// Benchmark: UUID generation (for connection tracking)
fn bench_uuid(c: &mut Criterion) {
    c.bench_function("uuid_v4_generate", |b| {
        b.iter(|| black_box(uuid::Uuid::new_v4()))
    });

    c.bench_function("uuid_parse", |b| {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        b.iter(|| black_box(uuid::Uuid::parse_str(uuid_str).unwrap()))
    });
}

/// Benchmark: Hash computation for VLESS authentication
fn bench_hash(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    let data = vec![0u8; 256];

    c.bench_function("sha256_256bytes", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&data));
            black_box(hasher.finalize())
        })
    });
}

criterion_group!(
    benches,
    bench_data_throughput,
    bench_vless_header_parse,
    bench_connection_tracking,
    bench_stats_serialization,
    bench_ip_parsing,
    bench_base64,
    bench_uuid,
    bench_hash,
);

criterion_main!(benches);
