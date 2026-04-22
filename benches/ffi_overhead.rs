// benches/ffi_overhead.rs
#![cfg(not(target_arch = "wasm32"))]
//! FFI Overhead Benchmarks
//!
//! Compares the performance of raw rustray operations vs FFI wrapper calls
//! to measure the overhead introduced by the FFI layer.
//!
//! Run with: cargo bench --bench ffi_overhead

use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// Benchmark raw Vision flow processing
fn bench_vision_raw(c: &mut Criterion) {
    use rustray::protocols::flow_trait::Flow;
    use rustray::protocols::vless_vision::VisionFlow;

    // Create a mock TLS ClientHello
    let mock_hello: Vec<u8> = (0..512)
        .map(|i| {
            if i < 5 {
                // TLS header
                match i {
                    0 => 0x16, // handshake
                    1 => 0x03, // version major
                    2 => 0x03, // version minor
                    3 => 0x01, // length high
                    4 => 0xFB, // length low (507 bytes)
                    _ => 0,
                }
            } else {
                (i & 0xFF) as u8
            }
        })
        .collect();

    c.bench_function("vision_flow_raw", |b| {
        b.iter(|| {
            let mut flow = VisionFlow::new();
            let processed = flow.process_write(black_box(&mock_hello)).unwrap();
            black_box(processed.len())
        })
    });
}

/// Benchmark Vision padding generation
fn bench_vision_padding(c: &mut Criterion) {
    use rustray::protocols::vless_vision::VisionFlow;

    c.bench_function("vision_padding_generation", |b| {
        b.iter(|| {
            let flow = VisionFlow::new();
            // Access the padding through the flow
            black_box(flow)
        })
    });
}

/// Benchmark Flow-J header encoding
fn bench_flowj_header_encode(c: &mut Criterion) {
    use rustray::protocols::flow_j::FlowJHeader;

    let header = FlowJHeader {
        version: 1,
        uuid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        command: 1,
        port: 443,
        addr_type: 2,
        address: "www.example.com".to_string(),
        nonce: [0xAA; 8],
        timestamp: 1234567890,
    };

    c.bench_function("flowj_header_encode", |b| {
        b.iter(|| {
            let encoded = header.encode();
            black_box(encoded.len())
        })
    });
}

/// Benchmark Flow-J header decoding
fn bench_flowj_header_decode(c: &mut Criterion) {
    use rustray::protocols::flow_j::FlowJHeader;

    let header = FlowJHeader {
        version: 1,
        uuid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        command: 1,
        port: 443,
        addr_type: 2,
        address: "www.example.com".to_string(),
        nonce: [0xAA; 8],
        timestamp: 1234567890,
    };

    let encoded = header.encode();

    c.bench_function("flowj_header_decode", |b| {
        b.iter(|| {
            let (decoded, consumed) = FlowJHeader::decode(black_box(&encoded)).unwrap();
            black_box((decoded.port, consumed))
        })
    });
}

/// Benchmark FFI config parsing
fn bench_ffi_config_parse(c: &mut Criterion) {
    use rustray::ffi::ConnectConfig;

    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "protocol": "vless",
        "flow": "xtls-rprx-vision",
        "security": "reality",
        "reality_settings": {
            "public_key": "1234567890abcdef1234567890abcdef",
            "short_id": "abcd1234",
            "server_name": "www.microsoft.com",
            "fingerprint": "chrome"
        },
        "fragment_settings": {
            "length": "10-50",
            "interval": "20-50"
        },
        "utls_fingerprint": "chrome",
        "local_address": "127.0.0.1",
        "local_port": 1080,
        "enable_udp": true,
        "routing_mode": "global"
    }
    "#;

    c.bench_function("ffi_config_parse", |b| {
        b.iter(|| {
            let config: ConnectConfig = serde_json::from_str(black_box(json)).unwrap();
            black_box(config.port)
        })
    });
}

/// Benchmark FFI config serialization
fn bench_ffi_config_serialize(c: &mut Criterion) {
    use rustray::ffi::{ConnectConfig, FragmentConfig, RealityConfig};

    let config = ConnectConfig {
        address: "example.com".to_string(),
        port: 443,
        uuid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
        protocol: "vless".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        network: "tcp".to_string(),
        security: "reality".to_string(),
        reality_settings: Some(RealityConfig {
            public_key: "test_key".to_string(),
            short_id: "abcd1234".to_string(),
            server_name: "www.google.com".to_string(),
            fingerprint: "chrome".to_string(),
            spider_x: None,
        }),
        utls_fingerprint: Some("chrome".to_string()),
        fragment_settings: Some(FragmentConfig {
            length: "10-50".to_string(),
            interval: "20-50".to_string(),
        }),
        flow_j_settings: None,
        local_address: "127.0.0.1".to_string(),
        local_port: 1080,
        enable_udp: true,
        tun_fd: None,
        routing_mode: "global".to_string(),
    };

    c.bench_function("ffi_config_serialize", |b| {
        b.iter(|| {
            let json = serde_json::to_string(black_box(&config)).unwrap();
            black_box(json.len())
        })
    });
}

/// Benchmark FFI is_running check
fn bench_ffi_is_running(c: &mut Criterion) {
    c.bench_function("ffi_is_running", |b| {
        b.iter(|| {
            let running = rustray::ffi::is_running();
            black_box(running)
        })
    });
}

/// Benchmark FFI get_version
fn bench_ffi_get_version(c: &mut Criterion) {
    c.bench_function("ffi_get_version", |b| {
        b.iter(|| {
            let version = rustray::ffi::get_version();
            black_box(version.len())
        })
    });
}

/// Benchmark FFI get_stats
fn bench_ffi_get_stats(c: &mut Criterion) {
    c.bench_function("ffi_get_stats", |b| {
        b.iter(|| {
            let stats = rustray::ffi::fetch_stats();
            black_box(stats.active_connections)
        })
    });
}

/// Benchmark REALITY auth tag generation
fn bench_reality_auth_tag(c: &mut Criterion) {
    use rustray::transport::flow_j_reality::generate_auth_tag;

    let private_key = b"0123456789abcdef0123456789abcdef";
    let short_id = b"abcd1234";
    let session_id = b"session_id_here!";

    c.bench_function("reality_auth_tag_gen", |b| {
        b.iter(|| {
            let tag = generate_auth_tag(
                black_box(private_key),
                black_box(short_id),
                black_box(session_id),
            );
            black_box(tag)
        })
    });
}

/// Benchmark REALITY auth tag verification
fn bench_reality_auth_verify(c: &mut Criterion) {
    use rustray::transport::flow_j_reality::{generate_auth_tag, verify_auth_tag};

    let private_key = b"0123456789abcdef0123456789abcdef";
    let short_id = b"abcd1234";
    let session_id = b"session_id_here!";
    let tag = generate_auth_tag(private_key, short_id, session_id);

    c.bench_function("reality_auth_tag_verify", |b| {
        b.iter(|| {
            let valid = verify_auth_tag(
                black_box(private_key),
                black_box(short_id),
                black_box(session_id),
                black_box(&tag),
            );
            black_box(valid)
        })
    });
}

/// Benchmark uTLS connector creation
fn bench_utls_connector(c: &mut Criterion) {
    use rustray::transport::utls::get_utls_connector;

    c.bench_function("utls_connector_chrome", |b| {
        b.iter(|| {
            let _connector = get_utls_connector(black_box("chrome"));
            // Just measure creation time
        })
    });
}

/// Benchmark raw bytes copy (baseline)
fn bench_bytes_copy_baseline(c: &mut Criterion) {
    let data: Vec<u8> = (0..16384).map(|i| (i & 0xFF) as u8).collect();

    c.bench_function("bytes_copy_16kb_baseline", |b| {
        b.iter(|| {
            let copy = data.clone();
            black_box(copy.len())
        })
    });
}

/// Benchmark TLS fragment stream config parsing
fn bench_fragment_config_parse(c: &mut Criterion) {
    use rustray::config::TlsFragmentSettings;

    let json = r#"{ "length": "10-100", "interval": "20-50" }"#;

    c.bench_function("fragment_config_parse", |b| {
        b.iter(|| {
            let config: TlsFragmentSettings = serde_json::from_str(black_box(json)).unwrap();
            black_box(config.length.len())
        })
    });
}

/// Compare FFI overhead vs raw operation
fn bench_ffi_overhead_comparison(c: &mut Criterion) {
    
    use rustray::protocols::vless_vision::VisionFlow;

    let _mock_data: Vec<u8> = vec![0x16, 0x03, 0x03, 0x00, 0x20]; // TLS header

    let mut group = c.benchmark_group("ffi_overhead");

    // Raw operation
    group.bench_function("raw_vision_new", |b| {
        b.iter(|| {
            let flow = VisionFlow::new();
            black_box(flow)
        })
    });

    // Through FFI config parsing (simulates FFI overhead)
    group.bench_function("ffi_parse_minimal", |b| {
        let json = r#"{"address":"a","port":1,"uuid":"u","protocol":"p"}"#;
        b.iter(|| {
            let _: rustray::ffi::ConnectConfig = serde_json::from_str(black_box(json)).unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_vision_raw,
    bench_vision_padding,
    bench_flowj_header_encode,
    bench_flowj_header_decode,
    bench_ffi_config_parse,
    bench_ffi_config_serialize,
    bench_ffi_is_running,
    bench_ffi_get_version,
    bench_ffi_get_stats,
    bench_reality_auth_tag,
    bench_reality_auth_verify,
    bench_utls_connector,
    bench_bytes_copy_baseline,
    bench_fragment_config_parse,
    bench_ffi_overhead_comparison,
);

criterion_main!(benches);
