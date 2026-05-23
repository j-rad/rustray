// benches/tal_overhead.rs
//! Benchmark: Measures the overhead of the TrinityTransport abstraction layer.
//!
//! Target: < 500ns per round-trip through the TAL wrapper chain.
//!
//! We benchmark:
//! 1. Raw DuplexStream read/write (baseline).
//! 2. TrinityStream-wrapped DuplexStream (TAL overhead).
//! 3. ChaffingTransport-wrapped DuplexStream (chaffing overhead).
//! 4. `get_transport_info()` call latency.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rustray::protocols::flow_trait::{BoxedTrinityTransport, TrinityStream, TrinityTransport};
use rustray::transport::chaffing::{ChaffingConfig, ChaffingTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

fn bench_raw_duplex_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("raw_duplex_write_1kb", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut client, mut server) = tokio::io::duplex(65536);
                let data = vec![0xABu8; 1024];

                client.write_all(&data).await.unwrap();
                client.flush().await.unwrap();

                let mut buf = vec![0u8; 1024];
                server.read_exact(&mut buf).await.unwrap();

                black_box(buf);
            });
        });
    });
}

fn bench_trinity_stream_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("trinity_stream_write_1kb", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (client, mut server) = tokio::io::duplex(65536);
                let data = vec![0xABu8; 1024];

                let tal: BoxedTrinityTransport = Box::new(client);
                let mut stream = TrinityStream::new(tal);

                stream.write_all(&data).await.unwrap();
                stream.flush().await.unwrap();

                let mut buf = vec![0u8; 1024];
                server.read_exact(&mut buf).await.unwrap();

                black_box(buf);
            });
        });
    });
}

fn bench_chaffing_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("chaffing_write_1kb", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (client, mut server) = tokio::io::duplex(65536);
                let data = vec![0xABu8; 1024];

                let tal: BoxedTrinityTransport = Box::new(client);
                let config = ChaffingConfig {
                    mtu: 1280,
                    junk_frames_per_segment: 2,
                    junk_ttl: 5,
                    encrypt_junk: true,
                };
                let mut chaffed = ChaffingTransport::new(tal, config);

                chaffed.write_all(&data).await.unwrap();
                chaffed.flush().await.unwrap();

                // Read whatever arrived (data + junk).
                let mut buf = vec![0u8; 4096];
                let n = server.read(&mut buf).await.unwrap();

                black_box(&buf[..n]);
            });
        });
    });
}

fn bench_get_transport_info(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("get_transport_info", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (client, _server) = tokio::io::duplex(65536);
                let tal: BoxedTrinityTransport = Box::new(client);
                let stream = TrinityStream::new(tal);

                let info = black_box(stream.get_transport_info());
                black_box(info);
            });
        });
    });
}

criterion_group!(
    benches,
    bench_raw_duplex_write,
    bench_trinity_stream_write,
    bench_chaffing_write,
    bench_get_transport_info,
);
criterion_main!(benches);
