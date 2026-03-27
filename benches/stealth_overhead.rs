// benches/stealth_overhead.rs
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rustray::protocols::stealth::{HeaderEncryptor, MarkovJitter, ProbabilisticShaper};

fn bench_probabilistic_shaper(c: &mut Criterion) {
    let mut group = c.benchmark_group("stealth_shaper");
    let mut shaper = ProbabilisticShaper::new();
    let data = vec![0u8; 1000]; // 1KB payload

    group.bench_function("shape_packet_1kb", |b| {
        b.iter(|| {
            black_box(shaper.shape_packet(black_box(&data)));
        })
    });

    group.finish();
}

fn bench_header_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("stealth_encryption");
    let uuid = [1u8; 16];
    let timestamp = 1234567890u64;
    let nonce = [2u8; 8];
    let encryptor = HeaderEncryptor::new(&uuid, timestamp, &nonce);
    let header = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    group.bench_function("encrypt_header", |b| {
        b.iter(|| {
            black_box(encryptor.encrypt(black_box(header)).unwrap());
        })
    });

    group.finish();
}

fn bench_markov_jitter_calc(c: &mut Criterion) {
    let mut group = c.benchmark_group("stealth_jitter");
    let mut jitter = MarkovJitter::new();

    group.bench_function("calculate_delay", |b| {
        b.iter(|| {
            black_box(jitter.calculate_delay());
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_probabilistic_shaper,
    bench_header_encryption,
    bench_markov_jitter_calc
);
criterion_main!(benches);
