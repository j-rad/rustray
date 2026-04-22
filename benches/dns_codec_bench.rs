// benches/dns_codec_bench.rs
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use rustray::transport::dns_codec::{base32_encode, base32_decode, encode_dns_payload, decode_dns_payload};

fn bench_base32_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_codec");
    let data = vec![0xAA; 100]; // 100 bytes

    group.bench_function("base32_encode_100b", |b| {
        b.iter(|| {
            black_box(base32_encode(black_box(&data)));
        })
    });

    group.finish();
}

fn bench_base32_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_codec");
    let data = vec![0xBB; 100];
    let encoded = base32_encode(&data);

    group.bench_function("base32_decode_100b", |b| {
        b.iter(|| {
            black_box(base32_decode(black_box(&encoded)).unwrap());
        })
    });

    group.finish();
}

fn bench_dns_payload_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_codec");
    let data = b"Test payload for DNS tunneling benchmark";
    let domain = "t.example.com";

    group.bench_function("dns_payload_encode", |b| {
        b.iter(|| {
            black_box(encode_dns_payload(black_box(data), black_box(domain)).unwrap());
        })
    });

    let encoded = encode_dns_payload(data, domain).unwrap();
    group.bench_function("dns_payload_decode", |b| {
        b.iter(|| {
            black_box(decode_dns_payload(black_box(&encoded), black_box(domain)).unwrap());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_base32_encode, bench_base32_decode, bench_dns_payload_roundtrip);
criterion_main!(benches);
