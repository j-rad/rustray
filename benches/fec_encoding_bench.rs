// benches/fec_encoding_bench.rs
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use rustray::fec::rs::{FecEncoder, FecDecoder};
use bytes::Bytes;

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_encode");
    let data_shards = 10;
    let parity_shards = 3;
    let mut encoder = FecEncoder::new(data_shards, parity_shards).unwrap();

    // 1 KB per shard
    let data: Vec<Bytes> = (0..data_shards)
        .map(|_| Bytes::from(vec![0xAA; 1024]))
        .collect();

    group.bench_function("encode_10+3_1kb", |b| {
        b.iter(|| {
            black_box(encoder.encode(black_box(&data)).unwrap());
        })
    });

    group.finish();
}

fn bench_fec_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_decode");
    let data_shards = 10;
    let parity_shards = 3;
    let mut encoder = FecEncoder::new(data_shards, parity_shards).unwrap();
    let decoder = FecDecoder::new(data_shards, parity_shards).unwrap();

    let data: Vec<Bytes> = (0..data_shards)
        .map(|_| Bytes::from(vec![0xBB; 1024]))
        .collect();

    let packets = encoder.encode(&data).unwrap();

    // Simulate losing 2 shards
    let mut shards: Vec<Option<Vec<u8>>> = packets.iter()
        .map(|p| Some(p.data.to_vec()))
        .collect();
    shards[0] = None;
    shards[5] = None;

    group.bench_function("decode_10+3_1kb_2lost", |b| {
        b.iter(|| {
            black_box(decoder.decode(black_box(shards.clone())).unwrap());
        })
    });

    group.finish();
}

criterion_group!(benches, bench_fec_encode, bench_fec_decode);
criterion_main!(benches);
