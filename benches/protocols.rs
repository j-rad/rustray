use criterion::{Criterion, Throughput, criterion_group, criterion_main};

// Note: We need to expose internal logic or use public APIs to benchmark.
// Since handle_inbound takes streams and router/stats, it's hard to micro-benchmark without mocks.
// We will benchmark a simple data copy loop representing the "Pipe" phase which is critical.

pub fn benchmark_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");

    // 1MB payload
    static PAYLOAD: [u8; 1024 * 1024] = [0u8; 1024 * 1024];

    group.throughput(Throughput::Bytes(PAYLOAD.len() as u64));
    group.bench_function("copy_1mb", |b| {
        b.iter(|| {
            // Simulate a memory copy which is the upper bound of proxy throughput
            let mut _dst = Vec::with_capacity(PAYLOAD.len());
            _dst.extend_from_slice(&PAYLOAD);
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark_throughput);
criterion_main!(benches);
