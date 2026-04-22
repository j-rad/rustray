// benches/multiport_overhead.rs
use criterion::{Criterion, criterion_group, criterion_main};
use rustray::transport::flow_j_multiport::{MultiportSocketPool, MultiportStrategy};
use tokio::runtime::Runtime;

fn bench_multiport_rotation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut pool = rt.block_on(async {
        MultiportSocketPool::bind(
            "127.0.0.1",
            "20000-20063",
            5,
            MultiportStrategy::DynamicRandom,
        )
        .await
        .unwrap()
    });

    let mut group = c.benchmark_group("multiport_overhead");

    group.bench_function("rotate_if_needed_fast_path", |b| {
        b.iter(|| {
            // Benchmark fast-path struct ops
            let _ = pool.rotate_if_needed();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_multiport_rotation);
criterion_main!(benches);
