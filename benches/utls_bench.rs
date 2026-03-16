use criterion::{Criterion, criterion_group, criterion_main};
use rustray::transport::utls::get_utls_connector;
use std::hint::black_box;

pub fn benchmark_hello_rewriting(c: &mut Criterion) {
    let mut group = c.benchmark_group("utls_hello_rewriting");

    group.bench_function("chrome_fingerprint", |b| {
        b.iter(|| {
            black_box(get_utls_connector("chrome").unwrap());
        })
    });

    group.bench_function("firefox_fingerprint", |b| {
        b.iter(|| {
            black_box(get_utls_connector("firefox").unwrap());
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark_hello_rewriting);
criterion_main!(benches);
