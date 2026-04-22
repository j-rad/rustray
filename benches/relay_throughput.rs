// benches/relay_throughput.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Microbenchmark for deriving the PSK hash, as it's the core crypto component in the handshake.
fn derive_psk_key(psk: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rustray-p2p-relay-v1");
    hasher.update(psk.as_bytes());
    *hasher.finalize().as_bytes()
}

fn bench_relay_derive_key(c: &mut Criterion) {
    let psk = "my_custom_random_psk_12345";
    c.bench_function("derive_psk_key", |b| {
        b.iter(|| derive_psk_key(black_box(psk)))
    });
}

fn bench_relay_auth_hash(c: &mut Criterion) {
    let psk_key = derive_psk_key("bench_psk");
    let challenge = [0xAA; 32];
    
    c.bench_function("compute_auth_response", |b| {
        b.iter(|| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(black_box(&challenge));
            hasher.update(black_box(&psk_key));
            *hasher.finalize().as_bytes()
        })
    });
}

criterion_group!(benches, bench_relay_derive_key, bench_relay_auth_hash);
criterion_main!(benches);
