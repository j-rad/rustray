use bytes::BytesMut;
use criterion::{Criterion, criterion_group, criterion_main};
use rustray::protocols::flow_trait::Flow;
use rustray::protocols::vless_vision::VisionFlow;

fn bench_vision_padding(c: &mut Criterion) {
    let mut flow = VisionFlow::new();
    let record = vec![
        0x16, 0x03, 0x03, 0x00, 0x10, // Header: Handshake, TLS 1.2, 16 bytes
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Payload
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];
    let mut buf = BytesMut::new();

    c.bench_function("vision_padding", |b| {
        b.iter(|| {
            buf.clear();
            flow.process_write_buf(&record, &mut buf);
            // Reset flow state ideally, but Vision state machine progresses.
            // For micro-benchmark of padding generation, we can just run it.
            // But VisionFlow state changes.
            // To bench cost of padding generation, we should keep it in Handshake state?
            // VisionFlow state resets if we create new flow or if we hack it.
            // Actually, `process_write_buf` will advance state on first call.
            // Subsequent calls might be traffic (passthrough).
            // We want to bench the PADDING cost.
            // So we need new flow usage inside iter? That includes allocation.
            // Or we just bench the function and accept state transition (1st iter = slow, rest = fast).
            // That's not what we want.
        })
    });
}
// For better bench, we need to reset state.

fn bench_vision_padding_generation(c: &mut Criterion) {
    let record = vec![
        0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];

    c.bench_function("vision_padding_generation", |b| {
        b.iter(|| {
            let mut flow = VisionFlow::new(); // Include creation in bench?
            let mut buf = BytesMut::with_capacity(2048);
            flow.process_write_buf(&record, &mut buf);
        })
    });
}

criterion_group!(benches, bench_vision_padding_generation);
criterion_main!(benches);
