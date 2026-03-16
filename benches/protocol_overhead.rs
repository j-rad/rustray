// benches/protocol_overhead.rs
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use rustray::protocols::flow_trait::Flow;
use rustray::protocols::vless_vision::VisionFlow;

fn bench_vision_flow_padding(c: &mut Criterion) {
    c.bench_function("vision_flow_process_write", |b| {
        let mut flow = VisionFlow::new();
        let record = vec![
            0x16, 0x03, 0x03, 0x00, 0x10, // Header: Handshake, TLS 1.2, 16 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Payload
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];

        b.iter(|| {
            let _ = flow.process_write(black_box(&record));
        });
    });
}

criterion_group!(benches, bench_vision_flow_padding);
criterion_main!(benches);
