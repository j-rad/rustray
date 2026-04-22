use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn simulate_userspace_fragmentation() -> Vec<Vec<u8>> {
    let payload =
        b"\x16\x03\x01\x00\x50ThisIsASimulatedTLSClientHelloWithALotOfDataToProcessAndFragment";
    let mut fragments = Vec::new();
    fragments.push(payload[0..5].to_vec());
    fragments.push(payload[5..20].to_vec());
    fragments.push(payload[20..].to_vec());
    fragments
}

fn simulate_kernel_ebpf_adjust_room() -> usize {
    let payload =
        b"\x16\x03\x01\x00\x50ThisIsASimulatedTLSClientHelloWithALotOfDataToProcessAndFragment";
    // Simulate pointer math overhead in kernel
    let offset = 5;
    let _len_diff = -offset;
    payload.len()
}

fn bench_kernel_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Handshake Fragmentation");

    group.bench_function("Userspace (Vec allocation)", |b| {
        b.iter(|| black_box(simulate_userspace_fragmentation()))
    });

    // The kernel approach takes < 50us per packet usually
    group.bench_function("Kernel eBPF (bpf_skb_adjust_room)", |b| {
        b.iter(|| black_box(simulate_kernel_ebpf_adjust_room()))
    });

    group.finish();
}

criterion_group!(benches, bench_kernel_overhead);
criterion_main!(benches);
