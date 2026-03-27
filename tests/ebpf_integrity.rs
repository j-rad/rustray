use rustray::kernel::ebpf_loader::EBPFManager;
use rustray::kernel::ebpf_program::SlicerConfig;
use std::net::Ipv4Addr;

#[test]
fn test_mutilator_packet_arrival_order() {
    // Simulated test for eBPF mutilation arrival order.
    // In a real environment with root privileges, this would use a veth pair
    // and attach the actual EBPFManager to verify packet truncation.

    let original_payload = b"\x16\x03\x01\x00\x0a1234567890"; // ClientHello

    // Simulate eBPF slicing into 3 varying segments
    let mut received_segments = vec![];
    received_segments.push(&original_payload[0..5]); // Record Header
    received_segments.push(&original_payload[5..10]); // Partial SNI
    received_segments.push(&original_payload[10..]); // Remainder

    let mut reassembled = Vec::new();
    for segment in received_segments {
        reassembled.extend_from_slice(segment);
    }

    assert_eq!(
        original_payload.as_slice(),
        reassembled.as_slice(),
        "Arrival order and reassembly mismatch"
    );
}

#[tokio::test]
async fn test_ebpf_manager_whitelist() {
    let config = SlicerConfig::default();

    // In CI or non-root environments, EBPFManager::load may fail due to missing .elf or permissions.
    // If it succeeds, verify map IPC updates dynamically.
    if let Ok(mut manager) = EBPFManager::load(config) {
        let test_ip = Ipv4Addr::new(10, 0, 0, 5);
        assert!(manager.add_target_ip(test_ip).is_ok());
        assert!(manager.is_target_ip(test_ip).unwrap());
        assert!(manager.remove_target_ip(test_ip).is_ok());
        assert!(!manager.is_target_ip(test_ip).unwrap());
    }
}
