// tests/fec_recovery_test.rs
use rustray::fec::rs::{FecEncoder, FecDecoder};
use bytes::Bytes;

#[test]
fn test_rs_recovery_30_percent_loss() {
    let data_shards = 10;
    let parity_shards = 4; // ~28.5% extra (total 14)
    let mut encoder = FecEncoder::new(data_shards, parity_shards).unwrap();
    let decoder = FecDecoder::new(data_shards, parity_shards).unwrap();

    // 1. Prepare data
    let original_data: Vec<Bytes> = (0..data_shards)
        .map(|i| Bytes::from(format!("Shard data number {}", i)))
        .collect();

    // 2. Encode
    let packets = encoder.encode(&original_data).unwrap();
    assert_eq!(packets.len(), data_shards + parity_shards);

    // 3. Simulate 30% loss (lose 4 packets out of 14)
    let lost_indices = [0, 3, 7, 11]; // Lose some data and some parity
    let mut received_shards: Vec<Option<Vec<u8>>> = vec![None; data_shards + parity_shards];

    for (i, p) in packets.into_iter().enumerate() {
        if !lost_indices.contains(&i) {
            received_shards[i] = Some(p.data.to_vec());
        }
    }

    // 4. Decode/Reconstruct
    let reconstructed = decoder.decode(received_shards).unwrap();

    // 5. Verify
    for i in 0..data_shards {
        assert_eq!(original_data[i].to_vec(), reconstructed[i], "Shard {} mismatch", i);
    }
    println!("FEC Reconstruction successful with {}/{} packets lost", lost_indices.len(), data_shards + parity_shards);
}

#[test]
fn test_rs_impossible_recovery() {
    let data_shards = 10;
    let parity_shards = 2; // Only 2 parity shards
    let mut encoder = FecEncoder::new(data_shards, parity_shards).unwrap();
    let decoder = FecDecoder::new(data_shards, parity_shards).unwrap();

    let original_data: Vec<Bytes> = (0..data_shards)
        .map(|i| Bytes::from(format!("Data {}", i)))
        .collect();

    let packets = encoder.encode(&original_data).unwrap();

    // Lose 3 packets (more than 2 parity)
    let lost_indices = [0, 1, 2];
    let mut received_shards: Vec<Option<Vec<u8>>> = vec![None; data_shards + parity_shards];

    for (i, p) in packets.into_iter().enumerate() {
        if !lost_indices.contains(&i) {
            received_shards[i] = Some(p.data.to_vec());
        }
    }

    // Decoding should fail
    let result = decoder.decode(received_shards);
    assert!(result.is_err(), "Decoding should have failed due to excessive loss");
}
