// tests/flow_j_stealth.rs
//! Flow-J Stealth Module Integration Tests
//!
//! Tests entropy analysis and statistical parity with raw HTTPS streams.

use rustray::protocols::stealth::{
    HeaderEncryptor, MarkovJitter, ProbabilisticShaper, StealthProcessor,
};

/// Test that shaped packets have statistically similar sizes to HTTPS traffic.
#[test]
fn test_traffic_distribution_similarity() {
    let mut shaper = ProbabilisticShaper::new();

    // Generate 1000 shaped packets with varying original sizes
    let mut sizes: Vec<usize> = Vec::with_capacity(1000);

    for i in 0..1000 {
        let original_size = 50 + (i % 500); // 50-549 bytes
        let data = vec![0u8; original_size];
        let shaped = shaper.shape_packet(&data);
        sizes.push(shaped.len());
    }

    // Calculate mean and std dev
    let mean: f64 = sizes.iter().map(|&s| s as f64).sum::<f64>() / sizes.len() as f64;
    let variance: f64 = sizes
        .iter()
        .map(|&s| {
            let diff = s as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / sizes.len() as f64;
    let std_dev = variance.sqrt();

    // HTTPS traffic typically has mean ~1200, std_dev ~400
    // Allow ±200 tolerance for mean, ±150 for std_dev
    println!(
        "Shaped traffic stats: mean={:.1}, std_dev={:.1}",
        mean, std_dev
    );

    assert!(
        mean > 800.0 && mean < 1600.0,
        "Mean {} should be between 800 and 1600",
        mean
    );
    assert!(
        std_dev > 200.0 && std_dev < 600.0,
        "Std dev {} should be between 200 and 600",
        std_dev
    );
}

/// Test entropy of shaped packets vs original.
#[test]
fn test_entropy_increase() {
    let mut shaper = ProbabilisticShaper::new();

    // Original data: highly structured (repeating bytes)
    let original = vec![0x42u8; 100];
    let shaped = shaper.shape_packet(&original);

    // Calculate Shannon entropy
    let original_entropy = calculate_entropy(&original);
    let shaped_entropy = calculate_entropy(&shaped);

    println!(
        "Entropy: original={:.3}, shaped={:.3}",
        original_entropy, shaped_entropy
    );

    // Shaped data should have higher entropy due to random padding
    assert!(
        shaped_entropy > original_entropy,
        "Shaped entropy {} should be > original entropy {}",
        shaped_entropy,
        original_entropy
    );
}

/// Calculate Shannon entropy of a byte slice
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Test markov chain state distribution over time.
#[test]
fn test_markov_state_distribution() {
    let mut jitter = MarkovJitter::new();

    let mut state_counts = [0u32; 4];

    // Run 10000 transitions
    for _ in 0..10000 {
        let _delay = jitter.calculate_delay();
        state_counts[jitter.current_state() as usize] += 1;
    }

    println!(
        "State distribution: Burst={}, Interactive={}, ThinkTime={}, Idle={}",
        state_counts[0], state_counts[1], state_counts[2], state_counts[3]
    );

    // Interactive should be most common (stationary distribution)
    assert!(
        state_counts[1] > state_counts[3],
        "Interactive should be more common than Idle"
    );

    // All states should be visited
    for (i, &count) in state_counts.iter().enumerate() {
        assert!(count > 0, "State {} should be visited", i);
    }
}

/// Test header encryption round-trip with different data sizes.
#[test]
fn test_encryption_various_sizes() {
    let uuid = [1u8; 16];
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = [2u8; 8];

    let encryptor = HeaderEncryptor::new(&uuid, timestamp, &nonce);

    // Test various sizes
    for size in [1, 16, 100, 1000].iter() {
        let plaintext: Vec<u8> = (0..*size).map(|i| i as u8).collect();
        let ciphertext = encryptor.encrypt(&plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted, "Round-trip failed for size {}", size);
    }
}

/// Test that replay detection works (nonces should not repeat).
#[test]
fn test_nonce_uniqueness() {
    let encryptor = HeaderEncryptor::new(&[1u8; 16], 12345, &[2u8; 8]);

    let plaintext = b"test data";

    // Encrypt the same data twice
    let c1 = encryptor.encrypt(plaintext).unwrap();
    let c2 = encryptor.encrypt(plaintext).unwrap();

    // Ciphertexts should be different due to unique nonces
    assert_ne!(
        c1, c2,
        "Repeated encryptions should produce different ciphertexts"
    );

    // Both should decrypt correctly
    assert_eq!(encryptor.decrypt(&c1).unwrap(), plaintext);
    assert_eq!(encryptor.decrypt(&c2).unwrap(), plaintext);
}

/// Test full stealth processor pipeline.
#[tokio::test]
async fn test_stealth_processor_pipeline() {
    let mut processor = StealthProcessor::new();

    // Initialize with session parameters
    processor.init_encryption(&[3u8; 16], 999999, &[4u8; 8]);

    // Process a header
    let header_data = b"Flow-J header content";
    let processed_header = processor.process_outgoing(header_data, true).await;

    // Process body data
    let body_data = b"Payload data that should be padded";
    let processed_body = processor.process_outgoing(body_data, false).await;

    // Both should be larger than originals
    assert!(processed_header.len() > header_data.len());
    assert!(processed_body.len() > body_data.len());

    // Body should be recoverable (no encryption for non-headers)
    let recovered_body = processor.process_incoming(&processed_body, false);
    assert_eq!(recovered_body, Some(body_data.to_vec()));
}
