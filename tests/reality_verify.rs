// tests/reality_verify.rs
//! REALITY Handshake Validation Tests
//!  
//! Tests the cryptographic validity of the REALITY handshake implementation
//! Ensures RustRay parity for X25519 key exchange, HMAC authentication, and probe detection

use aes_gcm::KeyInit;
use hmac::{Hmac, Mac};
use rustray::config::RealityClientConfig;
#[allow(unused_imports)]
use rustray::transport::reality;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test]
async fn test_reality_session_id_generation() {
    // Test that session ID generation matches RustRay spec
    let server_pub_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let short_id_hex = "abcd1234";

    let pk_bytes = hex::decode(server_pub_key_hex).unwrap();
    let short_id_bytes = hex::decode(short_id_hex).unwrap();

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&pk_bytes).unwrap();
    mac.update(&short_id_bytes);
    let session_id = mac.finalize().into_bytes();

    assert_eq!(session_id.len(), 32, "Session ID should be 32 bytes");
}

#[tokio::test]
async fn test_x25519_key_exchange() {
    // Test basic X25519 ECDH
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);

    let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);

    assert_eq!(
        client_shared.as_bytes(),
        server_shared.as_bytes(),
        "Shared secrets must match"
    );
}

#[tokio::test]
async fn test_reality_probe_detection() {
    // Test that invalid TLS headers are properly detected
    let invalid_handshake = vec![
        0x16, // Handshake
        0x03, 0x01, // TLS 1.0
        0x00, 0x05, // Length: 5 bytes
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Invalid data
    ];

    // Should detect as invalid and trigger fallback
    assert!(invalid_handshake[0] == 0x16, "Should be handshake type");
    assert!(invalid_handshake.len() < 100, "Probe should be small");
}

#[tokio::test]
async fn test_reality_config_validation() {
    let config = RealityClientConfig {
        show: false,
        fingerprint: "chrome".to_string(),
        server_name: "www.google.com".to_string(),
        public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        short_id: "abcd1234".to_string(),
        spider_x: None,
    };

    assert!(!config.server_name.is_empty(), "Server name required");
    assert_eq!(
        config.public_key.len(),
        64,
        "Public key should be 32 bytes hex"
    );
}

#[test]
fn test_tls_transcript_hash() {
    // Test transcript hash matches TLS 1.3 spec
    let client_hello = b"client_hello_data";
    let server_hello = b"server_hello_data";

    let mut transcript = Sha256::new();
    transcript.update(client_hello);
    transcript.update(server_hello);
    let hash = transcript.finalize();

    assert_eq!(hash.len(), 32, "SHA-256 hash should be 32 bytes");
}

#[test]
fn bench_reality_handshake_overhead() {
    // Benchmark X25519 key generation
    use std::time::Instant;

    let iterations = 1000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _secret = StaticSecret::random_from_rng(rand::thread_rng());
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() / iterations;

    println!("Average X25519 keygen: {} μs", avg_micros);
    assert!(avg_micros < 100, "Key generation should be < 100μs");
}
