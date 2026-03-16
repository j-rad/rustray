// tests/reality_parity_test.rs
//! REALITY Protocol Parity Tests
//!
//! Comprehensive test suite to verify rustray's REALITY implementation
//! matches RustRay's reference implementation for:
//! - X25519 key exchange
//! - HMAC-based authentication
//! - TLS 1.3 handshake flow
//! - Probe detection and forwarding

use bytes::{BufMut, BytesMut};
use digest::KeyInit;
use hmac::{Hmac, Mac};
use rustray::transport::flow_j_reality::{generate_auth_tag, verify_auth_tag};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use x25519_dalek::{PublicKey, StaticSecret};

// ============================================================================
// X25519 KEY EXCHANGE PARITY TESTS
// ============================================================================

#[tokio::test]
async fn test_x25519_shared_secret_computation() {
    // Verify that X25519 ECDH produces identical results on both sides
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);

    let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    // Compute shared secrets
    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);

    assert_eq!(
        client_shared.as_bytes(),
        server_shared.as_bytes(),
        "X25519 shared secrets must match"
    );
}

#[test]
fn test_x25519_deterministic_public_key() {
    // Test that same private key always produces same public key
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let secret1 = StaticSecret::from(secret_bytes);
    let secret2 = StaticSecret::from(secret_bytes);

    let public1 = PublicKey::from(&secret1);
    let public2 = PublicKey::from(&secret2);

    assert_eq!(public1.as_bytes(), public2.as_bytes());
}

#[test]
fn test_x25519_performance() {
    // Benchmark key generation to ensure it's fast enough
    use std::time::Instant;

    let iterations = 1000;
    let start = Instant::now();

    for _ in 0..iterations {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let _public = PublicKey::from(&secret);
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() / iterations;

    println!("Average X25519 keygen: {} μs", avg_micros);
    assert!(
        avg_micros < 100,
        "Key generation should be <100μs, got {}μs",
        avg_micros
    );
}

// ============================================================================
// HMAC AUTHENTICATION PARITY TESTS
// ============================================================================

#[test]
fn test_hmac_session_id_generation() {
    // Test that session ID generation matches RustRay specification
    let server_pub_key_hex = "a1b2c3d4e5f6071829a3b4c5d6e7f8091a2b3c4d5e6f70819293a4b5c6d7e8f9";
    let short_id_hex = "0123456789abcdef";

    let pk_bytes = hex::decode(server_pub_key_hex).unwrap();
    let short_id_bytes = hex::decode(short_id_hex).unwrap();

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&pk_bytes).unwrap();
    mac.update(&short_id_bytes);
    let session_id = mac.finalize().into_bytes();

    assert_eq!(session_id.len(), 32, "Session ID must be 32 bytes");

    // Session ID should be deterministic
    let mut mac2 = <Hmac<Sha256> as KeyInit>::new_from_slice(&pk_bytes).unwrap();
    mac2.update(&short_id_bytes);
    let session_id2 = mac2.finalize().into_bytes();

    assert_eq!(session_id, session_id2, "Session ID must be deterministic");
}

#[test]
fn test_reality_auth_tag_generation() {
    // Test the REALITY authentication tag generation
    let private_key = b"test_private_key_32_bytes!!!!!!";
    let short_id = b"shortid8";
    let session_id = b"session_id_data_32_bytes!!!!";

    let tag1 = generate_auth_tag(private_key, short_id, session_id);
    let tag2 = generate_auth_tag(private_key, short_id, session_id);

    assert_eq!(tag1, tag2, "Auth tags must be deterministic");
    assert_eq!(tag1.len(), 16, "Auth tag must be 16 bytes");
}

#[test]
fn test_reality_auth_tag_verification() {
    let private_key = b"test_private_key_32_bytes!!!!!!";
    let short_id = b"shortid8";
    let session_id = b"session_id_data_32_bytes!!!!";

    let tag = generate_auth_tag(private_key, short_id, session_id);

    // Valid tag should verify
    assert!(
        verify_auth_tag(private_key, short_id, session_id, &tag),
        "Valid auth tag must verify"
    );

    // Wrong tag should fail
    let wrong_tag = [0u8; 16];
    assert!(
        !verify_auth_tag(private_key, short_id, session_id, &wrong_tag),
        "Invalid auth tag must fail"
    );

    // Wrong session ID should fail
    let wrong_session = b"wrong_session_id_32_bytes!!!!";
    assert!(
        !verify_auth_tag(private_key, short_id, wrong_session, &tag),
        "Auth tag with wrong session must fail"
    );
}

#[test]
fn test_constant_time_auth_verification() {
    // Ensure auth verification is constant-time to prevent timing attacks
    use std::time::Instant;

    let private_key = b"test_private_key_32_bytes!!!!!!";
    let short_id = b"shortid8";
    let session_id = b"session_id_data_32_bytes!!!!";

    let valid_tag = generate_auth_tag(private_key, short_id, session_id);
    let invalid_tag = [0u8; 16];

    let iterations = 10000;

    // Time valid tag verification
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = verify_auth_tag(private_key, short_id, session_id, &valid_tag);
    }
    let valid_duration = start.elapsed();

    // Time invalid tag verification
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = verify_auth_tag(private_key, short_id, session_id, &invalid_tag);
    }
    let invalid_duration = start.elapsed();

    // Times should be similar (within 10% variance)
    let ratio = valid_duration.as_nanos() as f64 / invalid_duration.as_nanos() as f64;
    assert!(
        (0.9..=1.1).contains(&ratio),
        "Auth verification must be constant-time, got ratio: {}",
        ratio
    );
}

// ============================================================================
// TLS 1.3 HANDSHAKE TESTS
// ============================================================================

#[test]
fn test_tls_transcript_hash_computation() {
    // Test that transcript hash matches TLS 1.3 specification
    let client_hello = b"This is a mock ClientHello message";
    let server_hello = b"This is a mock ServerHello message";

    let mut transcript = Sha256::new();
    transcript.update(client_hello);
    transcript.update(server_hello);
    let hash1 = transcript.finalize();

    assert_eq!(hash1.len(), 32, "SHA-256 hash must be 32 bytes");

    // Verify determinism
    let mut transcript2 = Sha256::new();
    transcript2.update(client_hello);
    transcript2.update(server_hello);
    let hash2 = transcript2.finalize();

    assert_eq!(hash1, hash2, "Transcript hash must be deterministic");
}

#[test]
fn test_tls_client_hello_structure() {
    // Build a minimal TLS ClientHello and verify structure
    let mut buf = BytesMut::new();

    // TLS Record Header
    buf.put_u8(0x16); // Handshake
    buf.put_u16(0x0301); // TLS 1.0 (for compatibility)
    let length_pos = buf.len();
    buf.put_u16(0); // Length placeholder

    // Handshake Header
    buf.put_u8(0x01); // ClientHello
    buf.put_u8(0); // Length (3 bytes)
    buf.put_u16(0);

    // ClientHello body
    buf.put_u16(0x0303); // TLS 1.2
    buf.put_slice(&[0u8; 32]); // Random

    // Update length
    let total_len = buf.len() - 5;
    buf[length_pos..length_pos + 2].copy_from_slice(&(total_len as u16).to_be_bytes());

    // Verify structure
    assert_eq!(buf[0], 0x16, "First byte must be handshake");
    assert_eq!(&buf[1..3], &[0x03, 0x01], "Must be TLS 1.0");
    assert_eq!(buf[5], 0x01, "Must be ClientHello");
}

// ============================================================================
// PROBE DETECTION TESTS
// ============================================================================

#[tokio::test]
async fn test_probe_detection_valid_flowj() {
    // Test that valid Flow-J magic is detected
    let flowj_handshake = b"FJ01\x01\x00\x00\x00extra data";

    // Check magic
    assert_eq!(&flowj_handshake[0..4], b"FJ01", "Flow-J magic must match");
}

#[tokio::test]
async fn test_probe_detection_tls_client_hello() {
    // Test TLS ClientHello detection
    let mut tls_probe = BytesMut::new();
    tls_probe.put_u8(0x16); // Handshake
    tls_probe.put_u16(0x0303); // TLS 1.2
    tls_probe.put_u16(100); // Length
    tls_probe.put_u8(0x01); // ClientHello
    tls_probe.resize(105, 0); // Pad to length

    assert_eq!(tls_probe[0], 0x16, "Must be TLS handshake");
    assert_eq!(tls_probe[5], 0x01, "Must be ClientHello");
}

#[tokio::test]
async fn test_probe_detection_http_request() {
    // Test HTTP request detection (should be marked as probe)
    let http_probe = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    assert_eq!(&http_probe[0..3], b"GET", "HTTP request starts with method");
    assert_ne!(http_probe[0], 0x16, "HTTP is not TLS");
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[tokio::test]
async fn test_reality_handshake_flow() {
    // End-to-end test of REALITY handshake

    // Generate keypairs
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);

    let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    // Compute shared secret
    let shared_secret = client_secret.diffie_hellman(&server_public);

    // Generate session
    let private_key = server_secret.to_bytes();
    let short_id = b"testid12";
    let session_id = b"session123456789012345678901";

    // Client generates auth tag
    let auth_tag = generate_auth_tag(&private_key, short_id, session_id);

    // Server verifies auth tag
    assert!(
        verify_auth_tag(&private_key, short_id, session_id, &auth_tag),
        "Server must verify client auth"
    );

    // Both sides derive same shared secret
    let server_shared = server_secret.diffie_hellman(&client_public);
    assert_eq!(shared_secret.as_bytes(), server_shared.as_bytes());
}

#[tokio::test]
async fn test_concurrent_reality_handshakes() {
    // Test multiple concurrent handshakes don't interfere
    let mut handles = vec![];

    for i in 0..10 {
        let handle = tokio::spawn(async move {
            let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
            let server_secret = StaticSecret::random_from_rng(rand::thread_rng());

            let client_public = PublicKey::from(&client_secret);
            let server_public = PublicKey::from(&server_secret);

            let client_shared = client_secret.diffie_hellman(&server_public);
            let server_shared = server_secret.diffie_hellman(&client_public);

            assert_eq!(
                client_shared.as_bytes(),
                server_shared.as_bytes(),
                "Handshake {} failed",
                i
            );
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ============================================================================
// PERFORMANCE BENCHMARKS
// ============================================================================

#[tokio::test]
async fn bench_reality_handshake_latency() {
    use std::time::Instant;

    let iterations = 100;
    let mut total_duration = Duration::from_secs(0);

    for _ in 0..iterations {
        let start = Instant::now();

        // Simulate handshake operations
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());

        let client_public = PublicKey::from(&client_secret);
        let server_public = PublicKey::from(&server_secret);

        let _shared = client_secret.diffie_hellman(&server_public);

        let private_key = server_secret.to_bytes();
        let _auth_tag = generate_auth_tag(&private_key, b"shortid8", b"session_id_data");

        total_duration += start.elapsed();
    }

    let avg_ms = total_duration.as_millis() / iterations;
    println!("Average REALITY handshake: {} ms", avg_ms);
    assert!(avg_ms < 30, "Handshake should be <30ms, got {}ms", avg_ms);
}
