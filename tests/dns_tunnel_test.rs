// tests/dns_tunnel_test.rs
//! Integration tests for the DNS Base32 codec and tunnel.

use rustray::transport::dns_codec::{base32_encode, base32_decode, encode_dns_payload, decode_dns_payload, build_dns_query, build_dns_response};

#[test]
fn test_base32_roundtrip() {
    let test_data = b"Hello, RustRay DNS Tunnel!";
    let encoded = base32_encode(test_data);
    let decoded = base32_decode(&encoded).unwrap();
    assert_eq!(decoded, test_data, "Base32 roundtrip failed");
}

#[test]
fn test_base32_empty() {
    let encoded = base32_encode(b"");
    assert!(encoded.is_empty());
    let decoded = base32_decode("").unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn test_base32_various_lengths() {
    for len in 1..=256 {
        let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let encoded = base32_encode(&data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data, "Roundtrip failed for length {}", len);
    }
}

#[test]
fn test_dns_payload_encode_decode() {
    let data = b"Test payload for DNS tunneling";
    let domain = "t.example.com";
    
    let encoded = encode_dns_payload(data, domain).unwrap();
    
    // Verify it starts with label length bytes
    assert!(encoded[0] > 0 && encoded[0] <= 63, "First label too long");
    
    // Decode it back
    let decoded = decode_dns_payload(&encoded, domain).unwrap();
    assert_eq!(decoded, data, "DNS payload roundtrip failed");
}

#[test]
fn test_dns_query_packet_structure() {
    let data = b"short";
    let domain = "tunnel.test.com";
    let tx_id: u16 = 0xABCD;
    
    let packet = build_dns_query(data, domain, tx_id).unwrap();
    
    // Verify DNS header
    assert_eq!(packet[0], 0xAB, "TX ID high byte");
    assert_eq!(packet[1], 0xCD, "TX ID low byte");
    assert_eq!(packet[2], 0x01, "Flags high byte (RD=1)");
    assert_eq!(packet[3], 0x00, "Flags low byte");
    
    // QDCOUNT = 1
    assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1);
    // ANCOUNT = 0
    assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);
}

#[test]
fn test_dns_response_roundtrip() {
    let payload = b"Response data for tunnel";
    let tx_id: u16 = 0x1234;
    let qname = b"\x04test\x07example\x03com\x00";
    
    let response = build_dns_response(payload, tx_id, qname);
    
    // Verify header
    assert_eq!(response[0], 0x12);
    assert_eq!(response[1], 0x34);
    // Flags should be 0x8180 (response)
    assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8180);
    
    // Packet should contain the payload in TXT record
    assert!(response.len() > 12 + qname.len() + payload.len());
}

#[test]
fn test_dns_payload_too_large() {
    // Create data that's too large for a single DNS query
    let data = vec![0xAA; 500]; // Way too large after Base32 + zstd
    let domain = "a.very.long.domain.name.that.eats.space.example.com";
    
    let result = encode_dns_payload(&data, domain);
    // This might succeed or fail depending on compression ratio
    // Just ensure it doesn't panic
    match result {
        Ok(encoded) => {
            // Verify total length is reasonable
            assert!(encoded.len() < 260, "Encoded payload too large for DNS");
        }
        Err(e) => {
            assert!(e.to_string().contains("too large"), "Expected 'too large' error");
        }
    }
}
