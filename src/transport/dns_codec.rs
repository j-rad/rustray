// src/transport/dns_codec.rs
//! DNS Base32 Codec
//!
//! Encodes arbitrary binary data into DNS-safe Base32 labels for tunneling.
//! Each DNS label is max 63 bytes; full domain name max 253 bytes.
//! Uses zstd compression before encoding to maximize throughput.

use bytes::{BytesMut, BufMut};
use std::io::{self, Error, ErrorKind};

/// Maximum bytes per DNS label
const MAX_LABEL_LEN: usize = 63;
/// Maximum total domain name length
const MAX_DOMAIN_LEN: usize = 253;
/// Base32 alphabet (RFC 4648, lowercase for DNS compatibility)
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode binary data to lowercase Base32 (RFC 4648 without padding).
pub fn base32_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

/// Decode lowercase Base32 (RFC 4648 without padding) to binary.
pub fn base32_decode(encoded: &str) -> io::Result<Vec<u8>> {
    let mut result = Vec::with_capacity(encoded.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for ch in encoded.chars() {
        let value = match ch {
            'a'..='z' => ch as u8 - b'a',
            'A'..='Z' => ch as u8 - b'A',
            '2'..='7' => ch as u8 - b'2' + 26,
            '.' | '-' => continue, // Skip DNS separators
            _ => return Err(Error::new(ErrorKind::InvalidData, format!("Invalid Base32 char: {}", ch))),
        };

        buffer = (buffer << 5) | value as u64;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            result.push((buffer >> bits_left) as u8);
        }
    }

    Ok(result)
}

/// Compress data with zstd then Base32-encode into DNS labels.
pub fn encode_dns_payload(data: &[u8], base_domain: &str) -> io::Result<Vec<u8>> {
    // 1. Compress
    let compressed = zstd::encode_all(data, 3)
        .map_err(Error::other)?;

    // 2. Base32 encode
    let encoded = base32_encode(&compressed);

    // 3. Build DNS query name: split into labels, append base domain
    let available_len = MAX_DOMAIN_LEN
        .saturating_sub(base_domain.len())
        .saturating_sub(2); // dots

    if encoded.len() > available_len {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Encoded payload too large for DNS: {} bytes (max {})",
                encoded.len(),
                available_len
            ),
        ));
    }

    let mut packet = Vec::with_capacity(512);

    // Split encoded data into DNS labels (max 63 chars each)
    for chunk in encoded.as_bytes().chunks(MAX_LABEL_LEN) {
        packet.push(chunk.len() as u8);
        packet.extend_from_slice(chunk);
    }

    // Append base domain labels
    for label in base_domain.split('.') {
        if label.is_empty() {
            continue;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }

    // Root label
    packet.push(0);

    Ok(packet)
}

/// Decode DNS query name back into binary payload.
/// Strips the base_domain suffix and decodes the remaining labels.
pub fn decode_dns_payload(dns_name: &[u8], base_domain: &str) -> io::Result<Vec<u8>> {
    // 1. Parse labels from wire format
    let mut labels = Vec::new();
    let mut offset = 0;

    while offset < dns_name.len() {
        let len = dns_name[offset] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            // DNS pointer — skip
            break;
        }
        offset += 1;
        if offset + len > dns_name.len() {
            return Err(Error::new(ErrorKind::InvalidData, "Truncated DNS label"));
        }
        labels.push(&dns_name[offset..offset + len]);
        offset += len;
    }

    // 2. Strip base domain labels from the end
    let domain_labels: Vec<&str> = base_domain.split('.').filter(|l| !l.is_empty()).collect();
    let data_label_count = labels.len().saturating_sub(domain_labels.len());

    // 3. Concatenate data labels
    let mut encoded = String::new();
    for label in &labels[..data_label_count] {
        let s = std::str::from_utf8(label)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Non-UTF8 DNS label"))?;
        encoded.push_str(s);
    }

    // 4. Base32 decode
    let compressed = base32_decode(&encoded)?;

    // 5. Decompress
    let decompressed = zstd::decode_all(compressed.as_slice())
        .map_err(|e| Error::other(format!("zstd decompress failed: {}", e)))?;

    Ok(decompressed)
}

/// Build a complete DNS query packet with the encoded payload as the QNAME.
pub fn build_dns_query(data: &[u8], base_domain: &str, tx_id: u16) -> io::Result<Vec<u8>> {
    let qname = encode_dns_payload(data, base_domain)?;
    let mut packet = BytesMut::with_capacity(12 + qname.len() + 4);

    // DNS Header
    packet.put_u16(tx_id);        // Transaction ID
    packet.put_u16(0x0100);       // Flags: standard query, RD=1
    packet.put_u16(1);            // QDCOUNT
    packet.put_u16(0);            // ANCOUNT
    packet.put_u16(0);            // NSCOUNT
    packet.put_u16(0);            // ARCOUNT

    // Question section
    packet.extend_from_slice(&qname);
    packet.put_u16(16);           // QTYPE: TXT
    packet.put_u16(1);            // QCLASS: IN

    Ok(packet.to_vec())
}

/// Build a DNS response packet carrying data in a TXT record.
pub fn build_dns_response(data: &[u8], tx_id: u16, qname: &[u8]) -> Vec<u8> {
    let mut packet = BytesMut::with_capacity(128 + data.len());

    // DNS Header
    packet.put_u16(tx_id);
    packet.put_u16(0x8180);       // Flags: response, RD=1, RA=1
    packet.put_u16(1);            // QDCOUNT
    packet.put_u16(1);            // ANCOUNT
    packet.put_u16(0);            // NSCOUNT
    packet.put_u16(0);            // ARCOUNT

    // Question (echo)
    packet.extend_from_slice(qname);
    packet.put_u16(16);           // QTYPE: TXT
    packet.put_u16(1);            // QCLASS: IN

    // Answer: pointer to QNAME
    packet.put_u16(0xC00C);       // Name pointer to offset 12
    packet.put_u16(16);           // TYPE: TXT
    packet.put_u16(1);            // CLASS: IN
    packet.put_u32(60);           // TTL

    // RDATA: TXT records (each segment max 255 bytes)
    let mut rdata = BytesMut::new();
    for chunk in data.chunks(255) {
        rdata.put_u8(chunk.len() as u8);
        rdata.extend_from_slice(chunk);
    }

    packet.put_u16(rdata.len() as u16); // RDLENGTH
    packet.extend_from_slice(&rdata);

    packet.to_vec()
}
