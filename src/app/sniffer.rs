use bytes::BytesMut;
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, PartialEq)]
pub enum SniffResult {
    Http {
        host: Option<String>,
    },
    Tls {
        domain: Option<String>,
    },
    /// Domain resolved from FakeDNS reverse mapping
    ResolvedDomain {
        domain: String,
    },
    Unknown,
}

pub struct Sniffer;

impl Sniffer {
    /// Sniff with FakeDNS awareness
    /// If destination IP is in FakeDNS pool, resolve domain from reverse mapping
    pub async fn sniff_with_fakedns<R: AsyncRead + Unpin>(
        stream: &mut R,
        dest_ip: IpAddr,
        fakedns: Option<&crate::app::dns::fakedns::FakeDns>,
        max_peek_size: usize,
    ) -> io::Result<(SniffResult, BytesMut)> {
        // 1. Check FakeDNS first
        if let Some(fake) = fakedns {
            if let Some(domain) = fake.get_domain_from_ip(dest_ip) {
                return Ok((SniffResult::ResolvedDomain { domain }, BytesMut::new()));
            }
        }

        // 2. Fallback to traffic sniffing
        Self::sniff(stream, max_peek_size).await
    }

    /// Peeks bits of the stream to determine the protocol.
    /// Reads up to `max_peek_size` (or until a decision can be made).
    /// Returns the result and the bytes read (which must be re-combined with the stream).
    pub async fn sniff<R: AsyncRead + Unpin>(
        stream: &mut R,
        max_peek_size: usize,
    ) -> io::Result<(SniffResult, BytesMut)> {
        let mut buffer = BytesMut::with_capacity(max_peek_size);

        // Initial read. Usually the first packet contains enough info.
        let n = stream.read_buf(&mut buffer).await?;

        if n == 0 {
            return Ok((SniffResult::Unknown, buffer));
        }

        // 1. Try TLS
        if let Some(domain) = Self::sniff_tls(&buffer) {
            return Ok((
                SniffResult::Tls {
                    domain: Some(domain),
                },
                buffer,
            ));
        }

        // 2. Try HTTP
        if let Some(host) = Self::sniff_http(&buffer) {
            return Ok((SniffResult::Http { host: Some(host) }, buffer));
        }

        Ok((SniffResult::Unknown, buffer))
    }

    fn sniff_tls(buf: &[u8]) -> Option<String> {
        // Basic TLS ClientHello validation
        if buf.len() < 5 {
            return None;
        }
        // ContentType: Handshake (22)
        if buf[0] != 0x16 {
            return None;
        }
        // Version: 3.x (TLS 1.0=3.1, 1.1=3.2, 1.2=3.3)
        if buf[1] != 0x03 {
            return None;
        }

        let record_len = ((buf[3] as u16) << 8) | (buf[4] as u16);
        if buf.len() < (5 + record_len as usize) {
            // Incomplete record, but we might have enough for SNI.
        }

        // Handshake Type: ClientHello (1)
        if buf.len() < 6 || buf[5] != 0x01 {
            return None;
        }

        let mut pos = 6;
        // Handshake Length (3 bytes)
        pos += 3;
        // Client Version (2 bytes)
        pos += 2;
        // Random (32 bytes)
        pos += 32;

        // Session ID length
        if pos >= buf.len() {
            return None;
        }
        let session_id_len = buf[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher Suites length
        if pos + 1 >= buf.len() {
            return None;
        }
        let cipher_suites_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
        pos += 2 + cipher_suites_len;

        // Compression Methods length
        if pos >= buf.len() {
            return None;
        }
        let compression_methods_len = buf[pos] as usize;
        pos += 1 + compression_methods_len;

        // Extensions Length
        if pos + 1 >= buf.len() {
            return None;
        }
        let extensions_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
        pos += 2;

        // Parse Extensions
        let end = pos + extensions_len;
        if end > buf.len() {
            return None;
        }

        while pos + 4 <= end {
            let ext_type = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
            let ext_len = ((buf[pos + 2] as usize) << 8) | (buf[pos + 3] as usize);
            pos += 4;

            if pos + ext_len > end {
                break;
            }

            // SNI Extension Type is 0x0000
            if ext_type == 0x0000 {
                // SNI List Length (2 bytes)
                if ext_len < 2 {
                    return None;
                }
                let list_len = ((buf[pos] as usize) << 8) | (buf[pos + 1] as usize);
                let mut p = pos + 2;
                let list_end = p + list_len;

                while p + 3 <= list_end {
                    let name_type = buf[p];
                    let name_len = ((buf[p + 1] as usize) << 8) | (buf[p + 2] as usize);
                    p += 3;

                    if p + name_len > list_end {
                        break;
                    }

                    if name_type == 0x00 {
                        // Host Name
                        if let Ok(sni) = std::str::from_utf8(&buf[p..p + name_len]) {
                            return Some(sni.to_string());
                        }
                    }
                    p += name_len;
                }
            }

            pos += ext_len;
        }

        None
    }

    fn sniff_http(buf: &[u8]) -> Option<String> {
        let s = match std::str::from_utf8(buf) {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Check for common HTTP methods
        let methods = [
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH ",
        ];
        if !methods.iter().any(|m| s.starts_with(m)) {
            return None;
        }

        // Naive Host header extraction
        for line in s.lines() {
            let trim = line.trim();
            if trim.to_ascii_lowercase().starts_with("host:") {
                return Some(trim[5..].trim().to_string());
            }
        }

        None
    }
}
