// src/transport/tls_mimicry.rs
//! Phase 14 — Protocol Mimicry Engine
//!
//! Generates application-layer "ghost headers" that make proxy traffic
//! indistinguishable from legitimate database, API, or IoT protocols
//! when inspected by DPI systems.

use bytes::{BufMut, BytesMut};
use rand::Rng;

// ─────────────────────────────────────────────────────────────────────────────
// Protocol Ghost Header Types
// ─────────────────────────────────────────────────────────────────────────────

/// Supported ghost header protocol types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GhostProtocol {
    /// PostgreSQL wire protocol (Frontend/Backend message format).
    Postgres,
    /// Redis RESP3 protocol.
    Redis,
    /// MongoDB OP_MSG wire protocol.
    Mongo,
    /// MySQL client/server protocol.
    MySql,
    /// MQTT 3.1.1 CONNECT packet.
    MqttConnect,
    /// HTTP/2 connection preface + SETTINGS frame.
    Http2Preface,
    /// PostgreSQL SSLRequest (pre-TLS handshake).
    PsqlSslRequest,
    /// MySQL SSLRequest capability flag packet.
    MysqlSslRequest,
    /// MongoDB mongosh 2.x hello command.
    MongoshHello,
    /// Redis 7.x CLUSTER INFO command.
    RedisClusterInfo,
    /// Windows Update HTTP/2 HEADERS frame.
    WindowsUpdate,
    /// macOS Software Update HTTP/1.1 request.
    MacOsSoftwareUpdate,
    /// Debian APT-HTTP InRelease request.
    AptTransport,
    /// curl 8.x HTTP GET probe.
    CurlHttpGet,
    /// wget 1.24 HTTP GET probe.
    WgetHttpGet,
    /// HTTP/1.1 Keep-Alive probe.
    Http1KeepAlive,
    /// TLS False Start probe.
    TlsFalseStart,
    /// Scraped domestic site decoy headers.
    DomesticDecoy(String),
}

impl GhostProtocol {
    /// Returns true if this protocol header must be sent BEFORE the TLS handshake.
    pub fn is_pre_tls(&self) -> bool {
        match self {
            Self::PsqlSslRequest | Self::MysqlSslRequest => true,
            _ => false,
        }
    }

    /// Returns true if this protocol header should be sent as the first encrypted payload AFTER the TLS handshake.
    pub fn is_post_tls(&self) -> bool {
        match self {
            Self::Http2Preface
            | Self::Http1KeepAlive
            | Self::TlsFalseStart
            | Self::MongoshHello
            | Self::RedisClusterInfo
            | Self::WindowsUpdate
            | Self::MacOsSoftwareUpdate
            | Self::AptTransport
            | Self::CurlHttpGet
            | Self::WgetHttpGet
            | Self::DomesticDecoy(_) => true,
            _ => false,
        }
    }
}

/// A generated ghost header ready for wire injection.
#[derive(Debug, Clone)]
pub struct GhostHeader {
    pub protocol: GhostProtocol,
    pub bytes: Vec<u8>,
    pub description: &'static str,
}

// ─────────────────────────────────────────────────────────────────────────────
// Ghost Header Generator
// ─────────────────────────────────────────────────────────────────────────────

/// Generates protocol-specific ghost headers for DPI evasion.
pub struct GhostHeaderGenerator;

impl GhostHeaderGenerator {
    /// Generate a ghost header for the specified protocol.
    pub fn generate(protocol: GhostProtocol, sni: Option<&str>) -> GhostHeader {
        match protocol {
            GhostProtocol::Postgres => Self::postgres_startup(),
            GhostProtocol::Redis => Self::redis_auth(),
            GhostProtocol::Mongo => Self::mongo_op_msg(),
            GhostProtocol::MySql => Self::mysql_handshake(),
            GhostProtocol::MqttConnect => Self::mqtt_connect(),
            GhostProtocol::Http2Preface => Self::http2_preface(),
            GhostProtocol::PsqlSslRequest => Self::psql_ssl_request(),
            GhostProtocol::MysqlSslRequest => Self::mysql_ssl_request(),
            GhostProtocol::MongoshHello => Self::mongosh_hello(),
            GhostProtocol::RedisClusterInfo => Self::redis_cluster_info(),
            GhostProtocol::WindowsUpdate => Self::windows_update(),
            GhostProtocol::MacOsSoftwareUpdate => Self::macos_software_update(),
            GhostProtocol::AptTransport => Self::apt_transport(),
            GhostProtocol::CurlHttpGet => Self::curl_http_get(sni),
            GhostProtocol::WgetHttpGet => Self::wget_http_get(sni),
            GhostProtocol::Http1KeepAlive => Self::http1_keep_alive(sni),
            GhostProtocol::TlsFalseStart => Self::tls_false_start(sni),
            GhostProtocol::DomesticDecoy(ref headers) => Self::domestic_decoy(headers),
        }
    }

    /// Generate a random ghost header from all available protocols.
    pub fn random(sni: Option<&str>) -> GhostHeader {
        let protocols = [
            GhostProtocol::Postgres,
            GhostProtocol::Redis,
            GhostProtocol::Mongo,
            GhostProtocol::MySql,
            GhostProtocol::MqttConnect,
            GhostProtocol::Http2Preface,
            GhostProtocol::PsqlSslRequest,
            GhostProtocol::WindowsUpdate,
            GhostProtocol::CurlHttpGet,
        ];
        let idx = rand::thread_rng().gen_range(0..protocols.len());
        Self::generate(protocols[idx].clone(), sni)
    }

    /// PostgreSQL StartupMessage (Protocol 3.0).
    fn postgres_startup() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(64);
        let user = "pgadmin";
        let database = "production";

        // Length placeholder
        buf.put_i32(0);
        // Protocol version 3.0
        buf.put_i32(196608);
        // Parameters
        buf.put_slice(b"user\0");
        buf.put_slice(user.as_bytes());
        buf.put_u8(0);
        buf.put_slice(b"database\0");
        buf.put_slice(database.as_bytes());
        buf.put_u8(0);
        buf.put_slice(b"application_name\0");
        buf.put_slice(b"psql");
        buf.put_u8(0);
        buf.put_slice(b"client_encoding\0");
        buf.put_slice(b"UTF8");
        buf.put_u8(0);
        buf.put_u8(0); // Terminator

        let len = buf.len() as i32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());

        GhostHeader {
            protocol: GhostProtocol::Postgres,
            bytes: buf.to_vec(),
            description: "PostgreSQL 3.0 StartupMessage",
        }
    }

    /// Redis RESP3 AUTH command.
    fn redis_auth() -> GhostHeader {
        let cmd = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n";
        GhostHeader {
            protocol: GhostProtocol::Redis,
            bytes: cmd.to_vec(),
            description: "Redis RESP AUTH command",
        }
    }

    /// MongoDB OP_MSG (opcode 2013) isMaster command.
    fn mongo_op_msg() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(128);

        // BSON document for { isMaster: 1, $db: "admin" }
        let bson_doc = Self::bson_is_master();

        // MsgHeader
        let request_id = rand::thread_rng().r#gen::<i32>();
        let msg_len = 16 + 4 + 1 + bson_doc.len(); // header + flagBits + kind + doc

        buf.put_i32_le(msg_len as i32); // messageLength
        buf.put_i32_le(request_id); // requestID
        buf.put_i32_le(0); // responseTo
        buf.put_i32_le(2013); // opCode: OP_MSG

        // OP_MSG body
        buf.put_u32_le(0); // flagBits
        buf.put_u8(0); // kind: body
        buf.put_slice(&bson_doc);

        GhostHeader {
            protocol: GhostProtocol::Mongo,
            bytes: buf.to_vec(),
            description: "MongoDB OP_MSG isMaster",
        }
    }

    /// Build a minimal BSON document: { isMaster: 1, $db: "admin" }
    fn bson_is_master() -> Vec<u8> {
        let mut doc = BytesMut::with_capacity(64);
        doc.put_i32(0); // doc length placeholder

        // isMaster: 1 (int32, type 0x10)
        doc.put_u8(0x10);
        doc.put_slice(b"isMaster\0");
        doc.put_i32(1);

        // $db: "admin" (string, type 0x02)
        doc.put_u8(0x02);
        doc.put_slice(b"$db\0");
        let db = b"admin";
        doc.put_i32((db.len() + 1) as i32);
        doc.put_slice(db);
        doc.put_u8(0);

        doc.put_u8(0); // document terminator

        let len = doc.len() as i32;
        doc[0..4].copy_from_slice(&len.to_le_bytes());
        doc.to_vec()
    }

    /// MySQL server handshake greeting (v10).
    fn mysql_handshake() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(128);
        let mut rng = rand::thread_rng();

        // Packet header (3 bytes length + 1 byte sequence)
        let payload_start = buf.len();
        buf.put_slice(&[0, 0, 0]); // length placeholder
        buf.put_u8(0); // sequence id

        // Protocol version
        buf.put_u8(10);

        // Server version string
        buf.put_slice(b"8.0.36\0");

        // Connection ID
        buf.put_u32_le(rng.r#gen());

        // Auth plugin data part 1 (8 bytes)
        let mut salt1 = [0u8; 8];
        rng.fill(&mut salt1);
        buf.put_slice(&salt1);

        // Filler
        buf.put_u8(0);

        // Capability flags (lower 2 bytes)
        buf.put_u16_le(0xFFFF);

        // Character set (utf8mb4)
        buf.put_u8(255);

        // Status flags
        buf.put_u16_le(0x0002); // SERVER_STATUS_AUTOCOMMIT

        // Capability flags (upper 2 bytes)
        buf.put_u16_le(0xC1FF);

        // Length of auth plugin data
        buf.put_u8(21);

        // Reserved (10 zeros)
        buf.put_slice(&[0u8; 10]);

        // Auth plugin data part 2 (13 bytes including null)
        let mut salt2 = [0u8; 12];
        rng.fill(&mut salt2);
        buf.put_slice(&salt2);
        buf.put_u8(0);

        // Auth plugin name
        buf.put_slice(b"caching_sha2_password\0");

        // Fix packet length
        let payload_len = buf.len() - payload_start - 4;
        buf[payload_start] = (payload_len & 0xFF) as u8;
        buf[payload_start + 1] = ((payload_len >> 8) & 0xFF) as u8;
        buf[payload_start + 2] = ((payload_len >> 16) & 0xFF) as u8;

        GhostHeader {
            protocol: GhostProtocol::MySql,
            bytes: buf.to_vec(),
            description: "MySQL 8.0.36 Server Greeting",
        }
    }

    /// MQTT 3.1.1 CONNECT packet.
    fn mqtt_connect() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(64);
        let client_id = format!("sensor-{:04x}", rand::thread_rng().r#gen::<u16>());

        // Fixed header: CONNECT (0x10) + remaining length
        let variable_len = 10 + 2 + client_id.len(); // var header + client_id
        buf.put_u8(0x10);
        Self::encode_mqtt_remaining_length(&mut buf, variable_len);

        // Variable header
        buf.put_u16(4); // Protocol name length
        buf.put_slice(b"MQTT"); // Protocol name
        buf.put_u8(4); // Protocol level (3.1.1)
        buf.put_u8(0x02); // Connect flags (Clean Session)
        buf.put_u16(60); // Keep alive (60 seconds)

        // Payload: Client ID
        buf.put_u16(client_id.len() as u16);
        buf.put_slice(client_id.as_bytes());

        GhostHeader {
            protocol: GhostProtocol::MqttConnect,
            bytes: buf.to_vec(),
            description: "MQTT 3.1.1 CONNECT",
        }
    }

    /// HTTP/2 connection preface + initial SETTINGS frame.
    fn http2_preface() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(64);

        // HTTP/2 connection preface (24 bytes magic)
        buf.put_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // SETTINGS frame (type=0x04, no flags, stream 0)
        // Settings: HEADER_TABLE_SIZE=4096, MAX_CONCURRENT_STREAMS=100,
        //           INITIAL_WINDOW_SIZE=65535, MAX_FRAME_SIZE=16384
        let settings_payload_len = 4 * 6; // 4 settings × 6 bytes each
        buf.put_slice(&(settings_payload_len as u32).to_be_bytes()[1..]); // 3-byte length
        buf.put_u8(0x04); // type: SETTINGS
        buf.put_u8(0x00); // flags: none
        buf.put_u32(0); // stream ID: 0

        // HEADER_TABLE_SIZE (0x01) = 4096
        buf.put_u16(0x0001);
        buf.put_u32(4096);
        // MAX_CONCURRENT_STREAMS (0x03) = 100
        buf.put_u16(0x0003);
        buf.put_u32(100);
        // INITIAL_WINDOW_SIZE (0x04) = 65535
        buf.put_u16(0x0004);
        buf.put_u32(65535);
        // MAX_FRAME_SIZE (0x05) = 16384
        buf.put_u16(0x0005);
        buf.put_u32(16384);

        GhostHeader {
            protocol: GhostProtocol::Http2Preface,
            bytes: buf.to_vec(),
            description: "HTTP/2 Connection Preface + SETTINGS",
        }
    }

    /// Encode MQTT remaining length (variable-length encoding).
    fn encode_mqtt_remaining_length(buf: &mut BytesMut, mut len: usize) {
        loop {
            let mut byte = (len % 128) as u8;
            len /= 128;
            if len > 0 {
                byte |= 0x80;
            }
            buf.put_u8(byte);
            if len == 0 {
                break;
            }
        }
    }

    /// PostgreSQL SSLRequest (fixed 8-byte packet).
    fn http1_keep_alive(sni: Option<&str>) -> GhostHeader {
        let host = sni.unwrap_or("www.bing.com");
        let bytes = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            host
        ).into_bytes();
        GhostHeader {
            protocol: GhostProtocol::Http1KeepAlive,
            bytes,
            description: "HTTP/1.1 Keep-Alive Probe",
        }
    }

    fn tls_false_start(_sni: Option<&str>) -> GhostHeader {
        use rand::RngCore;
        let mut bytes = vec![0x17, 0x03, 0x03, 0x00, 0x28]; // Record header
        let mut payload = vec![0u8; 40];
        rand::thread_rng().fill_bytes(&mut payload);
        bytes.extend(payload);

        GhostHeader {
            protocol: GhostProtocol::TlsFalseStart,
            bytes,
            description: "TLS 1.3 False Start Speculative Payload",
        }
    }

    fn psql_ssl_request() -> GhostHeader {
        GhostHeader {
            protocol: GhostProtocol::PsqlSslRequest,
            bytes: vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
            description: "PostgreSQL SSLRequest",
        }
    }

    /// MySQL SSLRequest capability flag packet (mimics mysql-connector-python).
    fn mysql_ssl_request() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(36);
        buf.put_slice(&[32, 0, 0, 1]); // Len=32, Seq=1
        buf.put_u32_le(0x00a28585); // Client capabilities (with SSL)
        buf.put_u32_le(16777215); // Max packet size
        buf.put_u8(255); // Charset (utf8mb4)
        buf.put_slice(&[0u8; 23]); // Reserved
        GhostHeader {
            protocol: GhostProtocol::MysqlSslRequest,
            bytes: buf.to_vec(),
            description: "MySQL SSLRequest Packet",
        }
    }

    /// MongoDB mongosh 2.x hello command.
    fn mongosh_hello() -> GhostHeader {
        let mut buf = BytesMut::with_capacity(128);
        let mut doc = BytesMut::new();
        doc.put_i32(0); // length placeholder
        doc.put_u8(0x10);
        doc.put_slice(b"hello\0");
        doc.put_i32(1);
        doc.put_u8(0x02);
        doc.put_slice(b"$db\0");
        doc.put_i32(6);
        doc.put_slice(b"admin\0");
        doc.put_u8(0x08);
        doc.put_slice(b"helloOk\0");
        doc.put_u8(1);
        doc.put_u8(0); // terminator
        let doc_len = doc.len() as i32;
        doc[0..4].copy_from_slice(&doc_len.to_le_bytes());

        buf.put_i32_le(16 + 5 + doc_len); // Total len
        buf.put_i32_le(rand::thread_rng().r#gen()); // RequestID
        buf.put_i32_le(0); // responseTo
        buf.put_i32_le(2013); // opCode OP_MSG
        buf.put_u32_le(0); // flagBits
        buf.put_u8(0); // kind body
        buf.put_slice(&doc);

        GhostHeader {
            protocol: GhostProtocol::MongoshHello,
            bytes: buf.to_vec(),
            description: "MongoDB mongosh hello",
        }
    }

    /// Redis 7.x CLUSTER INFO command.
    fn redis_cluster_info() -> GhostHeader {
        GhostHeader {
            protocol: GhostProtocol::RedisClusterInfo,
            bytes: b"*2\r\n$7\r\nCLUSTER\r\n$4\r\nINFO\r\n".to_vec(),
            description: "Redis CLUSTER INFO",
        }
    }

    /// Windows Update HTTP/2 HEADERS frame (pseudo-accurate).
    fn windows_update() -> GhostHeader {
        let mut buf = BytesMut::new();
        buf.put_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // SETTINGS
        buf.put_slice(&[0, 0, 6, 4, 0, 0, 0, 0, 0]);
        buf.put_u16(1);
        buf.put_u32(4096);
        // Minimal HEADERS frame for Windows Update agent
        buf.put_slice(&[0, 0, 20, 1, 5, 0, 0, 0, 1]);
        buf.put_slice(b"Windows-Update-Agent");
        GhostHeader {
            protocol: GhostProtocol::WindowsUpdate,
            bytes: buf.to_vec(),
            description: "Windows Update Agent Handshake",
        }
    }

    /// macOS Software Update HTTP/1.1 request.
    fn macos_software_update() -> GhostHeader {
        GhostHeader {
            protocol: GhostProtocol::MacOsSoftwareUpdate,
            bytes: b"GET /content/catalogs/others/index-15.sucatalog HTTP/1.1\r\nUser-Agent: softwareupdated/1.0\r\n\r\n".to_vec(),
            description: "macOS Software Update",
        }
    }

    /// Debian APT-HTTP InRelease request.
    fn apt_transport() -> GhostHeader {
        GhostHeader {
            protocol: GhostProtocol::AptTransport,
            bytes:
                b"GET /dists/noble/InRelease HTTP/1.1\r\nUser-Agent: Debian APT-HTTP/2.9.6\r\n\r\n"
                    .to_vec(),
            description: "Debian APT Transport",
        }
    }

    /// curl 8.x HTTP GET probe.
    fn curl_http_get(sni: Option<&str>) -> GhostHeader {
        let host = sni.unwrap_or("google.com");
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.9.1\r\nAccept: */*\r\n\r\n",
            host
        );
        GhostHeader {
            protocol: GhostProtocol::CurlHttpGet,
            bytes: req.into_bytes(),
            description: "curl 8.9.1 GET",
        }
    }

    /// wget 1.24 HTTP GET probe.
    fn wget_http_get(sni: Option<&str>) -> GhostHeader {
        let host = sni.unwrap_or("google.com");
        let req = format!(
            "GET / HTTP/1.1\r\nUser-Agent: Wget/1.24.5\r\nAccept: */*\r\nHost: {}\r\n\r\n",
            host
        );
        GhostHeader {
            protocol: GhostProtocol::WgetHttpGet,
            bytes: req.into_bytes(),
            description: "wget 1.24.5 GET",
        }
    }

    /// Custom domestic site decoy using scraped headers.
    fn domestic_decoy(headers: &str) -> GhostHeader {
        GhostHeader {
            protocol: GhostProtocol::DomesticDecoy(headers.to_string()),
            bytes: headers.as_bytes().to_vec(),
            description: "Domestic Site Decoy (Scraped)",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol Mimicry Wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps outgoing data with a protocol ghost header prefix.
///
/// On first write, prepends the ghost header to make the initial bytes
/// of the connection look like the target protocol's handshake.
pub struct MimicryWrapper {
    ghost: GhostHeader,
    header_sent: bool,
}

impl MimicryWrapper {
    /// Create a new wrapper with a specific protocol ghost.
    pub fn new(protocol: GhostProtocol, sni: Option<&str>) -> Self {
        Self {
            ghost: GhostHeaderGenerator::generate(protocol, sni),
            header_sent: false,
        }
    }

    /// Create a wrapper with a randomly selected protocol.
    pub fn random(sni: Option<&str>) -> Self {
        Self {
            ghost: GhostHeaderGenerator::random(sni),
            header_sent: false,
        }
    }

    /// Wrap a data buffer, prepending the ghost header on first call.
    pub fn wrap(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.header_sent {
            self.header_sent = true;
            let mut out = Vec::with_capacity(self.ghost.bytes.len() + data.len());
            out.extend_from_slice(&self.ghost.bytes);
            out.extend_from_slice(data);
            out
        } else {
            data.to_vec()
        }
    }

    /// Get the ghost header protocol type.
    pub fn protocol(&self) -> GhostProtocol {
        self.ghost.protocol.clone()
    }

    /// Check if the ghost header has been sent.
    pub fn is_active(&self) -> bool {
        self.header_sent
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_ghost_valid_startup() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::Postgres, None);
        assert!(ghost.bytes.len() >= 20);
        // First 4 bytes are the packet length (big-endian i32)
        let len = i32::from_be_bytes([
            ghost.bytes[0],
            ghost.bytes[1],
            ghost.bytes[2],
            ghost.bytes[3],
        ]);
        assert_eq!(len as usize, ghost.bytes.len());
        // Protocol version 3.0 at offset 4
        let version = i32::from_be_bytes([
            ghost.bytes[4],
            ghost.bytes[5],
            ghost.bytes[6],
            ghost.bytes[7],
        ]);
        assert_eq!(version, 196608);
    }

    #[test]
    fn test_redis_ghost_valid_resp() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::Redis, None);
        assert!(ghost.bytes.starts_with(b"*2\r\n"));
    }

    #[test]
    fn test_mongo_ghost_valid_op_msg() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::Mongo, None);
        assert!(ghost.bytes.len() >= 16);
        // opCode at offset 12-15 should be 2013 (OP_MSG)
        let opcode = i32::from_le_bytes([
            ghost.bytes[12],
            ghost.bytes[13],
            ghost.bytes[14],
            ghost.bytes[15],
        ]);
        assert_eq!(opcode, 2013);
    }

    #[test]
    fn test_mysql_ghost_valid_greeting() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::MySql, None);
        // Protocol version at offset 4 should be 10
        assert_eq!(ghost.bytes[4], 10);
        // Should contain version string "8.0.36"
        assert!(ghost.bytes.windows(6).any(|w| w == b"8.0.36"));
    }

    #[test]
    fn test_mqtt_ghost_valid_connect() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::MqttConnect, None);
        // First byte: CONNECT packet type (0x10)
        assert_eq!(ghost.bytes[0], 0x10);
        // Should contain "MQTT" protocol name
        assert!(ghost.bytes.windows(4).any(|w| w == b"MQTT"));
    }

    #[test]
    fn test_http2_ghost_valid_preface() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::Http2Preface, None);
        assert!(ghost.bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    }

    #[test]
    fn test_mimicry_wrapper_prepends_once() {
        let mut wrapper = MimicryWrapper::new(GhostProtocol::Redis, None);
        let data1 = b"hello";
        let data2 = b"world";

        let out1 = wrapper.wrap(data1);
        assert!(out1.len() > data1.len()); // ghost header prepended
        assert!(out1.ends_with(data1));

        let out2 = wrapper.wrap(data2);
        assert_eq!(out2, data2); // no prefix on subsequent writes
    }

    #[test]
    fn test_random_ghost_produces_valid_header() {
        for _ in 0..50 {
            let ghost = GhostHeaderGenerator::random(None);
            assert!(!ghost.bytes.is_empty());
            assert!(!ghost.description.is_empty());
        }
    }

    #[test]
    fn test_psql_ssl_request_bytes() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::PsqlSslRequest, None);
        assert_eq!(
            ghost.bytes,
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]
        );
    }

    #[test]
    fn test_curl_http_get_sni() {
        let ghost = GhostHeaderGenerator::generate(GhostProtocol::CurlHttpGet, Some("example.com"));
        let req = String::from_utf8(ghost.bytes).unwrap();
        assert!(req.contains("Host: example.com"));
        assert!(req.contains("User-Agent: curl/8.9.1"));
    }
}
