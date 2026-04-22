# Flow-J Universal Protocol Implementation

## Overview

Flow-J is a next-generation, multi-transport polyglot proxy protocol designed for severe censorship environments. It dynamically shifts its digital fingerprint across multiple transport modes:

- **Mode A (Direct Stealth)**: REALITY-based with probe detection and certificate stealing
- **Mode B (CDN Relay)**: HTTP Upgrade and xhttp for CDN traversal
- **Mode C (IoT Camouflage)**: MQTT and Industrial Parasite steganography
- **Mode D (Brutal-QUIC)**: High-performance fixed-rate QUIC transport for lossy networks

## Architecture

### Split-Identity Design

Flow-J separates control and data planes, allowing:

- Probe detection and fallback to real destinations
- Multiple simultaneous transport streams
- Automatic mode selection based on network conditions
- eBPF-based packet fragmentation and SNI slicing

### Zero-Copy Optimization

- Uses `BytesMut` for efficient buffer management
- Linux `splice()` for kernel-level zero-copy transfer
- Minimal allocations in hot paths

### Elastic FEC

- Configurable Reed-Solomon erasure coding (10+3 default)
- Per-stream FEC for packet recovery on unreliable networks
- Graceful degradation under packet loss
- Integrated with Brutal-QUIC for massive throughput in 20%+ loss environments

## Module Structure

```
src/protocols/
  └── flow_j.rs           # Core protocol, header encoding, config structs

src/transport/
  ├── flow_j_reality.rs   # Mode A: REALITY TLS with probe detection
  ├── flow_j_cdn.rs       # Mode B: HTTP Upgrade & xhttp handlers
  ├── flow_j_mqtt.rs      # Mode C: MQTT IoT camouflage
  ├── flow_j_brutal.rs    # Mode D: Brutal-QUIC transport
  ├── flow_j_fec.rs       # Elastic FEC encoder/decoder
  └── tls_camouflage.rs   # Chrome TLS fingerprint mimicry
```

## Implementation Details

### Task 1: Core Protocol Structure (`flow_j.rs`)

**FlowJConfig** supports:

- `mode`: Auto, Reality, Cdn, Mqtt, Brutal
- `reality`: RealitySettings (dest, serverNames, privateKey, shortIds)
- `http_upgrade`: HttpUpgradeSettings (path, host, headers)
- `xhttp`: XhttpSettings (upload_path, download_path, h2)
- `mqtt`: MqttSettings (broker, topics, credentials, qos)
- `brutal`: BrutalSettings (up_mbps, down_mbps)
- `fec`: FecSettings (enabled, data_shards, parity_shards)

**Inbound Handler**:

- Parses Flow-J header with magic `FJ01`
- Validates client UUID against configured clients
- Routes to destination via Router

**Outbound Handler**:

- Auto-selects optimal mode based on availability (orchestrated)
- Creates Flow-J header with nonce and timestamp
- Dispatches to appropriate transport

### Task 2: Mode A - REALITY (`flow_j_reality.rs`)

**Server Side**:

- `RealityListener`: Accepts connections and handles probe detection
- `handle_reality_connection`: Peeks first 512 bytes without consuming
- `discriminate_handshake`: Distinguishes Flow-J, TLS ClientHello, or unknown
- Forwards probes to real destination (e.g., `www.samsung.com:443`)

**Client Side**:

- `connect_reality`: Establishes TLS 1.3 connection with Chrome fingerprint
- Uses `rustls` with webpki roots
- Injects authentication via HMAC-SHA256 tag

### Task 3: Mode B - CDN Relay (`flow_j_cdn.rs`)

**HTTP Upgrade Server** (Actix-web):

- Validates `Upgrade: flow-j-transport` header
- Authenticates via `Sec-FlowJ-Key` header
- Returns `101 Switching Protocols`

**HTTP Upgrade Client**:

- Constructs upgrade request with base64-encoded UUID
- Handles `101` response and switches to binary mode

**xhttp Transport**:

- Upload: `POST /api/up` with `X-FlowJ-Session` header
- Download: `GET /api/down` with chunked streaming response
- Session-based routing for multi-stream support

### Task 4: Mode C - MQTT Camouflage (`flow_j_mqtt.rs`)

**Tunneling Strategy**:

- Upload topic: `sensors/temperature/{session_id}/data`
- Download topic: `sensors/firmware/{session_id}/data`
- QoS 1 (AtLeastOnce) for reliability

**IoT Payload Wrapper**:

```json
{"sensor":"temperature","timestamp":1702800000,"data":"<base64>"}
```

**Industrial Parasite**:

- Disguises traffic as Modbus/TCP or OPC-UA telemetry
- Integrated via `mqtt_parasite.rs` for steganographic concealment

### Task 5: TLS Camouflage (`tls_camouflage.rs`)

**Chrome 124 Fingerprint**:

- TLS 1.3 only
- Cipher suites: AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305
- ALPN: h2, http/1.1
- Curves: X25519, P-256, P-384
- GREASE extensions (RFC 8701)
- Random padding (0-32 bytes)

**Utilities**:

- `generate_padding()`: Random padding bytes
- `random_grease()`: GREASE value selection
- `ClientHelloCustomization`: Chrome-like extension order

### Task 6: Elastic FEC (`flow_j_fec.rs`)

**FecEncoder**:

- Splits data into shards (MTU-friendly 1400 bytes)
- Generates parity shards using Reed-Solomon
- Sequence number for grouping

**FecDecoder**:

- Collects shards by sequence
- Reconstructs original data when threshold reached
- Auto-cleanup of expired groups (5 second timeout)

**Zero-Copy Functions**:

- `zero_copy_splice()`: Linux splice() for kernel-level copy

## Configuration Example

```json
{
  "outbounds": [{
    "tag": "flow-j-proxy",
    "protocol": "flow-j",
    "settings": {
      "mode": "auto",
      "uuid": "12345678-1234-1234-1234-123456789012",
      "address": "server.example.com",
      "port": 443,
      "reality": {
        "dest": "www.samsung.com:443",
        "server_names": ["server.example.com"],
        "private_key": "deadbeef..."
      },
      "fec": {
        "enabled": true,
        "data_shards": 10,
        "parity_shards": 3
      }
    }
  }]
}
```

## Test Coverage

All 32 Flow-J related tests pass:

| Module | Tests |
|--------|-------|
| `flow_j.rs` | 4 tests (header, magic, config) |
| `flow_j_reality.rs` | 5 tests (discrimination, auth) |
| `flow_j_cdn.rs` | 2 tests (upgrade, xhttp) |
| `flow_j_mqtt.rs` | 6 tests (broker, framing, IoT, Parasite) |
| `flow_j_brutal.rs` | 4 tests (pacing, throughput, loss) |
| `flow_j_fec.rs` | 4 tests (encode, decode, serialization) |
| `tls_camouflage.rs` | 7 tests (padding, grease, fingerprint) |

## Dependencies

```toml
# Flow-J Universal Protocol
reed-solomon-erasure = "6.0"
rumqttc = "0.25"
rustls = "0.23"
tokio-rustls = "0.26"
webpki-roots = "1.0"
actix-web = "4.8"
nix = { version = "0.29", features = ["fs"] }
```

## Future Enhancements

1. **Full AsyncRead/AsyncWrite for MqttStream**: Currently falls back to TCP
2. **Post-Quantum Cryptography (PQC)**: ML-KEM integration for handshakes
3. **Session persistence**: Redis-backed session storage
4. **Dynamic FEC ratio**: Adjust based on measured packet loss
5. **BoringSSL integration**: For even more accurate Chrome fingerprints
