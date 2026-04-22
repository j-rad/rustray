# RustRay Developer Guide

Welcome to the RustRay developer ecosystem. This guide provides technical deep-dives for developers looking to integrate RustRay into mobile apps, extend the core logic, or contribute to the transport layer.

## 🏗 Project Architecture

RustRay is structured as a modular proxy core with a high-performance transport layer.

- `src/app/`: Core application logic, routing, and stats management.
- `src/transport/`: Implementation of various transport protocols (TCP, QUIC, Flow-J, mDNS).
- `src/protocols/`: Application layer protocols (VLESS, VMess, Trojan).
- `src/ffi/`: UniFFI-based bindings for Android, iOS, and Desktop.
- `src/api/`: gRPC service implementations for remote management.

## 📱 Mobile Integration (UniFFI)

RustRay uses [UniFFI](https://github.com/mozilla/uniffi-rs) to generate bindings for Kotlin (Android) and Swift (iOS).

### Key FFI Components (`src/ffi/mod.rs`)

1. **`EngineManager`**: The primary singleton for starting and stopping the engine.
2. **`ConnectConfig`**: A simplified configuration structure used by mobile apps to initiate a connection without writing full JSON.
3. **`SharedStatsBuffer`**: A C-compatible memory region where real-time stats are stored, allowing mobile UIs to read data without expensive string serialization.

### Example: Starting the Engine (Pseudo-Swift)

```swift
let manager = EngineManager()
let config = ConnectConfig(
    address: "1.2.3.4",
    port: 443,
    uuid: "...",
    protocol: "flow-j"
)
let result = manager.startEngine(configJson: config.toJson(), callback: MyVpnCallback())
```

## 🛰 Extending Transports

To add a new transport (e.g., a new steganography method):

1. Implement the `AsyncRead` and `AsyncWrite` traits for your transport in `src/transport/`.
2. Wrap it in a `TransportConnector` in `src/transport/mod.rs`.
3. Register the protocol tag in `src/config.rs`.

## 🛡 eBPF & Kernel Integration

RustRay uses eBPF for packet mutilation on Linux.
- The bytecode is located in `src/transport/ebpf/mutilator.c`.
- The loader logic is in `src/transport/ebpf/loader.rs`.
- **Note:** eBPF requires `CAP_NET_ADMIN` or root privileges.

## 📊 gRPC API for Developers

Developers can manage a running RustRay instance via gRPC on port `10085` (default).

- **HandlerService**: Add/Remove users dynamically.
- **StatsService**: Query per-user or per-inbound bandwidth usage.
- **LoggerService**: Stream logs in real-time.

See `GRPC_API_INTEGRATION.md` for the full protobuf specification.

## 🧪 Testing Guidelines

Always run the full suite before submitting PRs:

```bash
# Unit tests
cargo test

# Integration tests (requires network)
cargo test --test phase10_mesh_intelligence_test

# Smoke tests for gRPC
bash scripts/grpc_smoke_test.sh
```

For more details, see `TESTING_GUIDE.md`.
