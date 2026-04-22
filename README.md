# RustRay 🦀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://github.com/FaezBarghasa/rustray/actions/workflows/test.yml/badge.svg)](https://github.com/FaezBarghasa/rustray/actions)
[![Production Ready](https://img.shields.io/badge/Status-Production--Ready-success.svg)](IMPLEMENTATION_STATUS.md)

**RustRay** is a next-generation, high-performance universal proxy core written entirely in memory-safe Rust. It functions as a **100% drop-in replacement** for legacy systems like `RustRay-core`, merging standard JSON APIs with cutting-edge proprietary evasion techniques built natively into the runtime.

---

## 📖 Table of Contents

- [Core Philosophy](#core-philosophy)
- [Key Features](#evasion-highlights)
- [Getting Started](#building--integration)
- [Roadmap](#project-roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [Community](#community)

## Core Philosophy

- **Uncompromising Performance**: Built securely on `tokio`, `quiche`, and `smoltcp` for extreme throughput and zero-copy packet passing (`bytes`).
- **Legacy Compatibility**: Reads standard `rustray` configurations, handling routing and outbounds without breaking your existing CI pipelines.
- **Radical Stealth**: Leverages `aya` eBPF hooking and advanced app-layer desynchronization to effectively disappear from stateful Deep Packet Inspection.

## Key Features

### Transports & Cryptography

- **Brutal-QUIC Congestion Controller:** Replaces classic TCP Cubic/BBR with a fixed-rate QUIC pump, tearing through packet-loss walls set up by ISPs.
- **DNS-over-QUIC (DoQ) Signaling:** Encrypted signaling using `hickory-resolver` for resilient, low-latency peer discovery and configuration fetching.
- **Secure mDNS Peer Announcements:** Local mesh discovery using AES-256-GCM encrypted mDNS, enabling zero-config peer-to-peer relaying in restricted LANs.
- **Elastic FEC:** Reed-Solomon Forward Error Correction calculates invisible repair packets alongside your traffic, rebuilding dropped data without a single retransmission ping.

### The Flow-J Protocol

RustRay ships with **Flow-J**, a dynamic polyglot protocol that shapeshifts under pressure:

1. **Mode A (Direct Stealth)**: Standard Chrome-fingerprint TLS 1.3 / REALITY.
2. **Mode B (CDN Relay)**: Disguises streams through HTTP-Upgrade xhttp headers to hide behind major CDNs.
3. **Mode C (IoT Camouflage)**: Traffic is encapsulated into MQTT smart-sensor telemetry or Industrial Parasite steganography, ignoring all web-focused firewall rules entirely.

### Tactical Subsystems

- **The eBPF Handshake Mutilator:** On Linux, `rustray` injects eBPF-based transport enhancements into the kernel, intentionally slicing our own TLS ClientHello packets at specific boundary limits to crash or evade inline DPI firewalls.
- **Autonomous Fallback Orchestrator:** Monitors health with a 5MB failover buffer. If a server is IP-blackholed, RustRay instantly races all available transports and hot-swaps to the lowest-latency path.
- **Carrier-Aware ISP Tuning:** Automatically detects mobile carriers (MCI, MTN, Rightel) via ASNs and applies optimal MTU/MSS clamping and packet pacing presets to bypass carrier-specific throttling.

## Getting Started

RustRay natively targets Linux, Windows, macOS, and via `UniFFI`, Android (JNI) and iOS.

To compile the headless proxy core with all evasion features active:

```sh
cargo build --release --features ebpf,quic,p2p
./target/release/rustray -c config.json
```

### Manual Run
```sh
# Run with a custom config
./rustray run -c config.json
```

## 🛠 For Developers

If you are a developer looking to integrate RustRay or contribute to the core:

- **[Developer Guide](DEVELOPER_GUIDE.md)**: Architecture, FFI/UniFFI, and transport extension.
- **[gRPC API Integration](GRPC_API_INTEGRATION.md)**: Managing the engine via HandlerService/StatsService.
- **[Testing Guide](TESTING_GUIDE.md)**: How to run unit and integration tests.
- **[Contributing](CONTRIBUTING.md)**: Branching models and coding standards.

## Roadmap

Detailed roadmap can be found in [FUTURE_IMPLEMENTATION_PLAN.md](FUTURE_IMPLEMENTATION_PLAN.md).

- [x] Phase 7: Complete Transport Architecture (eBPF, QUIC, P2P)
- [x] Phase 8: Ghost-Bucket (S3 Asynchronous Bridge)
- [x] Phase 9: Industrial Parasite (MQTT Steganography)
- [x] Phase 10: XDP Kernel Jitter & Window Control
- [x] Phase 11: Global Orchestrator (Handshake Race & Seamless Fallback)
- [ ] Phase 12: Post-Quantum Cryptography (PQC) Integration (In Progress)

## Contributing

We ❤️ open source! We are actively looking for contributors to help make RustRay the gold standard for privacy and performance.

- Check out our [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
- See "Good First Issues" on our [Issue Tracker](https://github.com/FaezBarghasa/rustray/issues).
- Help us improve our [Test Coverage](TESTING_GUIDE.md)!

## Security

Security is our top priority. Please review our [SECURITY.md](SECURITY.md) for vulnerability disclosure policies.

## Community

- **GitHub Discussions**: [Join the conversation](https://github.com/FaezBarghasa/rustray/discussions)
- **Telegram**: [@RustRayCommunity](https://t.me/RustRayCommunity) (Placeholder)
- **Discord**: [Join our Server](https://discord.gg/rustray) (Placeholder)

---
Copyright (c) 2024-2026 EdgeRay Team. Licensed under [MIT](LICENSE).
