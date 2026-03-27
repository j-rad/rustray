# RustRay 🦀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://github.com/FaezBarghasa/rustray/actions/workflows/test.yml/badge.svg)](https://github.com/FaezBarghasa/rustray/actions)
[![Production Ready](https://img.shields.io/badge/Status-Production--Ready-success.svg)](IMPLEMENTATION_STATUS.md)

**RustRay** is a next-generation, high-performance universal proxy core written entirely in memory-safe Rust. It functions as a **100% drop-in replacement** for legacy systems like `Xray-core`, merging standard JSON APIs with cutting-edge proprietary evasion techniques built natively into the runtime.

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
- **Legacy Compatibility**: Reads standard `xrustray` configurations, handling routing and outbounds without breaking your existing CI pipelines.
- **Radical Stealth**: Leverages `aya` eBPF hooking and advanced app-layer desynchronization to effectively disappear from stateful Deep Packet Inspection.

## Key Features

### Transports & Cryptography

- **Brutal-QUIC Congestion Controller:** Replaces classic TCP Cubic/BBR with a fixed-rate QUIC pump, tearing through packet-loss walls set up by ISPs.
- **Asymmetric P2P Relays:** Circumvent direct IP blocking by hopping through BLAKE3-authenticated residential mesh peers.
- **SIP003 Interoperability:** Need legacy shadowsocks plugins to convert heavy UDP tracking over obscure TCP networks? SIP003 is managed directly via RustRay's child-process supervisor.
- **Elastic FEC:** Reed-Solomon Forward Error Correction calculates invisible repair packets alongside your traffic, rebuilding dropped data without a single retransmission ping.

### The Flow-J Protocol

RustRay ships with **Flow-J**, a dynamic polyglot protocol that shapeshifts under pressure:

1. **Mode A (Direct Stealth)**: Standard Chrome-fingerprint TLS 1.3 / REALITY.
2. **Mode B (CDN Relay)**: Disguises streams through HTTP-Upgrade xhttp headers to hide behind major CDNs.
3. **Mode C (IoT Camouflage)**: The most extreme defense. Traffic is encapsulated into MQTT smart-sensor telemetry, ignoring all web-focused firewall rules entirely.

### Tactical Subsystems

- **The eBPF Handshake Mutilator:** On Linux, `rustray` injects an eBPF map into the kernel, intentionally slicing our own TLS ClientHello packets at specific boundary limits to crash or evade inline DPI firewalls attempting to read our SNI.
- **Autonomous Fallback Orchestrator:** Scans active protocols via gRPC metrics. If a server is IP-blackholed, RustRay instantly redirects internal buffers to a fallback tag (e.g. from Flow-J directly to a P2P neighbor).

## Getting Started

RustRay natively targets Linux, Windows, macOS, and via `UniFFI`, Android (JNI) and iOS.

To compile the headless proxy core with all evasion features active:

```sh
cargo build --release --features ebpf,quic,p2p
./target/release/rustray -c config.json
```

## Roadmap

Detailed roadmap can be found in [FUTURE_IMPLEMENTATION_PLAN.md](FUTURE_IMPLEMENTATION_PLAN.md).

- [x] Phase 7: Complete Transport Architecture (eBPF, QUIC, P2P)
- [ ] Phase 8: Post-Quantum Cryptography (ML-KEM-768)
- [ ] Phase 9: IO_uring & Kernel-level routing
- [ ] Phase 10: Enterprise Control Plane

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
