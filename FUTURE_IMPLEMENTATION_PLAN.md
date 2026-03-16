# Future Implementation Plan

This document outlines a strategic roadmap for the future development of RustRay, focusing on expanding its capabilities, enhancing security, and improving performance.

### Phase 1: Protocol Expansion & Interoperability

*   **TUIC Protocol:** Implement the TUIC protocol (`src/protocols/tuic.rs`) for high-performance UDP-based proxying, leveraging the existing QUIC infrastructure.
*   **SSH (Secure Shell) as a Transport:** Implement an SSH transport using the `russh` crate to encapsulate traffic within a standard SSH session, providing both proxying and remote shell capabilities.
*   **Full WireGuard Integration:** Move beyond the placeholder and implement a full WireGuard transport using `boringtun` or a similar library, allowing RustRay to act as a WireGuard peer.
*   **Shadowsocks v1 (AEAD):** Implement the original Shadowsocks AEAD-based protocol for broader compatibility with older clients.

### Phase 2: Security Enhancements

*   **Post-Quantum Cryptography:** Experiment with post-quantum key exchange algorithms (e.g., from the `oqs` crate) for TLS 1.3 and other protocols to future-proof against quantum attacks.
*   **Earendil Integration:** Explore integrating `earendil`, a next-generation anonymous networking protocol, as a transport option for enhanced privacy.
*   **DNS-over-QUIC (DoQ) and DNS-over-HTTP (DoH) Server:** Implement a built-in DoQ/DoH server to provide encrypted DNS resolution for clients, reducing reliance on external DNS providers.
*   **Advanced Obfuscation:** Develop more sophisticated traffic obfuscation techniques, such as mimicking common web traffic patterns (e.g., video streaming, WebRTC) to better evade DPI.

### Phase 3: Performance & Optimization

*   **IO_uring for Linux:** On Linux, implement an optional `io_uring` backend for network I/O to reduce syscall overhead and improve throughput.
*   **Zero-Copy Forwarding:** Refactor the routing and proxy logic to use zero-copy techniques (e.g., `splice` on Linux) where possible to minimize data copying between sockets.
*   **Optimized Muxing:** Benchmark and optimize the `yamux`-based muxing implementation, potentially exploring alternative libraries or custom solutions for lower latency.
*   **Connection Pooling for Outbounds:** Implement a more sophisticated connection pooling mechanism for outbound connections to reduce the overhead of repeated handshakes.

### Phase 4: Cross-Platform & Usability

*   **Desktop GUI:** Develop a cross-platform desktop GUI (using Tauri or a similar framework) for easier configuration and management.
*   **Android Service & VPN Integration:** Create a proper Android service and VpnService integration for a seamless mobile experience.
*   **Web Dashboard:** Build a web-based dashboard (using Actix-web) for real-time monitoring of traffic, active connections, and server status.
*   **Automated Certificate Management:** Integrate with ACME providers (e.g., Let's Encrypt) for automatic fetching and renewal of TLS certificates.

### Phase 5: Advanced Features

*   **Load Balancing & Failover:** Implement outbound load balancing (e.g., round-robin, latency-based) and automatic failover for improved reliability.
*   **Policy-Based Routing:** Enhance the router with more complex, policy-based routing rules (e.g., routing based on application, domain, or geographic location).
*   **Pluggable Transports:** Refactor the transport layer to support pluggable transports, allowing third-party developers to create their own transport protocols.
*   **Distributed Tracing:** Integrate with distributed tracing systems (e.g., OpenTelemetry) for better observability in complex, multi-hop proxy setups.
