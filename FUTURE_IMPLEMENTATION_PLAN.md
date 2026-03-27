# Future Implementation Plan

RustRay's "Phase 7" transport architecture (P2P, Brutal-QUIC, SIP003, eBPF Handshake Mutilator, Sub-protocol orchestrator) has formally **finished development** and is validated as production-ready.

This document outlines the strategic roadmap for Phase 8+, focusing predominantly on cutting-edge encryption mechanisms, kernel-io optimizations, and advanced behavioral logic.

### Phase 8: Hardened Security & Post-Quantum Cryptography

*   **PQC Cipher Integration:** Officially transition experimental `oqs` Post-Quantum Key Exchange wrappers (ML-KEM-768/Kyber) into the standard TLS 1.3 / REALITY transport path to safeguard traffic against "Harvest Now, Decrypt Later" quantum data collection.
*   **Earendil Tor-like Routing Integration:** Integrate the `earendil` library to allow RustRay instances to function within an incentivized, zero-knowledge anonymous mesh network.
*   **Automated Domain Fronting Miner:** Develop a background worker that continuously scans and ranks top SNI domains relative to local ISP whitelists, automating the optimal `dest` selection for REALITY handshakes based on live geo-location.

### Phase 9: Ultimate IO Optimization & Kernel Interaction

*   **IO_uring Migration (Linux):** On modern Linux kernels, convert the core `tokio` socket handling over to `tokio-uring` to utterly eliminate context-switching syscall overhead on massive bandwidth proxy chains.
*   **Windows RIO (Registered I/O):** Explore implementing the ultra-low latency Registered I/O API for native Windows systems to match the multi-gigabit throughput seen on the Linux side.
*   **eBPF Router Shift:** Shift the current userspace GeoIP matching database directly into an XDP (eXpress Data Path) eBPF program, dropping invalid subnets before they even reach `rustray`'s memory allocator.

### Phase 10: The Advanced Enterprise Control Plane

*   **Mesh Load Balancing:** Expand the Fallback Orchestrator into an active Load Balancer. Introduce latency-weighted random splitting for clustered server environments.
*   **Automated ACME Core Integration:** Integrate native `rustls` Let's Encrypt / ACME fetchers directly into the rustray core without needing an external web server proxy in front of it.
*   **Telemetry distributed Tracing:** Merge all debug spans across the `rustray` instance with the `OpenTelemetry` framework. This allows data centers to aggregate cross-ocean hop delays in tools like Jaeger/Zipkin.
*   **DDI (Distributed Denial of Information) Protection:** Incorporate aggressive rate-limiting layers on the `VLESS/Flow-J` entry points specifically to detect and ban GFW "Active Probes" permanently.
