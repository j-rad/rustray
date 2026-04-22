# Testing Guide for RustRay

RustRay is a mission-critical proxy core. High test coverage and reliability are our top priorities. This guide explains our testing architecture and how to contribute new tests.

## Test Tiers

### 1. Unit Tests
Located within the `src/` directory alongside the implementation.
- Focus on individual logic, data structures, and codec handling.
- Run with: `cargo test --lib`

### 2. Integration Tests
Located in the `tests/` directory. These test how different components of the core interact.
- **Protocol Muxing**: `tests/mux_tests.rs`
- **QUIC Stability**: `tests/brutal_quic_test.rs`
- **P2P Resilience**: `tests/mesh_resilience_test.rs`
- **Phase 10 Mesh Intelligence**: `tests/phase10_mesh_intelligence_test.rs`
- **gRPC API Integration**: `tests/grpc_integration.rs`
- **FFI Stealth**: `tests/ffi_stealth_test.rs`
- Run with: `cargo test --test <name>`

### 3. eBPF Integration Tests
Specialized tests for our kernel-level packet manipulation.
- **Requirement**: Must be run on Linux with root privileges to load eBPF programs.
- **Files**: 
    - `tests/ebpf_integrity.rs`
    - `tests/handshake_forensics_test.rs`
    - `tests/ebpf_fragmentation_test.rs`
- Run with: `sudo cargo test --test ebpf_integrity`

### 4. Fuzzing
We use `cargo-fuzz` for testing our codecs (VLESS, VMess, Flow-J) against malicious edge cases.
- **Directory**: `fuzz/`
- Run with: `cargo fuzz run <target>`

### 5. Benchmarks
Performance is key. We use `criterion` for high-precision benchmarking.
- **Directory**: `benches/`
- Run with: `cargo bench`

## Continuous Integration (CI)

Every Pull Request automatically triggers our GitHub Actions workflow which runs:
- `cargo check --workspace`
- `cargo clippy --workspace -D warnings`
- `cargo test --workspace`
- `cargo fmt --check`

## How to Contribute Tests

When adding a new feature:

1. **Add Unit Tests**: Cover the edge cases for the new logic.
2. **Add an Integration Test**: If it's a new transport or protocol, add it to `tests/`.
3. **Run existing tests**: Ensure no regressions in stability (`tests/stability_e2e.rs`).

### Example: Adding a Protocol Test
```rust
#[tokio::test]
async fn test_new_protocol_handshake() {
    let (server, client) = setup_mock_pair().await;
    // ... perform handshake ...
    assert!(handshake.is_success());
}
```

---
Need help with a complex scenario? Reach out on our [Discord](https://discord.gg/rustray). 🚀
