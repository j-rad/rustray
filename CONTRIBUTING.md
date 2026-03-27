# Contributing to RustRay

First off, thank you for considering contributing to RustRay! It's people like you who make RustRay such a great tool for the privacy community.

## How Can I Contribute?

### Reporting Bugs
- Use the [Bug Report Template](https://github.com/FaezBarghasa/rustray/issues/new?template=bug_report.md).
- Describe the exact steps to reproduce the issue.
- Include your architecture and OS details.

### Suggesting Enhancements
- Use the [Feature Request Template](https://github.com/FaezBarghasa/rustray/issues/new?template=feature_request.md).
- Explain why this enhancement would be useful to most users.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests!
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes (`cargo test`).
5. Make sure your code lints (`cargo clippy`).
6. Format your code (`cargo fmt`).

## Development Setup

### Prerequisites
- **Rust**: Latest stable version.
- **Protobuf Compiler**: `protoc` (required for gRPC APIs).
- **Aya Dependencies**: For eBPF features (Linux only).
  - `llc`, `clang`
- **Quiche Dependencies**: `cmake`, `go` (for BoringSSL).

### Building
```sh
# Build with all standard evasion features
cargo build --features ebpf,quic,p2p
```

## Coding Standards

- **Safety First**: Avoid `unsafe` unless absolutely necessary for performance. If used, document why and ensure bounds checks are equivalent.
- **Asynchronous Code**: We use `tokio` for our runtime. Keep blocking calls out of the async executors.
- **Error Handling**: Use `anyhow` for top-level errors and `thiserror` for library-level errors. No `.unwrap()` in production code.
- **Documentation**: All public modules and functions should have doc comments (`///`).

## Community

- Join our [Discord Server](https://discord.gg/rustray).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---
Happy Hacking! 🦀
