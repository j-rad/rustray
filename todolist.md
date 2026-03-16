# To-Do List

This to-do list has been refactored to prioritize tasks and provide a clearer roadmap for development. For a long-term roadmap, see [FUTURE_IMPLEMENTATION_PLAN.md](./FUTURE_IMPLEMENTATION_PLAN.md).

### High Priority: Core Functionality & Security
-   [ ] **VLESS REALITY Handshake**: Implement the cryptographic handshake for REALITY in `src/protocols/vless.rs`. (Crucial for security)
-   [ ] **Protocol-Specific Error Handling**: Refactor the top-level error type to wrap specific protocol errors from `src/protocols/error.rs` instead of converting them to strings. This will preserve error context and improve debugging.
-   [ ] **VLESS Handshake & Flow Tests**: Add integration tests for the VLESS REALITY handshake, flow control, and muxing.

### Medium Priority: Mobile Integration & Testing
-   [ ] **XCFramework Build Script**: Create a build script to compile the Rust library into an XCFramework for all required iOS architectures.
-   [ ] **iOS Integration Testing**: Develop a minimal iOS test app to validate end-to-end functionality.
-   [ ] **Secure Storage Path Validation (iOS)**: Verify and adapt the `init_storage` function for sandboxed file system paths on iOS.
-   [ ] **Comprehensive Testing**: Add more unit and integration tests for all protocols, covering edge cases and error conditions.

### Low Priority: Performance & Feature Expansion
-   [ ] **Benchmarking**: Implement benchmarks for each protocol to measure performance.
-   [ ] **UDP Support**: Implement UDP relaying for protocols that support it (e.g., Trojan, Socks5).
-   [ ] **Configuration Reloading**: Implement a mechanism to reload the configuration file without restarting the application.

### Ongoing: Code Quality & Maintenance
-   [ ] **CI/CD Pipeline**: Set up a continuous integration pipeline (e.g., using GitHub Actions).
-   [ ] **Documentation**: Improve inline code documentation and create higher-level project documentation.

### Completed
-   [x] **gRPC `AlterInbound`/`AlterOutbound`**: Implemented user modification logic for `AlterInbound` and `AlterOutbound` gRPC calls.
-   [x] **gRPC `GetInboundUser`**: Implemented the `GetInboundUser` gRPC call to allow user verification.
-   [x] **iOS TUN Interface**: Implemented the logic to handle the `tun_fd` passed via FFI to create a network interface on iOS.
-   [x] **Muxing Tests**: Added unit and integration tests for the muxing logic in `src/transport/mux.rs`.
-   [x] **Refactor todolist.md**: Updated the to-do list, checked for completed tasks, and generated a future implementation plan.
