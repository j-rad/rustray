# RustRay 🦀

**RustRay** is a next-generation, high-performance universal proxy core written in Rust.

Designed as a **100% drop-in replacement** for `xrustray`, RustRay extends standard proxy capabilities by integrating best-of-breed protocols and transports from across the open-source community into a single, unified, memory-safe runtime.

## 🚀 Core Philosophy

* **Performance**: Built on Rust's modern async stack (`tokio`, `hyper`, `quiche`, `actix`) for maximum throughput, low latency, and memory safety.
* **Compatibility**: Fully compatible with the `xrustray` JSON configuration structure. Seamlessly migrate using your existing `config.json`.
* **Universality**: Supports a massive array of protocols and transports, enabling complex proxy chains and routing strategies impossible with other single cores.
* **Mobile-First**: Dedicated Android support with UniFFI JNI bindings, socket protection, and battery-optimized components.
* **Stealth**: Features the exclusive **Flow-J** protocol for advanced censorship circumvention.

## ✨ Features

### 🛡️ Protocols & Transports

RustRay supports a superset of protocols found in Xray, Sing-Box, Hysteria, and others.

| Category      | Protocol / Transport  | Status   | Notes |
|---------------|-----------------------|----------|-------|
| **Core**      | VLESS                 | ✅ Ready | v0, v1, Vision |
|               | VMess                 | ✅ Ready | AEAD, MD5 |
|               | Trojan                | ✅ Ready | |
|               | Shadowsocks 2022      | ✅ Ready | Multi-user, AEAD 2022 |
|               | Socks5 / HTTP         | ✅ Ready | |
| **P2P / Relay**| **Flow-J**            | ✅ New   | Polyglot censorship circumvention |
|               | Hysteria 2            | ✅ Ready | QUIC-based high speed |
|               | TUIC                  | ✅ Ready | |
|               | WireGuard             | ✅ Ready | |
| **Outbound**  | Tor                   | ✅ Ready | Native directory integration |
|               | SSH                   | ✅ Ready | |
|               | Tailscale             | ✅ Ready | Userspace networking |
| **Encryption**| **REALITY**           | ✅ Ready | TLS 1.3 fingerprinting |
|               | uTLS                  | ✅ Ready | Chrome/Firefox/iOS Camouflage |

### 🔒 Flow-J Universal Protocol

Flow-J is a RustRay-exclusive polyglot protocol designed for severe censorship environments. It dynamically shifts its digital fingerprint across three modes:

1. **Mode A (Direct Stealth)**: REALITY-based TLS 1.3 with probe detection and fallback.
2. **Mode B (CDN Relay)**: HTTP Upgrade and xhttp techniques for CDN traversal.
3. **Mode C (IoT Camouflage)**: Encapsulates traffic as MQTT sensor data to blend in with smart devices.

It features **Elastic FEC** (Reed-Solomon) for reliability on lossy networks.

### 🧩 App Modules

* **Rules-Based Router**: GeoIP (CN/private), Domain (Geosite), and CIDR routing.
* **Global Kill Switch**: Critical panic handling to prevent traffic leaks.
* **Secure Storage**: Encrypted local storage (SurrealDB).
* **Observatory**: Active health-checking and latency monitoring.
* **Stats & Metrics**: gRPC and Prometheus metrics export.
* **Reverse Proxy**: Bridge/Portal system for tunneling behind NAT.
* **Headless Control Plane**: Lightweight HTTP server with an embedded Wasm dashboard for configuration and monitoring.
* **Automatic Core Updates**: Can download and manage `RustRay` or `sing-box` binaries automatically.
* **Diagnostic Reports**: Generate comprehensive diagnostic archives including logs, system info, and firewall rules for easy troubleshooting.

### 📱 Mobile Integration

* **Android UniFFI Bindings**: Exposes a clean Kotlin/Java API via UniFFI.
* **VpnService Integration**: Includes helpers for `VpnService.protect()` to prevent routing loops.

## 🛠️ Building from Source

### Prerequisites

* [Rust Toolchain](https://rustup.rs/) (latest stable)
* **Android NDK** (for mobile builds)
* `cargo-ndk` (for Android): `cargo install cargo-ndk`
* `protobuf-compiler` (for gRPC generation)

### Desktop Build (Linux/macOS/Windows)

```sh
git clone https://github.com/your-username/rustray.git
cd rustray
cargo build --release
```

Binary location: `target/release/rustray`

### Android Cross-Compilation

RustRay provides a complete build system for Android, generating JNI-compatible shared libraries (`librustray.so`) and executables.

**1. Set Environment**

```sh
export ANDROID_HOME=$HOME/Android/Sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<ver>
```

**2. Build All Targets**

```sh
cargo ndk -t aarch64-linux-android \
          -t armv7-linux-androideabi \
          -t x86_64-linux-android \
          -t i686-linux-android \
          build --release
```

Artifacts location: `target/<target-triple>/release/`

## 📱 Android Integration

For VpnService developers:

1. **Load Library**: `System.loadLibrary("rustray")`
2. **Socket Protection**: Use the UniFFI API to register the VPN protection callback. This allows RustRay to protect its own outbound sockets from the VPN routing table.
3. **Lifecycle**: Use `RustRay.start()` and `RustRay.stop()`.

```kotlin
// Android/Kotlin Integration Example
object RustRayVPN {
    init {
        System.loadLibrary("rustray")
    }

    fun startVpn(service: VpnService, config: String) {
        // 1. Register protection callback
        RustRay.registerProtectCallback(object : ProtectCallback {
            override fun protect(fd: Int): Boolean {
                return service.protect(fd)
            }
        })

        // 2. Start Core
        val result = RustRay.start(config)
    }
}
```

## ⚙️ Configuration

RustRay uses a JSON configuration file compatible with Xray.

**Minimal Example:**

```json
{
  "log": { "loglevel": "info" },
  "inbounds": [{
    "port": 10808,
    "protocol": "socks",
    "settings": { "auth": "noauth" }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
```

**Running:**

```sh
./rustray -c config.json
```

## 📂 Project Structure

```
RustRay/
├── src/
│   ├── api/            # gRPC Service Implementation
│   ├── android/        # JNI Bridge & Socket Protection
│   ├── app/            # Internal Apps (DNS, Router, Stats)
│   ├── ffi.rs          # UniFFI Exports (Mobile API)
│   ├── inbounds/       # SOCKS, HTTP, Dokodemo
│   ├── outbounds/      # Freedom, Blackhole, Tailscale
│   ├── protocols/      # VLESS, VMess, Flow-J, Trojan
│   ├── transport/      # TCP, QUIC, REALITY, WS, Mux
│   └── lib.rs          # Core Entry Point
```

## 🤝 Contributing

Contributions are welcome! Please submit Pull Requests for bug fixes or new protocol implementations.

## 📄 License

Proprietary / Closed Source (Currently)
