# Build Targets

The following targets are supported for the RustRay core library and application.

## Linux

| Architecture | Target Triple | LibC |
|--------------|---------------|------|
| x86_64 | `x86_64-unknown-linux-gnu` | GNU (glibc) |
| x86_64 | `x86_64-unknown-linux-musl` | Musl (Static) |
| x86 (32-bit) | `i686-unknown-linux-gnu` | GNU (glibc) |
| x86 (32-bit) | `i686-unknown-linux-musl` | Musl (Static) |

## Windows

| Architecture | Target Triple | Toolchain |
|--------------|---------------|-----------|
| x86_64 | `x86_64-pc-windows-msvc` | MSVC |
| x86 (32-bit) | `i686-pc-windows-msvc` | MSVC |

## macOS (Universal Binary)

| Architecture | Target Triple | Note |
|--------------|---------------|------|
| x86_64 (Intel) | `x86_64-apple-darwin` | Legacy Macs |
| ARM64 (M1/M2) | `aarch64-apple-darwin` | Apple Silicon |

## Mobile: Android

| Architecture | Target Triple | Android ABI |
|--------------|---------------|-------------|
| ARM64 | `aarch64-linux-android` | `arm64-v8a` |
| ARMv7 | `armv7-linux-androideabi` | `armeabi-v7a` |
| x86_64 | `x86_64-linux-android` | `x86_64` |
| x86 | `i686-linux-android` | `x86` |

## Mobile: iOS

| Architecture | Target Triple | Note |
|--------------|---------------|------|
| ARM64 | `aarch64-apple-ios` | iPhone/iPad |
| x86_64 | `x86_64-apple-ios` | Simulator |
| ARM64 | `aarch64-apple-ios-sim` | Simulator (M1) |
