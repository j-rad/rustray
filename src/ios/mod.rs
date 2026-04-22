// src/ios/mod.rs
//! iOS-specific native integration
//! Provides TUN device handling for NetworkExtension framework

#[cfg(target_os = "ios")]
pub mod tun;

#[cfg(target_os = "ios")]
pub use tun::{IosTunDevice, create_tun_from_fd};
