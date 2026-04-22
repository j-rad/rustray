// src/android/mod.rs
//! Android-specific native integration
//! Provides socket protection to prevent VPN routing loops

pub mod jni;

pub use jni::{is_android, protect_socket};
