// src/p2p/mod.rs
//! Asymmetric P2P Relay Network
//!
//! Enables traffic bridging through privileged relay nodes using
//! PSK-authenticated, encrypted connections with zero-copy forwarding.

pub mod relay;
pub mod conduit;
