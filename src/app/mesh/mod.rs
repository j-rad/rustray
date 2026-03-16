// src/app/mesh/mod.rs
pub mod discovery;
pub mod health;
pub mod peer_registry;

pub use peer_registry::{GossipConfig, PeerAnnouncement, PeerEntry, PeerGossip, PeerRegistry};
