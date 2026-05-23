// src/orchestrator/mod.rs
//! Autonomous Fallback Orchestrator
//!
//! Dynamically probes transport availability and performs hot-swap failover
//! when the active transport degrades or gets blocked.

pub mod manager;
pub mod probe;
