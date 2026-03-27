// src/fec/mod.rs
//! Forward Error Correction (FEC) subsystem.
//!
//! Provides Reed-Solomon erasure coding for packet recovery on unreliable
//! networks experiencing 20-30% random UDP packet loss.

pub mod rs;
pub mod transport;
