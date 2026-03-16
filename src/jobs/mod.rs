// rustray/src/jobs/mod.rs
//! Background Jobs Module
//!
//! Provides background job infrastructure for the headless server:
//! - Billing: User quota enforcement and traffic accounting
//! - Watchdog: Core health monitoring and auto-restart
//! - Traffic Reset: Periodic traffic counter resets

#[cfg(feature = "full-server")]
pub mod billing;

#[cfg(feature = "full-server")]
pub mod watchdog;

#[cfg(feature = "full-server")]
pub mod traffic_reset;
