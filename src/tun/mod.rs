// src/tun/mod.rs
//! Userspace TUN Stack
//!
//! Provides high-performance TUN device management and Tun2Socks
//! packet routing using smoltcp userspace TCP/IP stack.
//!
//! Features:
//! - Dynamic MTU profiles (Cellular/Standard/Jumbo)
//! - MSS clamping for fragmentation prevention
//! - Zero-leak Kill-Switch
//! - Lock-free packet processing via crossbeam-queue

pub mod packet_queue;
pub mod packet_router;
pub mod tun2socks;
pub mod tun_device;

pub use packet_queue::{AsyncPacketProcessor, PacketQueue, PooledBuffer, SharedBufferPool};
pub use packet_router::PacketRouter;
pub use tun_device::{AutoTuner, AutoTunerStats, MtuProfile, TunConfig, TunDevice};
pub use tun2socks::{
    ConnectionKey, Protocol, StreamEvent, Tun2SocksConfig, Tun2SocksEngine, clamp_mss,
    is_core_healthy, set_core_healthy,
};
