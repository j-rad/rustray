// src/protocols/mod.rs
pub mod error;
pub mod flow;
pub mod flow_j;
pub mod flow_trait;
pub mod http_proxy;
#[cfg(feature = "quic")]
pub mod hysteria2;
pub mod naive;
pub mod shadowsocks_2022;
pub mod shadowsocks_stream;
pub mod stealth;
pub mod trojan;
#[cfg(feature = "quic")]
pub mod tuic;
pub mod vless;
pub mod vless_vision;
pub mod vmess;
pub mod wireguard;

use crate::error::Result;
use std::net::SocketAddr;

/// Performs a STUN lookup to determine the public IP and port.
/// Useful for P2P protocols like WireGuard, Hysteria, and TUIC.
pub async fn resolve_stun(_stun_server: &str) -> Result<SocketAddr> {
    Err(anyhow::anyhow!(
        "STUN resolution temporarily disabled due to dependency issues"
    ))
}
