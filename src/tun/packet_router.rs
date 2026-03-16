// src/tun/packet_router.rs
//! Packet Router
//!
//! Routes IP packets between TUN device and proxy based on routing rules.

use crate::error::Result;
use crate::router::Router;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, warn};

/// IP packet parser (simplified)
pub struct IpPacket<'a> {
    data: &'a [u8],
}

impl<'a> IpPacket<'a> {
    /// Parse an IP packet
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        // Check IP version (first 4 bits)
        let version = data[0] >> 4;
        if version != 4 && version != 6 {
            return None;
        }

        Some(Self { data })
    }

    /// Get IP version
    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    /// Get destination IP address
    pub fn destination(&self) -> Option<IpAddr> {
        match self.version() {
            4 => {
                if self.data.len() < 20 {
                    return None;
                }
                // IPv4 destination is at offset 16-19
                let dst = [self.data[16], self.data[17], self.data[18], self.data[19]];
                Some(IpAddr::V4(dst.into()))
            }
            6 => {
                if self.data.len() < 40 {
                    return None;
                }
                // IPv6 destination is at offset 24-39
                let mut dst = [0u8; 16];
                dst.copy_from_slice(&self.data[24..40]);
                Some(IpAddr::V6(dst.into()))
            }
            _ => None,
        }
    }

    /// Get protocol number
    pub fn protocol(&self) -> Option<u8> {
        match self.version() {
            4 => {
                if self.data.len() < 20 {
                    return None;
                }
                Some(self.data[9])
            }
            6 => {
                if self.data.len() < 40 {
                    return None;
                }
                Some(self.data[6])
            }
            _ => None,
        }
    }

    /// Get raw packet data
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

/// Packet routing decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Send through proxy
    Proxy,
    /// Send directly
    Direct,
    /// Drop packet
    Drop,
}

/// Packet router
pub struct PacketRouter {
    router: Arc<Router>,
}

impl PacketRouter {
    /// Create a new packet router
    pub fn new(router: Arc<Router>) -> Self {
        Self { router }
    }

    /// Route a packet and return routing decision
    pub async fn route_packet(&self, packet: &[u8]) -> Result<RoutingDecision> {
        let ip_packet = match IpPacket::parse(packet) {
            Some(p) => p,
            None => {
                warn!("Failed to parse IP packet");
                return Ok(RoutingDecision::Drop);
            }
        };

        let dest_ip = match ip_packet.destination() {
            Some(ip) => ip,
            None => {
                warn!("Failed to extract destination IP");
                return Ok(RoutingDecision::Drop);
            }
        };

        debug!(
            "Routing packet: dst={}, proto={:?}, size={}",
            dest_ip,
            ip_packet.protocol(),
            packet.len()
        );

        // Use router to determine if IP should go through proxy
        let should_proxy = self.router.should_proxy_ip(&dest_ip).await;

        if should_proxy {
            Ok(RoutingDecision::Proxy)
        } else {
            Ok(RoutingDecision::Direct)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_packet_parsing() {
        // Minimal IPv4 packet (version=4, dest=8.8.8.8)
        let packet = vec![
            0x45, 0x00, 0x00, 0x14, // Version, IHL, TOS, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x11, 0x00, 0x00, // TTL, Protocol (UDP), Checksum
            0x0a, 0x00, 0x00, 0x01, // Source IP (10.0.0.1)
            0x08, 0x08, 0x08, 0x08, // Dest IP (8.8.8.8)
        ];

        let ip = IpPacket::parse(&packet).unwrap();
        assert_eq!(ip.version(), 4);
        assert_eq!(ip.destination(), Some(IpAddr::V4([8, 8, 8, 8].into())));
        assert_eq!(ip.protocol(), Some(17)); // UDP
    }
}
