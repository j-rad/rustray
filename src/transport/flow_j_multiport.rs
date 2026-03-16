// src/transport/flow_j_multiport.rs
//! Multiport UDP Transport for QUIC
//!
//! Manages a pool of UDP sockets to enable port hopping and connection migration.
//! This helps evade port-based throttling and makes a single QUIC connection
//! look like multiple independent flows to a DPI classifier.

use crate::error::Result;
use rand::Rng;
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Rotation strategy for the multiport pool.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MultiportStrategy {
    /// Rotate sequentially through a fixed pool of pre-bound ports.
    StaticPool,
    /// Randomly select a port from the pool on every rotation.
    DynamicRandom,
}

impl Default for MultiportStrategy {
    fn default() -> Self {
        Self::StaticPool
    }
}

/// A multiport pool that manages multiple sockets for QUIC packet rotation.
pub struct MultiportSocketPool {
    /// A collection of underlying Tokio UDP sockets bound to various ports.
    tokio_sockets: Vec<Arc<UdpSocket>>,
    /// Pre-cloned std::net::UdpSocket descriptors for quinn rebinding.
    std_sockets: Vec<std::net::UdpSocket>,
    port_range: (u16, u16),
    current_idx: usize,
    rotation_frequency: u32,
    packet_count: u32,
    current_port_sent: u32,
    current_port_lost: u32,
    strategy: MultiportStrategy,
    /// Optional attached Quinn endpoint for direct rebinding during rotations.
    quinn_endpoint: Option<quinn::Endpoint>,
}

impl MultiportSocketPool {
    /// Create a new multiport pool binding to the specified port range.
    pub async fn bind(
        listen_addr: &str,
        port_range: &str,
        _rotation_frequency: u32,
        strategy: MultiportStrategy,
    ) -> Result<Self> {
        let (start, end) = parse_port_range(port_range)?;
        let mut tokio_sockets = Vec::new();
        let mut std_sockets = Vec::new();

        info!(
            "Multiport: Binding to range {}-{} on {} using strategy {:?}",
            start, end, listen_addr, strategy
        );

        // Bind to a subset of ports for diversity
        let count = (end - start + 1).min(64);
        let step = ((end - start + 1) as f32 / count as f32).max(1.0) as u16;

        let mut available_ports: Vec<u16> = (0..count).map(|i| start + i * step).collect();
        // Shuffle ports for DynamicRandom initially
        if strategy == MultiportStrategy::DynamicRandom {
            available_ports.shuffle(&mut rand::thread_rng());
        }

        for port in available_ports {
            let addr = format!("{}:{}", listen_addr, port);
            match std::net::UdpSocket::bind(&addr) {
                Ok(std_socket) => {
                    std_socket.set_nonblocking(true)?;
                    let std_clone = std_socket.try_clone()?;
                    let tokio_socket = UdpSocket::from_std(std_socket)?;

                    tokio_sockets.push(Arc::new(tokio_socket));
                    std_sockets.push(std_clone);
                    debug!("Multiport: Bound to {}", addr);
                }
                Err(e) => {
                    warn!("Multiport: Failed to bind to {}: {}", addr, e);
                }
            }
        }

        if tokio_sockets.is_empty() {
            return Err(anyhow::anyhow!("Failed to bind to any ports in range"));
        }

        Ok(Self {
            tokio_sockets,
            std_sockets,
            port_range: (start, end),
            current_idx: 0,
            rotation_frequency: rand::thread_rng().gen_range(5..=15),
            packet_count: 0,
            current_port_sent: 0,
            current_port_lost: 0,
            strategy,
            quinn_endpoint: None,
        })
    }

    /// Attach a Quinn endpoint to the socket pool.
    /// When rotation occurs, `MultiportSocketPool` will automatically call `endpoint.rebind()`
    /// to seamlessly migrate the QUIC connection to the new local port.
    pub fn attach_quinn_endpoint(&mut self, endpoint: quinn::Endpoint) {
        debug!("Multiport: Attached Quinn endpoint for automatic rebinding");
        self.quinn_endpoint = Some(endpoint);
    }

    /// Get the currently active tokio socket.
    pub fn current_socket(&self) -> Arc<UdpSocket> {
        self.tokio_sockets[self.current_idx].clone()
    }

    /// Rotate to the next socket if the rotation frequency is reached.
    /// Returns `true` if a rotation occurred.
    pub fn rotate_if_needed(&mut self) -> bool {
        if self.rotation_frequency == 0 {
            return false;
        }

        self.packet_count += 1;
        self.current_port_sent += 1;

        // Failover: >20% loss (require at least 5 packets sent to compute a meaningful ratio)
        let high_loss = self.current_port_sent >= 5
            && (self.current_port_lost as f32 / self.current_port_sent as f32) > 0.2;

        if self.packet_count >= self.rotation_frequency || high_loss {
            if high_loss {
                warn!("Multiport: >20% packet loss detected, fast failover triggered");
            }
            self.packet_count = 0;
            self.current_port_sent = 0;
            self.current_port_lost = 0;
            self.rotation_frequency = rand::thread_rng().gen_range(5..=15);
            self.perform_rotation();
            return true;
        }
        false
    }

    /// Explicitly record a transmission failure / loss for the current port.
    pub fn record_loss(&mut self) {
        self.current_port_lost += 1;
    }

    /// Performs the actual socket rotation based on the configured strategy
    /// and triggers automatic failover mechanisms if the target is unreachable.
    fn perform_rotation(&mut self) {
        let old_idx = self.current_idx;

        match self.strategy {
            MultiportStrategy::StaticPool => {
                // Sequential rotation
                self.current_idx = (self.current_idx + 1) % self.tokio_sockets.len();
            }
            MultiportStrategy::DynamicRandom => {
                // Randomly hop to a different socket
                let mut rng = rand::thread_rng();
                let mut new_idx = rng.gen_range(0..self.tokio_sockets.len());
                // Ensure we actually change the port if possible
                if new_idx == self.current_idx && self.tokio_sockets.len() > 1 {
                    new_idx = (new_idx + 1) % self.tokio_sockets.len();
                }
                self.current_idx = new_idx;
            }
        }

        if old_idx != self.current_idx {
            debug!(
                "Multiport: Rotated local port to index {}",
                self.current_idx
            );

            // Integrate QUIC packet rotation using `quinn` over the pool of UDP sockets.
            if let Some(endpoint) = &self.quinn_endpoint {
                let current_std_sock = &self.std_sockets[self.current_idx];

                // std::net::UdpSocket clone logic for Quinn rebinding
                match current_std_sock.try_clone() {
                    Ok(std_sock) => {
                        if let Err(e) = endpoint.rebind(std_sock) {
                            warn!(
                                "Multiport [Failover]: Failed to rebind Quinn endpoint: {} - Reverting to previous port",
                                e
                            );
                            // Failover: revert back if rebinding explicitly fails in quinn.
                            self.current_idx = old_idx;
                        } else {
                            debug!(
                                "Multiport: Successfully rebound Quinn endpoint to new local port"
                            );
                        }
                    }
                    Err(e) => warn!("Multiport Quinn failover mapping error (try_clone): {}", e),
                }
            }
        }
    }

    /// Get all sockets currently in the pool as tokio UdpSockets.
    pub fn all_sockets(&self) -> Vec<Arc<UdpSocket>> {
        self.tokio_sockets.clone()
    }

    /// Get the associated port range.
    pub fn range(&self) -> (u16, u16) {
        self.port_range
    }
}

/// Parse a port range string like "10000-20000".
fn parse_port_range(range: &str) -> Result<(u16, u16)> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid port range format: {}", range));
    }

    let start = parts[0].parse()?;
    let end = parts[1].parse()?;

    if start > end {
        return Err(anyhow::anyhow!("Start port {} > end port {}", start, end));
    }

    Ok((start, end))
}
