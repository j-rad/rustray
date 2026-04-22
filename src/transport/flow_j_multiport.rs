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
#[derive(Default)]
pub enum MultiportStrategy {
    /// Rotate sequentially through a fixed pool of pre-bound ports.
    #[default]
    StaticPool,
    /// Randomly select a port from the pool on every rotation.
    DynamicRandom,
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

// ============================================================================
// MULTIPORT ASYNC UDP SOCKET WRAPPER
// ============================================================================

/// Per-port packet counters for ICMP-unreachable detection and adaptive rotation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PortHealth {
    /// Local address of this socket.
    local_addr: SocketAddr,
    /// Total datagrams sent through this port.
    sent: u64,
    /// Consecutive send failures (ICMP unreachable, ECONNREFUSED, etc.).
    consecutive_failures: u32,
    /// Whether this port has been marked dead and removed from rotation.
    dead: bool,
}

impl PortHealth {
    fn new(addr: SocketAddr) -> Self {
        Self {
            local_addr: addr,
            sent: 0,
            consecutive_failures: 0,
            dead: false,
        }
    }

    /// Record a successful send.
    fn record_success(&mut self) {
        self.sent += 1;
        self.consecutive_failures = 0;
    }

    /// Record a send failure. Returns true if the port should be considered dead.
    fn record_failure(&mut self) -> bool {
        self.consecutive_failures += 1;
        // Mark dead after 5 consecutive failures (ICMP unreachable pattern)
        if self.consecutive_failures >= 5 {
            self.dead = true;
        }
        self.dead
    }

    /// Loss ratio (0.0 to 1.0).
    #[allow(dead_code)]
    fn loss_ratio(&self) -> f32 {
        if self.sent == 0 {
            return 0.0;
        }
        self.consecutive_failures as f32 / self.sent.min(100) as f32
    }
}

/// Manages datagram-level round-robin with per-packet jitter across
/// multiple UDP sockets. Each `select_socket()` call returns the next
/// healthy socket index, applying a small random offset to break
/// deterministic patterns visible to DPI.
pub struct RoundRobinJitter {
    /// Number of sockets in the pool.
    pool_size: usize,
    /// Current index in the round-robin sequence.
    cursor: usize,
    /// Datagrams sent since last jitter offset.
    since_jitter: u32,
    /// Jitter window: after this many sends, apply a random skip.
    jitter_window: u32,
}

impl RoundRobinJitter {
    /// Create a new jitter selector for a pool of `pool_size` sockets.
    pub fn new(pool_size: usize) -> Self {
        Self {
            pool_size,
            cursor: 0,
            since_jitter: 0,
            jitter_window: rand::thread_rng().gen_range(3..=8),
        }
    }

    /// Select the next socket index with jitter applied.
    pub fn select(&mut self, health: &[PortHealth]) -> usize {
        if self.pool_size == 0 {
            return 0;
        }

        self.since_jitter += 1;

        // Apply jitter: occasionally skip 1-2 sockets to break patterns
        if self.since_jitter >= self.jitter_window {
            self.since_jitter = 0;
            self.jitter_window = rand::thread_rng().gen_range(3..=8);
            let skip = rand::thread_rng().gen_range(1..=2);
            self.cursor = (self.cursor + skip) % self.pool_size;
        }

        // Find next healthy socket
        let start = self.cursor;
        loop {
            if self.cursor < health.len() && !health[self.cursor].dead {
                let selected = self.cursor;
                self.cursor = (self.cursor + 1) % self.pool_size;
                return selected;
            }
            self.cursor = (self.cursor + 1) % self.pool_size;
            if self.cursor == start {
                // All ports dead; return first one as fallback
                return 0;
            }
        }
    }
}

/// Dynamically re-bind a new random port within the configured range,
/// replacing a dead port in the pool.
pub async fn reroll_port(
    listen_addr: &str,
    port_range: (u16, u16),
    existing_ports: &[SocketAddr],
) -> Result<(Arc<UdpSocket>, std::net::UdpSocket, SocketAddr)> {
    let mut rng = rand::thread_rng();
    let _range_size = (port_range.1 - port_range.0 + 1) as usize;

    // Try up to 20 random ports within the range
    for _ in 0..20 {
        let port = rng.gen_range(port_range.0..=port_range.1);

        // Skip if this port is already in use
        let addr_str = format!("{}:{}", listen_addr, port);
        let candidate: SocketAddr = addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        if existing_ports.contains(&candidate) {
            continue;
        }

        match std::net::UdpSocket::bind(&addr_str) {
            Ok(std_socket) => {
                std_socket.set_nonblocking(true)?;
                let std_clone = std_socket.try_clone()?;
                let local_addr = std_socket.local_addr()?;
                let tokio_socket = UdpSocket::from_std(std_socket)?;

                info!("Multiport: Re-rolled dead port → {}", local_addr);
                return Ok((Arc::new(tokio_socket), std_clone, local_addr));
            }
            Err(_) => continue,
        }
    }

    Err(anyhow::anyhow!(
        "Failed to re-roll port after 20 attempts in range {}-{}",
        port_range.0,
        port_range.1,
    ))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_range_valid() {
        let (start, end) = parse_port_range("10000-20000").unwrap();
        assert_eq!(start, 10000);
        assert_eq!(end, 20000);
    }

    #[test]
    fn test_parse_port_range_invalid() {
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("20000-10000").is_err());
    }

    #[test]
    fn test_port_health_failure_detection() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut health = PortHealth::new(addr);

        for _ in 0..4 {
            assert!(!health.record_failure());
        }
        // 5th consecutive failure should mark dead
        assert!(health.record_failure());
        assert!(health.dead);
    }

    #[test]
    fn test_port_health_recovery() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut health = PortHealth::new(addr);

        // 3 failures then a success resets counter
        for _ in 0..3 {
            health.record_failure();
        }
        health.record_success();
        assert_eq!(health.consecutive_failures, 0);
        assert!(!health.dead);
    }

    #[test]
    fn test_round_robin_jitter_cycles() {
        let health = vec![
            PortHealth::new("127.0.0.1:5000".parse().unwrap()),
            PortHealth::new("127.0.0.1:5001".parse().unwrap()),
            PortHealth::new("127.0.0.1:5002".parse().unwrap()),
        ];
        let mut rr = RoundRobinJitter::new(3);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            seen.insert(rr.select(&health));
        }
        // Should visit all 3 sockets
        assert_eq!(seen.len(), 3, "All sockets should be visited");
    }

    #[test]
    fn test_round_robin_skips_dead_ports() {
        let mut health = vec![
            PortHealth::new("127.0.0.1:5000".parse().unwrap()),
            PortHealth::new("127.0.0.1:5001".parse().unwrap()),
            PortHealth::new("127.0.0.1:5002".parse().unwrap()),
        ];
        health[1].dead = true;

        let mut rr = RoundRobinJitter::new(3);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            seen.insert(rr.select(&health));
        }
        // Should not select index 1 (dead)
        assert!(!seen.contains(&1), "Dead port should not be selected");
        assert!(seen.contains(&0));
        assert!(seen.contains(&2));
    }

    #[tokio::test]
    async fn test_multiport_bind_diverse_ports() {
        let pool = MultiportSocketPool::bind(
            "127.0.0.1",
            "30000-30063",
            5,
            MultiportStrategy::DynamicRandom,
        )
        .await
        .unwrap();

        // Should have bound multiple sockets
        assert!(
            pool.tokio_sockets.len() >= 2,
            "Expected ≥2 sockets, got {}",
            pool.tokio_sockets.len()
        );

        // All sockets should have unique local ports
        let mut ports = std::collections::HashSet::new();
        for sock in &pool.tokio_sockets {
            ports.insert(sock.local_addr().unwrap().port());
        }
        assert_eq!(
            ports.len(),
            pool.tokio_sockets.len(),
            "All ports should be unique"
        );
    }

    #[test]
    fn test_rotation_mechanics() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut pool = rt.block_on(async {
            MultiportSocketPool::bind("127.0.0.1", "31000-31015", 5, MultiportStrategy::StaticPool)
                .await
                .unwrap()
        });

        let initial_idx = pool.current_idx;

        // Send enough packets to trigger rotation
        for _ in 0..20 {
            pool.rotate_if_needed();
        }

        // At least one rotation should have occurred
        assert_ne!(
            pool.current_idx, initial_idx,
            "At least one rotation should occur after 20 packets"
        );
    }

    #[tokio::test]
    async fn test_reroll_port() {
        let existing: Vec<SocketAddr> = vec!["127.0.0.1:32000".parse().unwrap()];
        let result = reroll_port("127.0.0.1", (32000, 32063), &existing).await;
        assert!(result.is_ok(), "Should successfully reroll a port");
        let (_, _, addr) = result.unwrap();
        assert_ne!(addr.port(), 32000, "Should not reuse existing port");
        assert!(addr.port() >= 32000 && addr.port() <= 32063);
    }
}
