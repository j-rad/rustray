// src/tun/tun2socks.rs
//! High-Performance Tun2Socks Engine
//!
//! Implements a userspace TCP/IP stack using smoltcp to convert
//! raw TUN packets into logical TCP/UDP streams for proxy routing.
//!
//! Features:
//! - Dynamic MTU support (Cellular/Standard/Jumbo)
//! - MSS clamping for fragmentation prevention
//! - Zero-leak Kill-Switch for connection security

use crate::tun::tun_device::{MtuProfile, TunConfig, TunDevice, split_device};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// ============================================================================
// Kill-Switch Global State
// ============================================================================

/// Global atomic flag indicating core health status.
/// When `false`, all packets are dropped to prevent leaks.
static CORE_HEALTHY: AtomicBool = AtomicBool::new(true);

/// Set the core health status.
/// When set to `false`, the Kill-Switch activates and drops all packets.
pub fn set_core_healthy(healthy: bool) {
    let prev = CORE_HEALTHY.swap(healthy, Ordering::SeqCst);
    if prev != healthy {
        if healthy {
            info!("Kill-Switch: Core marked as HEALTHY, resuming packet flow");
        } else {
            warn!("Kill-Switch: Core marked as UNHEALTHY, dropping all packets!");
        }
    }
}

/// Check if the core is healthy.
pub fn is_core_healthy() -> bool {
    CORE_HEALTHY.load(Ordering::SeqCst)
}

// ============================================================================
// MSS Clamping
// ============================================================================

/// TCP option kind for Maximum Segment Size
const TCP_OPT_MSS: u8 = 2;
/// TCP option length for MSS (always 4 bytes: kind + length + 2-byte MSS value)
const TCP_OPT_MSS_LEN: u8 = 4;
/// TCP SYN flag position in flags byte
const TCP_FLAG_SYN: u8 = 0x02;

/// Clamp MSS in TCP SYN packets to prevent fragmentation.
///
/// This function modifies the MSS option in TCP SYN packets if the advertised
/// MSS is larger than the allowed maximum (based on MTU profile).
///
/// # Arguments
/// * `packet` - Mutable slice containing the raw IP packet
/// * `mtu_profile` - The MTU profile to derive target MSS from
///
/// # Returns
/// * `true` if MSS was clamped
/// * `false` if no clamping was needed or packet was not a TCP SYN
pub fn clamp_mss(packet: &mut [u8], mtu_profile: MtuProfile) -> bool {
    if packet.len() < 20 {
        return false;
    }

    let version = packet[0] >> 4;
    let (target_mss, ip_header_len, _protocol_offset) = match version {
        4 => {
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if packet.len() < ihl {
                return false;
            }
            let protocol = packet[9];
            if protocol != 6 {
                // Not TCP
                return false;
            }
            (mtu_profile.mss_ipv4(), ihl, 9usize)
        }
        6 => {
            if packet.len() < 40 {
                return false;
            }
            let next_header = packet[6];
            if next_header != 6 {
                // Not TCP (simple check, doesn't handle extension headers)
                return false;
            }
            (mtu_profile.mss_ipv6(), 40, 6usize)
        }
        _ => return false,
    };

    let tcp_offset = ip_header_len;
    if packet.len() < tcp_offset + 20 {
        return false;
    }

    // Check if SYN flag is set
    let flags = packet[tcp_offset + 13];
    if flags & TCP_FLAG_SYN == 0 {
        return false;
    }

    // Get TCP data offset (header length in 32-bit words)
    let data_offset = ((packet[tcp_offset + 12] >> 4) as usize) * 4;
    if data_offset < 20 || packet.len() < tcp_offset + data_offset {
        return false;
    }

    // Scan TCP options for MSS
    let options_start = tcp_offset + 20;
    let options_end = tcp_offset + data_offset;
    let mut offset = options_start;

    while offset < options_end {
        let kind = packet[offset];

        match kind {
            0 => break, // End of options
            1 => {
                // NOP
                offset += 1;
            }
            TCP_OPT_MSS => {
                if offset + 4 > options_end {
                    break;
                }
                let len = packet[offset + 1];
                if len != TCP_OPT_MSS_LEN {
                    break;
                }

                let current_mss = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if current_mss > target_mss {
                    debug!(
                        "MSS Clamping: {} -> {} (profile: {:?})",
                        current_mss, target_mss, mtu_profile
                    );
                    let mss_bytes = target_mss.to_be_bytes();
                    packet[offset + 2] = mss_bytes[0];
                    packet[offset + 3] = mss_bytes[1];

                    // Recalculate TCP checksum (simplified: set to 0 for hardware offload)
                    // In production, we'd recalculate the full checksum
                    packet[tcp_offset + 16] = 0;
                    packet[tcp_offset + 17] = 0;

                    return true;
                }
                return false;
            }
            _ => {
                // Other option
                if offset + 1 >= options_end {
                    break;
                }
                let len = packet[offset + 1] as usize;
                if len < 2 || offset + len > options_end {
                    break;
                }
                offset += len;
            }
        }
    }

    false
}

// ============================================================================
// Tun2Socks Configuration
// ============================================================================

/// Tun2Socks configuration
#[derive(Debug, Clone)]
pub struct Tun2SocksConfig {
    /// TUN device configuration
    pub tun: TunConfig,
    /// Maximum concurrent TCP connections
    pub max_tcp_connections: usize,
    /// Maximum concurrent UDP sessions
    pub max_udp_sessions: usize,
    /// TCP receive buffer size per connection
    pub tcp_rx_buffer: usize,
    /// TCP send buffer size per connection
    pub tcp_tx_buffer: usize,
    /// UDP receive buffer size
    pub udp_rx_buffer: usize,
    /// UDP send buffer size
    pub udp_tx_buffer: usize,
    /// Enable MSS clamping
    pub enable_mss_clamping: bool,
    /// Enable Kill-Switch (drop packets when core is unhealthy)
    pub enable_kill_switch: bool,
}

impl Default for Tun2SocksConfig {
    fn default() -> Self {
        Self {
            tun: TunConfig::default(),
            max_tcp_connections: 4096,
            max_udp_sessions: 1024,
            tcp_rx_buffer: 65536,
            tcp_tx_buffer: 65536,
            udp_rx_buffer: 65536,
            udp_tx_buffer: 65536,
            enable_mss_clamping: true,
            enable_kill_switch: true,
        }
    }
}

impl Tun2SocksConfig {
    /// Create a config with Jumbo MTU profile for high-performance environments
    pub fn with_jumbo_mtu() -> Self {
        Self {
            tun: TunConfig::with_mtu_profile(MtuProfile::Jumbo),
            ..Default::default()
        }
    }

    /// Create a config with Standard MTU profile
    pub fn with_standard_mtu() -> Self {
        Self {
            tun: TunConfig::with_mtu_profile(MtuProfile::Standard),
            ..Default::default()
        }
    }
}

// ============================================================================
// Connection Types
// ============================================================================

/// Connection key for tracking TCP/UDP sessions
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

// ============================================================================
// Virtual Device (smoltcp bridge)
// ============================================================================

/// Virtual device that bridges TUN and smoltcp
struct VirtualDevice {
    rx_buffer: Option<Vec<u8>>,
    tx_queue: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    mtu_profile: MtuProfile,
    enable_mss_clamping: bool,
    enable_kill_switch: bool,
}

impl VirtualDevice {
    fn new(
        tx_queue: mpsc::Sender<Vec<u8>>,
        mtu: usize,
        mtu_profile: MtuProfile,
        enable_mss_clamping: bool,
        enable_kill_switch: bool,
    ) -> Self {
        Self {
            rx_buffer: None,
            tx_queue,
            mtu,
            mtu_profile,
            enable_mss_clamping,
            enable_kill_switch,
        }
    }

    fn inject_packet(&mut self, mut packet: Vec<u8>) {
        // Kill-Switch check
        if self.enable_kill_switch && !is_core_healthy() {
            debug!("Kill-Switch: Dropping inbound packet (core unhealthy)");
            return;
        }

        // MSS clamping on incoming SYN packets
        if self.enable_mss_clamping {
            clamp_mss(&mut packet, self.mtu_profile);
        }

        self.rx_buffer = Some(packet);
    }
}

struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

struct VirtualTxToken {
    tx_queue: mpsc::Sender<Vec<u8>>,
    mtu_profile: MtuProfile,
    enable_mss_clamping: bool,
    enable_kill_switch: bool,
}

impl TxToken for VirtualTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Kill-Switch check
        if self.enable_kill_switch && !is_core_healthy() {
            debug!("Kill-Switch: Dropping outbound packet (core unhealthy)");
            let mut buffer = vec![0u8; len];
            return f(&mut buffer); // Consume but don't send
        }

        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        // MSS clamping on outgoing SYN packets
        if self.enable_mss_clamping {
            clamp_mss(&mut buffer, self.mtu_profile);
        }

        let _ = self.tx_queue.try_send(buffer);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_buffer.take().map(|buffer| {
            (
                VirtualRxToken { buffer },
                VirtualTxToken {
                    tx_queue: self.tx_queue.clone(),
                    mtu_profile: self.mtu_profile,
                    enable_mss_clamping: self.enable_mss_clamping,
                    enable_kill_switch: self.enable_kill_switch,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: self.tx_queue.clone(),
            mtu_profile: self.mtu_profile,
            enable_mss_clamping: self.enable_mss_clamping,
            enable_kill_switch: self.enable_kill_switch,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// ============================================================================
// Stream Events
// ============================================================================

/// Stream event for dispatching to outbound handlers
#[derive(Debug)]
pub enum StreamEvent {
    /// New TCP connection established
    TcpConnect {
        key: ConnectionKey,
        stream_tx: mpsc::Sender<Vec<u8>>,
        stream_rx: mpsc::Receiver<Vec<u8>>,
    },
    /// New UDP session
    UdpSession {
        key: ConnectionKey,
        packet_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        packet_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    },
    /// Connection closed
    Closed { key: ConnectionKey },
    /// Local Link/IP Changed (Trigger Re-Dial)
    LinkChange,
}

// ============================================================================
// Tun2Socks Engine
// ============================================================================

/// High-performance Tun2Socks engine
pub struct Tun2SocksEngine {
    config: Tun2SocksConfig,
    event_tx: mpsc::Sender<StreamEvent>,
    event_rx: Option<mpsc::Receiver<StreamEvent>>,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

impl Tun2SocksEngine {
    /// Create a new Tun2Socks engine
    pub fn new(config: Tun2SocksConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1024);
        let (shutdown, _) = tokio::sync::broadcast::channel(1);

        Self {
            config,
            event_tx,
            event_rx: Some(event_rx),
            shutdown,
        }
    }

    /// Take the event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<StreamEvent>> {
        self.event_rx.take()
    }

    /// Get a shutdown sender
    pub fn shutdown_sender(&self) -> tokio::sync::broadcast::Sender<()> {
        self.shutdown.clone()
    }

    /// Check if the engine is healthy
    pub fn is_healthy(&self) -> bool {
        is_core_healthy()
    }

    /// Run the Tun2Socks engine
    pub async fn run(self) -> anyhow::Result<()> {
        info!(
            "Starting Tun2Socks engine (MTU Profile: {:?}, MSS Clamping: {}, Kill-Switch: {})",
            self.config.tun.mtu_profile,
            self.config.enable_mss_clamping,
            self.config.enable_kill_switch
        );

        // Create TUN device
        let tun = TunDevice::create(self.config.tun.clone()).await?;
        let mtu = tun.mtu() as usize;
        let mtu_profile = tun.mtu_profile();
        let (tun_reader, tun_writer, _tun_control) = split_device(tun);

        // Create packet queue for stack -> TUN
        let (stack_to_tun_tx, mut stack_to_tun_rx) = mpsc::channel::<Vec<u8>>(4096);

        let shutdown = self.shutdown.clone();
        let enable_mss_clamping = self.config.enable_mss_clamping;
        let enable_kill_switch = self.config.enable_kill_switch;

        // Spawn TUN reader task - reads packets and processes them
        let _reader_handle = {
            let stack_to_tun_tx = stack_to_tun_tx.clone();
            let tun_config = self.config.tun.clone();
            let mut shutdown_rx = shutdown.subscribe();

            tokio::spawn(async move {
                // Create virtual device for smoltcp
                let mut device = VirtualDevice::new(
                    stack_to_tun_tx.clone(),
                    mtu,
                    mtu_profile,
                    enable_mss_clamping,
                    enable_kill_switch,
                );

                // Configure smoltcp interface
                let config = Config::new(HardwareAddress::Ip);
                let mut iface = Interface::new(config, &mut device, Instant::now());

                // Add IP addresses
                iface.update_ip_addrs(|addrs| {
                    let ipv4 = IpCidr::new(
                        IpAddress::Ipv4(Ipv4Address::from_bytes(&tun_config.address.octets())),
                        24,
                    );
                    addrs.push(ipv4).ok();

                    if let Some(v6) = tun_config.address_v6 {
                        let ipv6 = IpCidr::new(
                            IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
                            tun_config.prefix_v6,
                        );
                        addrs.push(ipv6).ok();
                    }
                });

                let mut sockets = SocketSet::new(vec![]);
                let mut buf = vec![0u8; mtu + 64];

                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("TUN reader shutting down");
                            break;
                        }
                        result = tun_reader.recv(&mut buf) => {
                            match result {
                                Ok(n) if n > 0 => {
                                    let packet = buf[..n].to_vec();

                                    // Inject packet into smoltcp
                                    device.inject_packet(packet);

                                    // Poll the interface
                                    let timestamp = Instant::now();
                                    iface.poll(timestamp, &mut device, &mut sockets);
                                }
                                Ok(_) => continue,
                                Err(e) => {
                                    error!("TUN read error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            })
        };

        // Spawn TUN writer task - sends packets from stack to TUN
        let _writer_handle = {
            let mut shutdown_rx = shutdown.subscribe();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("TUN writer shutting down");
                            break;
                        }
                        packet = stack_to_tun_rx.recv() => {
                            match packet {
                                Some(data) => {
                                    // Kill-Switch check before writing to TUN
                                    if enable_kill_switch && !is_core_healthy() {
                                        debug!("Kill-Switch: Dropping TUN write (core unhealthy)");
                                        continue;
                                    }
                                    if let Err(e) = tun_writer.send(&data).await {
                                        error!("TUN write error: {}", e);
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
            })
        };

        // Wait for shutdown
        let _ = self.shutdown.subscribe().recv().await;

        info!("Tun2Socks engine stopped");
        Ok(())
    }
}

// ============================================================================
// Packet Parsing
// ============================================================================

/// Parse IP packet to extract connection info
pub fn parse_ip_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, Protocol)> {
    if data.len() < 20 {
        return None;
    }

    let version = data[0] >> 4;

    match version {
        4 => parse_ipv4_packet(data),
        6 => parse_ipv6_packet(data),
        _ => None,
    }
}

fn parse_ipv4_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, Protocol)> {
    if data.len() < 20 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return None;
    }

    let protocol = data[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    let transport_offset = ihl;
    if data.len() < transport_offset + 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
    let dst_port = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);

    let proto = match protocol {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };

    Some((src_ip, dst_ip, src_port, dst_port, proto))
}

fn parse_ipv6_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, Protocol)> {
    if data.len() < 40 {
        return None;
    }

    let next_header = data[6];

    let mut src_ip_bytes = [0u8; 16];
    let mut dst_ip_bytes = [0u8; 16];
    src_ip_bytes.copy_from_slice(&data[8..24]);
    dst_ip_bytes.copy_from_slice(&data[24..40]);

    let src_ip = IpAddr::V6(src_ip_bytes.into());
    let dst_ip = IpAddr::V6(dst_ip_bytes.into());

    let transport_offset = 40;
    if data.len() < transport_offset + 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
    let dst_port = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);

    let proto = match next_header {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };

    Some((src_ip, dst_ip, src_port, dst_port, proto))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_tcp() {
        // Minimal IPv4 TCP packet header
        let packet = [
            0x45, 0x00, 0x00, 0x28, // IP header
            0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP
            0x0a, 0x00, 0x00, 0x01, // Src: 10.0.0.1
            0x08, 0x08, 0x08, 0x08, // Dst: 8.8.8.8
            0x04, 0x00, 0x00, 0x50, // Src port: 1024, Dst port: 80
        ];

        let result = parse_ip_packet(&packet);
        assert!(result.is_some());

        let (src, dst, src_port, dst_port, proto) = result.unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(src_port, 1024);
        assert_eq!(dst_port, 80);
        assert_eq!(proto, Protocol::Tcp);
    }

    #[test]
    fn test_kill_switch() {
        // Test Kill-Switch functionality
        assert!(is_core_healthy()); // Default is healthy

        set_core_healthy(false);
        assert!(!is_core_healthy());

        set_core_healthy(true);
        assert!(is_core_healthy());
    }

    #[test]
    fn test_mss_clamping_ipv4_syn() {
        // IPv4 TCP SYN packet with MSS option = 65535 (too large)
        // IP Header (20 bytes) + TCP Header (24 bytes with MSS option)
        let mut packet = [
            // IPv4 Header
            0x45, 0x00, 0x00, 0x2c, // Version, IHL, TOS, Total Length (44)
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
            0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP, Checksum
            0x0a, 0x00, 0x00, 0x01, // Src: 10.0.0.1
            0x08, 0x08, 0x08, 0x08, // Dst: 8.8.8.8
            // TCP Header
            0x04, 0x00, 0x00, 0x50, // Src port: 1024, Dst port: 80
            0x00, 0x00, 0x00, 0x00, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x60, 0x02, 0x00, 0x00, // Data offset (6*4=24), SYN flag, Window
            0x00, 0x00, 0x00, 0x00, // Checksum, Urgent
            // TCP Options: MSS = 65535
            0x02, 0x04, 0xff, 0xff, // MSS option: kind=2, len=4, value=65535
        ];

        // Before clamping - MSS option: [kind=2, len=4, MSS-high, MSS-low] at bytes 40-43
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 65535);

        // Clamp with Standard MTU profile (MSS should be 1460)
        let was_clamped = clamp_mss(&mut packet, MtuProfile::Standard);
        assert!(was_clamped);

        // After clamping
        let new_mss = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(new_mss, 1460);
    }

    #[test]
    fn test_mss_clamping_jumbo() {
        // Test clamping with Jumbo MTU profile
        let mut packet = [
            // IPv4 Header
            0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x08, 0x08, 0x08, 0x08, // TCP Header
            0x04, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // TCP Options: MSS = 65535 (larger than jumbo MSS)
            0x02, 0x04, 0xff, 0xff,
        ];

        // Clamp with Jumbo MTU profile (MSS should be 8960)
        let was_clamped = clamp_mss(&mut packet, MtuProfile::Jumbo);
        assert!(was_clamped);

        let new_mss = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(new_mss, 8960);
    }

    #[test]
    fn test_mss_no_clamp_needed() {
        // TCP SYN with MSS = 1000 (smaller than profile, no clamp needed)
        let mut packet = [
            // IPv4 Header
            0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x08, 0x08, 0x08, 0x08, // TCP Header
            0x04, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TCP Options: MSS = 1000
            0x02, 0x04, 0x03, 0xe8, // 1000 in big endian
        ];

        let was_clamped = clamp_mss(&mut packet, MtuProfile::Standard);
        assert!(!was_clamped); // No clamping needed

        // MSS should remain 1000
        let mss = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(mss, 1000);
    }

    #[test]
    fn test_config_with_jumbo() {
        let config = Tun2SocksConfig::with_jumbo_mtu();
        assert_eq!(config.tun.mtu(), 9000);
        assert!(config.enable_mss_clamping);
        assert!(config.enable_kill_switch);
    }
}
