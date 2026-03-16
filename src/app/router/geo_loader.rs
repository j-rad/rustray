// src/app/router/geo_loader.rs
//! Production-Grade Geo-Asset Manager (Iran Optimized)
//!
use crate::app::platform_paths;
// This module handles loading, verification, and efficient matching
// against GeoIP and GeoSite data files. Features include:
//
// - Iranian IP range fast-path for local traffic (Shatel, MCI, Irancell)
// - Binary search matching for O(log n) IP lookups
// - Thread-safe concurrent access
// - Integration with chocolate4u/iran-clash-rules logic

use crate::error::Result;
use prost::Message;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tracing::{info, warn};

// Re-export from assets.rs
use super::assets::{Domain, DomainType, GeoIp, GeoSite};
use memmap2::Mmap;
use prost::encoding::{self, WireType};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default cache directory
#[allow(dead_code)]
const DEFAULT_CACHE_DIR: &str = "./assets";

// ============================================================================
// IRANIAN IP RANGES (FAST PATH)
// Major Iranian ISPs and data centers for direct routing
// Based on chocolate4u/iran-clash-rules
// ============================================================================

/// Iranian IP ranges for fast-path matching (CIDR format)
/// These are the major Iranian ISPs that should always route directly
const IRANIAN_IPV4_RANGES: &[(&str, &str)] = &[
    // Major ISPs
    ("2.144.0.0", "2.159.255.255"),     // Shatel
    ("2.176.0.0", "2.191.255.255"),     // MCI (Mobile Telecommunication)
    ("5.52.0.0", "5.55.255.255"),       // Irancell
    ("5.56.0.0", "5.63.255.255"),       // Irancell
    ("5.104.0.0", "5.107.255.255"),     // RighTel
    ("5.112.0.0", "5.127.255.255"),     // ITC
    ("5.160.0.0", "5.175.255.255"),     // ITC
    ("5.200.0.0", "5.207.255.255"),     // ITC
    ("5.208.0.0", "5.223.255.255"),     // TIC
    ("31.2.0.0", "31.3.255.255"),       // Pardis Technology Park
    ("31.14.0.0", "31.15.255.255"),     // Afranet
    ("31.24.0.0", "31.25.255.255"),     // Rightel
    ("31.56.0.0", "31.63.255.255"),     // Afranet
    ("37.32.0.0", "37.63.255.255"),     // Various ISPs
    ("37.98.0.0", "37.98.255.255"),     // Arax
    ("37.114.0.0", "37.139.255.255"),   // Various Datacenters
    ("37.143.0.0", "37.143.255.255"),   // Arin
    ("37.148.0.0", "37.151.255.255"),   // Afranet
    ("37.152.0.0", "37.159.255.255"),   // Fanava
    ("37.191.0.0", "37.191.255.255"),   // Talia
    ("37.202.0.0", "37.203.255.255"),   // Shatel
    ("37.254.0.0", "37.254.255.255"),   // Pars Online
    ("46.21.0.0", "46.21.255.255"),     // Pardis
    ("46.28.0.0", "46.28.255.255"),     // Afranet/Parsun
    ("46.34.0.0", "46.35.255.255"),     // Asiatech
    ("46.36.0.0", "46.39.255.255"),     // Respina
    ("46.41.0.0", "46.41.255.255"),     // ITMC
    ("46.51.0.0", "46.51.255.255"),     // Dade Pardazi Fanava
    ("46.62.0.0", "46.63.255.255"),     // Rayaneh Pardaz
    ("46.100.0.0", "46.103.255.255"),   // Shatel
    ("46.143.0.0", "46.143.255.255"),   // Mobin Net
    ("46.148.0.0", "46.148.255.255"),   // Sairan
    ("46.164.0.0", "46.167.255.255"),   // Respina
    ("46.182.0.0", "46.183.255.255"),   // Fanava
    ("46.209.0.0", "46.209.255.255"),   // Pars Online
    ("46.224.0.0", "46.227.255.255"),   // Irancell
    ("46.235.0.0", "46.235.255.255"),   // Various
    ("46.245.0.0", "46.245.255.255"),   // Pars Online
    ("46.248.0.0", "46.251.255.255"),   // Asiatech
    ("62.32.0.0", "62.32.255.255"),     // ITMC
    ("62.60.0.0", "62.60.255.255"),     // DCI
    ("62.102.0.0", "62.102.255.255"),   // DCI
    ("62.220.0.0", "62.220.255.255"),   // Arax
    ("63.243.0.0", "63.243.255.255"),   // Parsun
    ("65.75.0.0", "65.75.255.255"),     // ITC
    ("66.79.0.0", "66.79.255.255"),     // Afranet
    ("69.94.0.0", "69.94.255.255"),     // Bamdad Kowsar
    ("78.38.0.0", "78.39.255.255"),     // Shatel
    ("78.109.0.0", "78.109.255.255"),   // Gostaresh
    ("78.110.0.0", "78.111.255.255"),   // Pars Data
    ("78.152.0.0", "78.159.255.255"),   // MCI
    ("79.127.0.0", "79.127.255.255"),   // Asiatech
    ("79.174.0.0", "79.175.255.255"),   // Afranet
    ("80.66.0.0", "80.66.255.255"),     // Dade Pardazi
    ("80.71.0.0", "80.71.255.255"),     // ITC
    ("80.75.0.0", "80.75.255.255"),     // Aria Shatel
    ("80.191.0.0", "80.191.255.255"),   // Afranet
    ("80.210.0.0", "80.210.255.255"),   // ADSL
    ("80.231.0.0", "80.231.255.255"),   // Mobinnet
    ("80.242.0.0", "80.242.255.255"),   // Neda
    ("80.250.0.0", "80.250.255.255"),   // Pardis
    ("81.12.0.0", "81.12.255.255"),     // Rayaneh
    ("81.14.0.0", "81.14.255.255"),     // Tebyan
    ("81.16.0.0", "81.16.255.255"),     // Fanava
    ("81.28.0.0", "81.31.255.255"),     // Mihan Host
    ("81.29.0.0", "81.29.255.255"),     // Afranet
    ("81.31.0.0", "81.31.255.255"),     // Afranet
    ("81.90.0.0", "81.92.255.255"),     // Pars Online
    ("81.163.0.0", "81.163.255.255"),   // Shatel
    ("82.99.0.0", "82.99.255.255"),     // Respina
    ("83.120.0.0", "83.123.255.255"),   // Afranet
    ("83.147.0.0", "83.147.255.255"),   // Shatel
    ("84.47.0.0", "84.47.255.255"),     // Shatel
    ("84.241.0.0", "84.241.255.255"),   // Shatel
    ("85.9.0.0", "85.9.255.255"),       // Afranet
    ("85.15.0.0", "85.15.255.255"),     // Mobinnet
    ("85.133.0.0", "85.133.255.255"),   // Pishgaman Tose
    ("85.185.0.0", "85.185.255.255"),   // TCI
    ("85.198.0.0", "85.198.255.255"),   // Datis
    ("85.204.0.0", "85.204.255.255"),   // ITC
    ("85.208.0.0", "85.208.255.255"),   // Various
    ("86.55.0.0", "86.57.255.255"),     // Aria Shatel
    ("86.104.0.0", "86.109.255.255"),   // Various
    ("87.107.0.0", "87.107.255.255"),   // ADSL
    ("87.236.0.0", "87.236.255.255"),   // HDMC
    ("87.247.0.0", "87.248.255.255"),   // Pardazesh Elec
    ("87.251.0.0", "87.251.255.255"),   // Mobin Net
    ("89.32.0.0", "89.33.255.255"),     // Fanava
    ("89.34.0.0", "89.35.255.255"),     // Asiatech
    ("89.38.0.0", "89.39.255.255"),     // Shatel
    ("89.42.0.0", "89.43.255.255"),     // Pars Online
    ("89.144.0.0", "89.144.255.255"),   // Mobinnet
    ("89.165.0.0", "89.165.255.255"),   // Parsun
    ("89.196.0.0", "89.196.255.255"),   // Shatel
    ("89.198.0.0", "89.199.255.255"),   // Shatel
    ("89.219.0.0", "89.219.255.255"),   // Asiatech
    ("89.235.0.0", "89.235.255.255"),   // Afranet
    ("91.92.0.0", "91.92.255.255"),     // Various
    ("91.98.0.0", "91.99.255.255"),     // Afranet
    ("91.106.0.0", "91.107.255.255"),   // Rightel
    ("91.108.0.0", "91.109.255.255"),   // ITC
    ("91.184.0.0", "91.184.255.255"),   // Various
    ("91.185.0.0", "91.185.255.255"),   // Various
    ("91.221.0.0", "91.239.255.255"),   // Various
    ("91.240.0.0", "91.243.255.255"),   // Pardaz
    ("91.244.0.0", "91.251.255.255"),   // Various
    ("92.42.0.0", "92.42.255.255"),     // Mabna
    ("92.50.0.0", "92.50.255.255"),     // Shatel
    ("92.61.0.0", "92.61.255.255"),     // Various
    ("92.114.0.0", "92.115.255.255"),   // Various
    ("92.119.0.0", "92.119.255.255"),   // Various
    ("93.88.0.0", "93.88.255.255"),     // Various
    ("93.110.0.0", "93.110.255.255"),   // Afranet
    ("93.113.0.0", "93.113.255.255"),   // Mobin Net
    ("93.114.0.0", "93.115.255.255"),   // Mobinnet
    ("93.117.0.0", "93.126.255.255"),   // Various Iran
    ("94.24.0.0", "94.24.255.255"),     // Shatel
    ("94.74.0.0", "94.74.255.255"),     // Various
    ("94.101.0.0", "94.101.255.255"),   // Fava
    ("94.139.0.0", "94.139.255.255"),   // Datis
    ("94.176.0.0", "94.176.255.255"),   // Shatel
    ("94.177.0.0", "94.177.255.255"),   // Various
    ("94.180.0.0", "94.183.255.255"),   // TCI
    ("94.232.0.0", "94.232.255.255"),   // Various
    ("94.241.0.0", "94.241.255.255"),   // Shatel
    ("95.38.0.0", "95.39.255.255"),     // TCI
    ("95.80.0.0", "95.80.255.255"),     // Amin IDC
    ("95.81.0.0", "95.81.255.255"),     // Various
    ("95.82.0.0", "95.82.255.255"),     // Various
    ("95.130.0.0", "95.130.255.255"),   // DCI
    ("95.142.0.0", "95.143.255.255"),   // Pars Online
    ("95.156.0.0", "95.156.255.255"),   // AUA
    ("95.162.0.0", "95.162.255.255"),   // IDC
    ("109.72.0.0", "109.72.255.255"),   // Asiatech
    ("109.74.0.0", "109.74.255.255"),   // Various
    ("109.94.0.0", "109.94.255.255"),   // Various
    ("109.108.0.0", "109.110.255.255"), // Various
    ("109.122.0.0", "109.122.255.255"), // Shatel
    ("109.125.0.0", "109.125.255.255"), // Pars Online
    ("109.162.0.0", "109.163.255.255"), // Various
    ("109.201.0.0", "109.201.255.255"), // Fava
    ("109.203.0.0", "109.203.255.255"), // Various
    ("109.230.0.0", "109.230.255.255"), // Various
    ("109.238.0.0", "109.238.255.255"), // Various
    ("128.65.0.0", "128.65.255.255"),   // Shatel
    ("130.193.0.0", "130.193.255.255"), // IPM
    ("130.244.0.0", "130.244.255.255"), // Shatel
    ("139.28.0.0", "139.28.255.255"),   // Various
    ("144.76.0.0", "144.76.255.255"),   // Hetzner (some Iranian hosting)
    ("151.232.0.0", "151.239.255.255"), // MCI
    ("152.89.0.0", "152.89.255.255"),   // Various
    ("158.58.0.0", "158.58.255.255"),   // Various
    ("159.20.0.0", "159.20.255.255"),   // Various
    ("164.138.0.0", "164.138.255.255"), // Various
    ("164.215.0.0", "164.215.255.255"), // Shatel
    ("176.12.0.0", "176.12.255.255"),   // Shatel
    ("176.56.0.0", "176.56.255.255"),   // Various
    ("176.65.0.0", "176.65.255.255"),   // Various
    ("176.101.0.0", "176.101.255.255"), // Various
    ("176.102.0.0", "176.102.255.255"), // Various
    ("176.221.0.0", "176.221.255.255"), // Fanava
    ("176.223.0.0", "176.223.255.255"), // Various
    ("178.21.0.0", "178.21.255.255"),   // Various
    ("178.22.0.0", "178.22.255.255"),   // Shatel
    ("178.131.0.0", "178.131.255.255"), // TCI
    ("178.169.0.0", "178.169.255.255"), // Various
    ("178.173.0.0", "178.173.255.255"), // Various
    ("178.215.0.0", "178.215.255.255"), // Asiatech
    ("178.216.0.0", "178.216.255.255"), // Various
    ("178.219.0.0", "178.219.255.255"), // Various
    ("178.236.0.0", "178.236.255.255"), // Various
    ("178.238.0.0", "178.238.255.255"), // Various
    ("178.239.0.0", "178.239.255.255"), // Fanava
    ("178.248.0.0", "178.248.255.255"), // Various
    ("178.251.0.0", "178.251.255.255"), // Various
    ("178.252.0.0", "178.252.255.255"), // Various
    ("178.253.0.0", "178.253.255.255"), // Various
    ("185.1.0.0", "185.255.255.255"),   // Many Iranian allocations (wide range)
    ("188.0.0.0", "188.0.255.255"),     // Various
    ("188.75.0.0", "188.75.255.255"),   // Various
    ("188.94.0.0", "188.94.255.255"),   // Various
    ("188.95.0.0", "188.95.255.255"),   // Various
    ("188.118.0.0", "188.118.255.255"), // Various
    ("188.121.0.0", "188.121.255.255"), // Shatel
    ("188.136.0.0", "188.136.255.255"), // Various
    ("188.158.0.0", "188.159.255.255"), // Various
    ("188.192.0.0", "188.192.255.255"), // Fanava
    ("188.208.0.0", "188.215.255.255"), // TCI
    ("188.229.0.0", "188.229.255.255"), // Various
    ("188.230.0.0", "188.230.255.255"), // Shatel
    ("188.240.0.0", "188.240.255.255"), // Various
    ("188.253.0.0", "188.253.255.255"), // Shatel
    ("192.15.0.0", "192.15.255.255"),   // Various
    ("193.8.0.0", "193.8.255.255"),     // ITC
    ("193.19.0.0", "193.19.255.255"),   // Various
    ("193.22.0.0", "193.22.255.255"),   // Various
    ("193.28.0.0", "193.29.255.255"),   // Various
    ("193.29.0.0", "193.29.255.255"),   // Various
    ("193.34.0.0", "193.35.255.255"),   // Various
    ("193.104.0.0", "193.107.255.255"), // Various
    ("193.111.0.0", "193.111.255.255"), // Various
    ("193.141.0.0", "193.141.255.255"), // Various
    ("193.142.0.0", "193.142.255.255"), // Various
    ("193.150.0.0", "193.150.255.255"), // Various
    ("193.151.0.0", "193.151.255.255"), // Various
    ("193.162.0.0", "193.163.255.255"), // MCI
    ("193.176.0.0", "193.176.255.255"), // Various
    ("193.186.0.0", "193.186.255.255"), // Various
    ("193.200.0.0", "193.200.255.255"), // Various
    ("193.228.0.0", "193.228.255.255"), // Various
    ("194.5.0.0", "194.5.255.255"),     // Various
    ("194.26.0.0", "194.26.255.255"),   // Various
    ("194.33.0.0", "194.33.255.255"),   // Various
    ("194.36.0.0", "194.36.255.255"),   // Various
    ("194.50.0.0", "194.50.255.255"),   // Various
    ("194.53.0.0", "194.53.255.255"),   // Various
    ("194.59.0.0", "194.59.255.255"),   // Various
    ("194.60.0.0", "194.60.255.255"),   // Various
    ("194.143.0.0", "194.143.255.255"), // Afranet
    ("194.146.0.0", "194.146.255.255"), // Various
    ("194.147.0.0", "194.147.255.255"), // Various
    ("194.150.0.0", "194.150.255.255"), // Various
    ("194.156.0.0", "194.156.255.255"), // Various
    ("194.225.0.0", "194.225.255.255"), // TCI
    ("195.2.0.0", "195.2.255.255"),     // Various
    ("195.20.0.0", "195.20.255.255"),   // Various
    ("195.28.0.0", "195.28.255.255"),   // Various
    ("195.114.0.0", "195.114.255.255"), // Various
    ("195.146.0.0", "195.146.255.255"), // DCI
    ("195.181.0.0", "195.181.255.255"), // Various
    ("195.182.0.0", "195.182.255.255"), // Various
    ("195.190.0.0", "195.190.255.255"), // Various
    ("195.191.0.0", "195.191.255.255"), // Various
    ("195.219.0.0", "195.219.255.255"), // Various
    ("195.225.0.0", "195.225.255.255"), // Various
    ("195.234.0.0", "195.234.255.255"), // Various
    ("195.238.0.0", "195.238.255.255"), // Various
    ("212.16.0.0", "212.16.255.255"),   // Various
    ("212.18.0.0", "212.18.255.255"),   // Various
    ("212.23.0.0", "212.23.255.255"),   // Pars Online
    ("212.33.0.0", "212.33.255.255"),   // Various
    ("212.73.0.0", "212.73.255.255"),   // Various
    ("212.80.0.0", "212.80.255.255"),   // Afranet
    ("212.86.0.0", "212.86.255.255"),   // Various
    ("212.120.0.0", "212.120.255.255"), // Various
    ("213.32.0.0", "213.32.255.255"),   // Various
    ("213.109.0.0", "213.109.255.255"), // Various
    ("213.176.0.0", "213.176.255.255"), // TCI
    ("213.195.0.0", "213.195.255.255"), // Various
    ("213.207.0.0", "213.207.255.255"), // Various
    ("213.217.0.0", "213.217.255.255"), // Afranet
    ("213.232.0.0", "213.232.255.255"), // Various
    ("213.233.0.0", "213.233.255.255"), // Various
    ("217.11.0.0", "217.11.255.255"),   // Various
    ("217.24.0.0", "217.25.255.255"),   // Various
    ("217.60.0.0", "217.60.255.255"),   // Various
    ("217.66.0.0", "217.66.255.255"),   // Various
    ("217.77.0.0", "217.77.255.255"),   // Various
    ("217.114.0.0", "217.114.255.255"), // Various
    ("217.144.0.0", "217.144.255.255"), // Shatel
    ("217.146.0.0", "217.146.255.255"), // Various
    ("217.161.0.0", "217.161.255.255"), // Various
    ("217.170.0.0", "217.170.255.255"), // Various
    ("217.171.0.0", "217.171.255.255"), // Shatel
    ("217.172.0.0", "217.172.255.255"), // Various
    ("217.174.0.0", "217.174.255.255"), // Pars Online
    ("217.218.0.0", "217.219.255.255"), // TCI
];

/// Iranian domain suffixes for fast-path matching
const IRANIAN_DOMAINS: &[&str] = &[
    ".ir",
    ".iran",
    ".shatel.ir",
    ".mci.ir",
    ".irancell.ir",
    ".mobinnet.ir",
    ".pishgaman.net",
    ".parsianwan.net",
    ".rightel.ir",
    ".asiatech.ir",
    ".parsonline.com",
    ".respina.net",
    ".afranet.com",
    ".sabacell.ir",
    ".tic.ir",
    ".tci.ir",
];

// ============================================================================
// IP RANGE
// ============================================================================

/// IP range for binary search matching
#[derive(Clone, Debug)]
pub struct IpRange {
    /// Starting IP as u32 (IPv4)
    pub start: u32,
    /// Ending IP as u32
    pub end: u32,
}

impl IpRange {
    /// Create from start and end IP strings
    pub fn from_range(start: &str, end: &str) -> Option<Self> {
        let start_ip: std::net::Ipv4Addr = start.parse().ok()?;
        let end_ip: std::net::Ipv4Addr = end.parse().ok()?;
        Some(Self {
            start: u32::from(start_ip),
            end: u32::from(end_ip),
        })
    }

    /// Create from IpNetwork
    pub fn from_network(net: ipnetwork::IpNetwork) -> Option<Self> {
        match net {
            ipnetwork::IpNetwork::V4(v4) => Some(Self {
                start: u32::from(v4.network()),
                end: u32::from(v4.broadcast()),
            }),
            ipnetwork::IpNetwork::V6(_) => None, // Handle separately
        }
    }

    /// Check if IP is in range
    #[inline]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }
}

// ============================================================================
// GEO MANAGER
// ============================================================================

/// Mapped GeoIP Data
pub struct MappedGeoIp {
    mmap: Mmap,
    index: HashMap<String, (usize, usize)>, // Country -> (Start, Length) in mmap
}

/// Mapped GeoSite Data
pub struct MappedGeoSite {
    mmap: Mmap,
    index: HashMap<String, (usize, usize)>, // Category -> (Start, Length) in mmap
}

/// Production-grade Geo-Asset Manager with Iranian optimization
pub struct GeoManager {
    /// Cache directory path
    cache_dir: PathBuf,
    /// Memory-mapped GeoIP data
    geoip_data: Arc<RwLock<Option<MappedGeoIp>>>,
    /// Memory-mapped GeoSite data
    geosite_data: Arc<RwLock<Option<MappedGeoSite>>>,
    /// Pre-computed Iranian IP ranges (fast path)
    iranian_ranges: Vec<IpRange>,
    /// Loading status
    is_loaded: AtomicBool,
    /// Last update time
    last_update: Arc<RwLock<Option<SystemTime>>>,
    /// Statistics
    stats: GeoStats,
}

/// Statistics for geo operations
#[derive(Default)]
pub struct GeoStats {
    /// Total GeoIP lookups
    pub geoip_lookups: AtomicUsize,
    /// GeoIP cache hits
    pub geoip_hits: AtomicUsize,
    /// Iranian fast-path hits
    pub iranian_hits: AtomicUsize,
    /// Total GeoSite lookups
    pub geosite_lookups: AtomicUsize,
    /// GeoSite hits
    pub geosite_hits: AtomicUsize,
    /// Total countries loaded
    pub countries_loaded: AtomicUsize,
    /// Total categories loaded
    pub categories_loaded: AtomicUsize,
}

impl GeoManager {
    /// Create a new GeoManager with default cache directory
    pub fn new() -> Self {
        let path = platform_paths::get_asset_dir("org.edgeray.rustray");
        // Ensure the directory exists
        if !path.exists() {
            let _ = std::fs::create_dir_all(&path);
        }
        Self::with_cache_dir(path.to_str().unwrap_or("."))
    }

    /// Create a new GeoManager with custom cache directory
    pub fn with_cache_dir(cache_dir: &str) -> Self {
        let cache_path = PathBuf::from(cache_dir);

        // Ensure directory exists
        if let Err(e) = fs::create_dir_all(&cache_path) {
            warn!("Failed to create cache directory: {}", e);
        }

        // Pre-compute Iranian IP ranges
        let iranian_ranges: Vec<IpRange> = IRANIAN_IPV4_RANGES
            .iter()
            .filter_map(|(start, end)| IpRange::from_range(start, end))
            .collect();

        info!(
            "GeoManager: Pre-loaded {} Iranian IP ranges for fast-path",
            iranian_ranges.len()
        );

        Self {
            cache_dir: cache_path,
            geoip_data: Arc::new(RwLock::new(None)),
            geosite_data: Arc::new(RwLock::new(None)),
            iranian_ranges,
            is_loaded: AtomicBool::new(false),
            last_update: Arc::new(RwLock::new(None)),
            stats: GeoStats::default(),
        }
    }

    /// Initialize and load geo data
    pub async fn init(&self) -> Result<()> {
        info!("Initializing GeoManager...");

        // Load data into memory
        self.load_geoip().await?;
        self.load_geosite().await?;

        self.is_loaded.store(true, Ordering::SeqCst);

        if let Ok(mut last) = self.last_update.write() {
            *last = Some(SystemTime::now());
        }

        info!(
            "GeoManager initialized: {} countries, {} categories, {} Iranian ranges",
            self.stats.countries_loaded.load(Ordering::Relaxed),
            self.stats.categories_loaded.load(Ordering::Relaxed),
            self.iranian_ranges.len()
        );

        Ok(())
    }

    /// Load GeoIP data with binary search optimization
    async fn load_geoip(&self) -> Result<()> {
        let path = self.cache_dir.join("geoip.dat");
        if !path.exists() {
            // Try fallback locations
            let fallbacks = [
                Path::new("/usr/share/rustray/geoip.dat"),
                Path::new("/usr/local/share/rustray/geoip.dat"),
                Path::new("./geoip.dat"),
            ];

            for fallback in fallbacks {
                if fallback.exists() {
                    info!("Using GeoIP from fallback: {:?}", fallback);
                    return self.load_geoip_from_path(fallback).await;
                }
            }

            warn!("GeoIP file not found, using Iranian fast-path only");
            return Ok(());
        }

        self.load_geoip_from_path(&path).await
    }

    async fn load_geoip_from_path(&self, path: &Path) -> Result<()> {
        let path = path.to_owned();
        let mapped = tokio::task::spawn_blocking(move || -> Result<MappedGeoIp> {
            let file = fs::File::open(&path)?;
            let mmap = unsafe { Mmap::map(&file)? };

            // Pre-allocate HashMap capacity (estimate ~250 countries)
            let mut index = HashMap::with_capacity(256);
            // Start of buffer
            let mut buf = &mmap[..];
            let total_len = buf.len();

            // Loop until empty
            while !buf.is_empty() {
                // Record start offset of this message relative to mmap start
                // offset = total_len - buf.remaining()
                let _start_offset = total_len - buf.len();

                // 1. Decode Tag (GeoIPList repeated entry = 1)
                let (tag, wire_type) = encoding::decode_key(&mut buf)?;

                if tag != 1 {
                    // Skip unknown key
                    encoding::skip_field(wire_type, tag, &mut buf, Default::default())?;
                    continue;
                }

                // 2. Decode Length of the inner message (GeoIp)
                let msg_len = encoding::decode_varint(&mut buf)?;
                let msg_len_usize = msg_len as usize;

                if buf.len() < msg_len_usize {
                    break; // Partial or corrupt
                }

                // 3. Peek at the message body to find country code
                // The body is `buf[..msg_len_usize]`
                // We advance buf past body AFTER peeking
                #[allow(unused_assignments)]
                let mut body_slice = &buf[..msg_len_usize];

                // Helper to scan country code (Tag=1, type=String/Bytes)
                let mut country = String::new();
                while !body_slice.is_empty() {
                    let before_len = body_slice.len();
                    let (itag, iwire) =
                        encoding::decode_key(&mut body_slice).unwrap_or((0, WireType::Varint));
                    if itag == 1 {
                        // Country Code
                        let clen = encoding::decode_varint(&mut body_slice).unwrap_or(0) as usize;
                        if body_slice.len() >= clen {
                            let cbytes = &body_slice[..clen];
                            if let Ok(s) = std::str::from_utf8(cbytes) {
                                country = s.to_uppercase();
                            }
                        }
                        break; // Found it
                    } else {
                        // Skip field in body
                        let _ =
                            encoding::skip_field(iwire, itag, &mut body_slice, Default::default());
                    }
                    if body_slice.len() == before_len {
                        break;
                    }
                }

                if !country.is_empty() {
                    // Store strict slice for this Country's GeoIp message
                    // We want to point to the message BODY (length delimited content).
                    // `buf` is currently pointing at start of body.
                    // The body length is `msg_len_usize`.

                    // index stores (offset_in_mmap, length)
                    let body_offset = total_len - buf.len();
                    index.insert(country, (body_offset, msg_len_usize));
                }

                // Advance past this message
                buf = &buf[msg_len_usize..];
            }

            Ok(MappedGeoIp { mmap, index })
        })
        .await??;

        self.stats
            .countries_loaded
            .store(mapped.index.len(), Ordering::Relaxed);
        info!("GeoIP Mmap loaded: {} countries", mapped.index.len());

        if let Ok(mut data) = self.geoip_data.write() {
            *data = Some(mapped);
        }

        Ok(())
    }

    /// Load GeoSite data
    async fn load_geosite(&self) -> Result<()> {
        let path = self.cache_dir.join("geosite.dat");
        if !path.exists() {
            // Try fallback locations
            let fallbacks = [
                Path::new("/usr/share/rustray/geosite.dat"),
                Path::new("/usr/local/share/rustray/geosite.dat"),
                Path::new("./geosite.dat"),
            ];

            for fallback in fallbacks {
                if fallback.exists() {
                    info!("Using GeoSite from fallback: {:?}", fallback);
                    return self.load_geosite_from_path(fallback).await;
                }
            }

            warn!("GeoSite file not found");
            return Ok(());
        }

        self.load_geosite_from_path(&path).await
    }

    async fn load_geosite_from_path(&self, path: &Path) -> Result<()> {
        let path = path.to_owned();
        let mapped = tokio::task::spawn_blocking(move || -> Result<MappedGeoSite> {
            let file = fs::File::open(&path)?;
            let mmap = unsafe { Mmap::map(&file)? };

            // Pre-allocate HashMap capacity (estimate ~1000 categories)
            let mut index = HashMap::with_capacity(1024);
            let mut buf = &mmap[..];
            let total_len = buf.len();

            while !buf.is_empty() {
                let _start_offset = total_len - buf.len();
                let (tag, wire_type) = encoding::decode_key(&mut buf)?;

                if tag != 1 {
                    encoding::skip_field(wire_type, tag, &mut buf, Default::default())?;
                    continue;
                }

                let msg_len = encoding::decode_varint(&mut buf)?;
                let msg_len_usize = msg_len as usize;

                if buf.len() < msg_len_usize {
                    break;
                }

                #[allow(unused_assignments)]
                let mut body_slice = &buf[..msg_len_usize];
                let mut country = String::new();

                // GeoSite: string country_code = 1;
                while !body_slice.is_empty() {
                    let before_len = body_slice.len();
                    let (itag, iwire) =
                        encoding::decode_key(&mut body_slice).unwrap_or((0, WireType::Varint));
                    if itag == 1 {
                        let clen = encoding::decode_varint(&mut body_slice).unwrap_or(0) as usize;
                        if body_slice.len() >= clen {
                            if let Ok(s) = std::str::from_utf8(&body_slice[..clen]) {
                                country = s.to_uppercase();
                            }
                        }
                        break;
                    } else {
                        let _ =
                            encoding::skip_field(iwire, itag, &mut body_slice, Default::default());
                    }
                    if body_slice.len() == before_len {
                        break; // Make progress or die
                    }
                }

                if !country.is_empty() {
                    let body_offset = total_len - buf.len();
                    index.insert(country, (body_offset, msg_len_usize));
                }

                buf = &buf[msg_len_usize..]; // Advance
            }

            Ok(MappedGeoSite { mmap, index })
        })
        .await??;

        self.stats
            .categories_loaded
            .store(mapped.index.len(), Ordering::Relaxed);
        info!("GeoSite Mmap loaded: {} categories", mapped.index.len());

        if let Ok(mut data) = self.geosite_data.write() {
            *data = Some(mapped);
        }

        Ok(())
    }

    /// Fast-path check for Iranian IPs (O(log n) binary search)
    #[inline]
    pub fn is_iranian_ip(&self, ip: IpAddr) -> bool {
        self.stats.geoip_lookups.fetch_add(1, Ordering::Relaxed);

        let ip_u32 = match ip {
            IpAddr::V4(v4) => u32::from(v4),
            IpAddr::V6(_) => return false, // IPv6 not in fast-path
        };

        // Binary search in pre-sorted Iranian ranges
        let pos = self.iranian_ranges.partition_point(|r| r.end < ip_u32);
        if pos < self.iranian_ranges.len() && self.iranian_ranges[pos].contains(ip_u32) {
            self.stats.iranian_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    /// Fast-path check for Iranian domains
    #[inline]
    pub fn is_iranian_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Check .ir TLD first (most common)
        if domain_lower.ends_with(".ir") || domain_lower == "ir" {
            return true;
        }

        // Check known Iranian domains
        for suffix in IRANIAN_DOMAINS {
            if domain_lower.ends_with(suffix) {
                return true;
            }
        }

        false
    }

    /// Match IP against GeoIP using binary search
    pub fn match_geoip(&self, ip: IpAddr, country: &str) -> bool {
        self.stats.geoip_lookups.fetch_add(1, Ordering::Relaxed);

        // Special case: Iran (use fast path first)
        if country.eq_ignore_ascii_case("ir") || country.eq_ignore_ascii_case("iran") {
            if self.is_iranian_ip(ip) {
                return true;
            }
        }

        // Zero-copy lookup
        let guard = match self.geoip_data.read() {
            Ok(g) => g,
            Err(_) => return false,
        };

        let mapped = match guard.as_ref() {
            Some(m) => m,
            None => return false,
        };

        let country_upper = country.to_uppercase();
        if let Some(&(start, len)) = mapped.index.get(&country_upper) {
            let slice = &mapped.mmap[start..start + len];

            // ZERO-COPY ITERATION logic
            // We traverse the slice manually to find matching CIDRs without allocating a Vec.
            let mut buf = slice;

            // Loop over fields in the GeoIp message body
            while !buf.is_empty() {
                // Decode field tag
                let (tag, wire_type) = match encoding::decode_key(&mut buf) {
                    Ok(x) => x,
                    Err(_) => break,
                };

                if tag == 2 {
                    // This is a CIDR field (repeated)
                    // WireType should be LengthDelimited (2)
                    if wire_type != WireType::LengthDelimited {
                        // Skip unexpected wire type
                        if encoding::skip_field(wire_type, tag, &mut buf, Default::default())
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }

                    // Decode length of Cidr message
                    let cidr_len = match encoding::decode_varint(&mut buf) {
                        Ok(l) => l as usize,
                        Err(_) => break,
                    };

                    if buf.len() < cidr_len {
                        break;
                    }

                    // Slice for this specific Cidr message
                    let mut cidr_slice = &buf[..cidr_len];

                    // Decode Cidr struct manually
                    let mut cidr_ip_bytes: &[u8] = &[];
                    let mut cidr_prefix: u32 = 0;

                    while !cidr_slice.is_empty() {
                        let (c_tag, c_wire) = match encoding::decode_key(&mut cidr_slice) {
                            Ok(x) => x,
                            Err(_) => break,
                        };

                        match c_tag {
                            1 => {
                                // ip bytes
                                let b_len = match encoding::decode_varint(&mut cidr_slice) {
                                    Ok(l) => l as usize,
                                    Err(_) => break,
                                };
                                if cidr_slice.len() >= b_len {
                                    cidr_ip_bytes = &cidr_slice[..b_len];
                                    cidr_slice = &cidr_slice[b_len..];
                                }
                            }
                            2 => {
                                // prefix uint32
                                cidr_prefix = match encoding::decode_varint(&mut cidr_slice) {
                                    Ok(p) => p as u32,
                                    Err(_) => break,
                                };
                            }
                            _ => {
                                if encoding::skip_field(
                                    c_wire,
                                    c_tag,
                                    &mut cidr_slice,
                                    Default::default(),
                                )
                                .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }

                    // Check if IP matches this CIDR
                    if !cidr_ip_bytes.is_empty() {
                        let ip_addr_opt = if cidr_ip_bytes.len() == 4 {
                            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                cidr_ip_bytes[0],
                                cidr_ip_bytes[1],
                                cidr_ip_bytes[2],
                                cidr_ip_bytes[3],
                            )))
                        } else if cidr_ip_bytes.len() == 16 {
                            let b = cidr_ip_bytes;
                            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                                u16::from_be_bytes([b[0], b[1]]),
                                u16::from_be_bytes([b[2], b[3]]),
                                u16::from_be_bytes([b[4], b[5]]),
                                u16::from_be_bytes([b[6], b[7]]),
                                u16::from_be_bytes([b[8], b[9]]),
                                u16::from_be_bytes([b[10], b[11]]),
                                u16::from_be_bytes([b[12], b[13]]),
                                u16::from_be_bytes([b[14], b[15]]),
                            )))
                        } else {
                            None
                        };

                        if let Some(net_ip) = ip_addr_opt {
                            if let Ok(net) = ipnetwork::IpNetwork::new(net_ip, cidr_prefix as u8) {
                                if net.contains(ip) {
                                    self.stats.geoip_hits.fetch_add(1, Ordering::Relaxed);
                                    return true;
                                }
                            }
                        }
                    }

                    // Advance main buf past this CIDR
                    buf = &buf[cidr_len..];
                } else {
                    // Skip other fields
                    if encoding::skip_field(wire_type, tag, &mut buf, Default::default()).is_err() {
                        break;
                    }
                }
            }
        }

        false
    }

    /// Get country for IP
    pub fn get_country(&self, ip: IpAddr) -> Option<String> {
        self.stats.geoip_lookups.fetch_add(1, Ordering::Relaxed);

        // Fast path for Iran
        if self.is_iranian_ip(ip) {
            return Some("IR".to_string());
        }

        // Use Mmap
        let guard = match self.geoip_data.read() {
            Ok(g) => g,
            Err(_) => return None,
        };
        let mapped = match guard.as_ref() {
            Some(m) => m,
            None => return None,
        };

        // This is expensive: We must check ALL countries?
        // Optimized: Only check frequently accessed ones?
        // Or iteration over index?
        // Note: The previous implementation iterated `data.iter()`.
        // We will match that.

        let ip_u32 = match ip {
            IpAddr::V4(v4) => u32::from(v4),
            _ => return None,
        };

        for (country, &(start, len)) in &mapped.index {
            let slice = &mapped.mmap[start..start + len];
            if let Ok(geo_ip) = GeoIp::decode(slice) {
                // Inline check (slow)
                // We could check only "Full/Plain" types if index was smarter.
                // For now, we replicate logic.
                // Note: this is O(Countries * Ranges). Very slow.
                // But `get_country` is usually for UI.

                // Optimization: decode `cidrs` and check containment.
                for cidr in geo_ip.cidr {
                    if cidr.ip.len() == 4 {
                        let ip_addr =
                            std::net::Ipv4Addr::new(cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]);
                        if let Ok(net) = ipnetwork::IpNetwork::new(
                            std::net::IpAddr::V4(ip_addr),
                            cidr.prefix as u8,
                        ) {
                            if let Some(range) = IpRange::from_network(net) {
                                if range.contains(ip_u32) {
                                    self.stats.geoip_hits.fetch_add(1, Ordering::Relaxed);
                                    return Some(country.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Match domain against GeoSite category
    pub fn match_geosite(&self, domain: &str, category: &str) -> bool {
        self.stats.geosite_lookups.fetch_add(1, Ordering::Relaxed);

        if category.eq_ignore_ascii_case("ir") || category.eq_ignore_ascii_case("iran") {
            if self.is_iranian_domain(domain) {
                self.stats.geosite_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        let guard = match self.geosite_data.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let mapped = match guard.as_ref() {
            Some(m) => m,
            None => return false,
        };

        let category_upper = category.to_uppercase();
        if let Some(&(start, len)) = mapped.index.get(&category_upper) {
            let slice = &mapped.mmap[start..start + len];
            let domain_lower = domain.to_lowercase();

            // ZERO-COPY ITERATION logic for GeoSite
            let mut buf = slice;

            while !buf.is_empty() {
                let (tag, wire_type) = match encoding::decode_key(&mut buf) {
                    Ok(x) => x,
                    Err(_) => break,
                };

                if tag == 2 {
                    // "domain" field repeated
                    if wire_type != WireType::LengthDelimited {
                        if encoding::skip_field(wire_type, tag, &mut buf, Default::default())
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }

                    let domain_msg_len = match encoding::decode_varint(&mut buf) {
                        Ok(l) => l as usize,
                        Err(_) => break,
                    };

                    if buf.len() < domain_msg_len {
                        break;
                    }
                    let mut domain_buf = &buf[..domain_msg_len];
                    buf = &buf[domain_msg_len..]; // Advance main buf

                    // Decode Domain msg
                    let mut d_type = 0;
                    let mut d_value = "";

                    // We need to parse fields 1 (type) and 2 (value)
                    while !domain_buf.is_empty() {
                        let (d_tag, d_wire) = match encoding::decode_key(&mut domain_buf) {
                            Ok(x) => x,
                            Err(_) => break,
                        };
                        match d_tag {
                            1 => {
                                // type (enum i32)
                                if let Ok(val) = encoding::decode_varint(&mut domain_buf) {
                                    d_type = val as i32;
                                }
                            }
                            2 => {
                                // value (string)
                                let s_len = match encoding::decode_varint(&mut domain_buf) {
                                    Ok(l) => l as usize,
                                    Err(_) => break,
                                };
                                if domain_buf.len() >= s_len {
                                    if let Ok(s) = std::str::from_utf8(&domain_buf[..s_len]) {
                                        d_value = s;
                                    }
                                    domain_buf = &domain_buf[s_len..];
                                }
                            }
                            _ => {
                                if encoding::skip_field(
                                    d_wire,
                                    d_tag,
                                    &mut domain_buf,
                                    Default::default(),
                                )
                                .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }

                    // Check match
                    let matched = match DomainType::try_from(d_type) {
                        Ok(DomainType::Full) => domain_lower == d_value.to_lowercase(),
                        Ok(DomainType::Domain) => {
                            let suffix = d_value.to_lowercase();
                            domain_lower == suffix
                                || domain_lower.ends_with(&format!(".{}", suffix))
                        }
                        Ok(DomainType::Plain) => domain_lower.contains(&d_value.to_lowercase()),
                        Ok(DomainType::Regex) => {
                            if let Ok(re) = regex::Regex::new(d_value) {
                                re.is_match(&domain_lower)
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };

                    if matched {
                        self.stats.geosite_hits.fetch_add(1, Ordering::Relaxed);
                        return true;
                    }
                } else {
                    if encoding::skip_field(wire_type, tag, &mut buf, Default::default()).is_err() {
                        break;
                    }
                }
            }
        }

        false
    }

    /// Get GeoSite domains for a category
    pub fn get_geosite_domains(&self, category: &str) -> Option<Vec<Domain>> {
        let guard = self.geosite_data.read().ok()?;
        let mapped = guard.as_ref()?;

        let (start, len) = *mapped.index.get(&category.to_uppercase())?;
        let slice = &mapped.mmap[start..start + len];
        let site = GeoSite::decode(slice).ok()?;
        Some(site.domain)
    }

    /// Get GeoIP CIDRs for a country
    pub fn get_geoip_cidrs(&self, country: &str) -> Option<Vec<ipnetwork::IpNetwork>> {
        let mut cidrs = Vec::new();

        // Special case for Iran - include fast path ranges
        // Note: Iranian ranges are stored as IpRange (start/end).
        // Converting Range -> CIDRs is complex logic (splitting).
        // Ideally we store Iranian ranges as CIDRs too or convert the const list.
        // For now, if country is Iran, we might skip the fast-path internal struct
        // and just load "IR" from file if available, OR we parse the CIDR list from consts?
        // The const ranges are Strings "2.144.0.0", "2.159.255.255".
        // This corresponds to 2.144.0.0/12.
        // It's safer to rely on the Mmap DB for compilation if available.
        // Only if Mmap is missing do we fallback.
        // But fast-path is checked FIRST in `match_geoip`.
        // If we compile, we MUST include fast-path.

        // Simpler approach for now: Just load from Mmap.
        // If user wants fast-path behavior in Trie, the Trie should include "IR" rules.

        let guard = self.geoip_data.read().ok()?;
        let mapped = guard.as_ref()?;
        let (start, len) = *mapped.index.get(&country.to_uppercase())?;
        let slice = &mapped.mmap[start..start + len];
        let geo_ip = GeoIp::decode(slice).ok()?;

        for cidr in geo_ip.cidr {
            if cidr.ip.len() == 4 {
                let ip = std::net::Ipv4Addr::new(cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]);
                if let Ok(net) =
                    ipnetwork::IpNetwork::new(std::net::IpAddr::V4(ip), cidr.prefix as u8)
                {
                    cidrs.push(net);
                }
            }
        }
        Some(cidrs)
    }

    /// Get statistics
    pub fn get_stats(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.stats.geoip_lookups.load(Ordering::Relaxed),
            self.stats.geoip_hits.load(Ordering::Relaxed),
            self.stats.iranian_hits.load(Ordering::Relaxed),
            self.stats.geosite_lookups.load(Ordering::Relaxed),
            self.stats.geosite_hits.load(Ordering::Relaxed),
        )
    }

    /// Check if data is loaded
    pub fn is_loaded(&self) -> bool {
        self.is_loaded.load(Ordering::SeqCst)
    }

    /// Force reload of geo data
    pub async fn reload(&self) -> Result<()> {
        info!("Reloading geo data...");
        self.is_loaded.store(false, Ordering::SeqCst);
        self.init().await
    }

    /// Get count of Iranian ranges
    pub fn iranian_range_count(&self) -> usize {
        self.iranian_ranges.len()
    }

    /// Get keys (Country Codes) available in GeoIP
    pub fn get_geoip_keys(&self) -> Vec<String> {
        if let Ok(guard) = self.geoip_data.read() {
            if let Some(mapped) = guard.as_ref() {
                return mapped.index.keys().cloned().collect();
            }
        }
        Vec::new()
    }

    /// Get keys (Categories) available in GeoSite
    pub fn get_geosite_keys(&self) -> Vec<String> {
        if let Ok(guard) = self.geosite_data.read() {
            if let Some(mapped) = guard.as_ref() {
                return mapped.index.keys().cloned().collect();
            }
        }
        Vec::new()
    }
}

impl Default for GeoManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_range_contains() {
        let range = IpRange::from_range("192.168.0.0", "192.168.0.255").unwrap();

        let ip1: std::net::Ipv4Addr = "192.168.0.1".parse().unwrap();
        let ip2: std::net::Ipv4Addr = "192.168.0.255".parse().unwrap();
        let ip3: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();

        assert!(range.contains(u32::from(ip1)));
        assert!(range.contains(u32::from(ip2)));
        assert!(!range.contains(u32::from(ip3)));
    }

    #[test]
    fn test_iranian_ip_check() {
        let manager = GeoManager::new();

        // MCI IP (should be Iranian)
        let mci_ip: IpAddr = "2.176.1.1".parse().unwrap();
        assert!(manager.is_iranian_ip(mci_ip));

        // Shatel IP (should be Iranian)
        let shatel_ip: IpAddr = "2.144.1.1".parse().unwrap();
        assert!(manager.is_iranian_ip(shatel_ip));

        // Google IP (should NOT be Iranian)
        let google_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!manager.is_iranian_ip(google_ip));
    }

    #[test]
    fn test_iranian_domain_check() {
        let manager = GeoManager::new();

        assert!(manager.is_iranian_domain("example.ir"));
        assert!(manager.is_iranian_domain("www.shatel.ir"));
        assert!(manager.is_iranian_domain("api.mci.ir"));
        assert!(!manager.is_iranian_domain("example.com"));
        assert!(!manager.is_iranian_domain("google.com"));
    }

    #[test]
    fn test_geo_manager_creation() {
        let manager = GeoManager::new();
        assert!(!manager.is_loaded());
        assert!(manager.iranian_range_count() > 0);
    }

    #[test]
    fn test_iranian_ranges_preloaded() {
        let manager = GeoManager::new();
        // Should have Iranian ranges pre-loaded
        assert!(manager.iranian_range_count() > 100);
    }

    #[tokio::test]
    async fn test_geo_manager_init() {
        let manager = GeoManager::with_cache_dir("/tmp/rustray_test_geo");
        // Should not fail even without files
        let result = manager.init().await;
        let _ = result;
    }

    #[test]
    fn test_match_geoip_iran() {
        let manager = GeoManager::new();

        // Iranian IP
        let ir_ip: IpAddr = "2.176.1.1".parse().unwrap();
        assert!(manager.match_geoip(ir_ip, "ir"));
        assert!(manager.match_geoip(ir_ip, "IR"));
        assert!(manager.match_geoip(ir_ip, "iran"));

        // Non-Iranian IP
        let us_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!manager.match_geoip(us_ip, "ir"));
    }

    #[test]
    fn test_match_geosite_iran() {
        let manager = GeoManager::new();

        assert!(manager.match_geosite("example.ir", "ir"));
        assert!(manager.match_geosite("www.digikala.ir", "ir"));
        assert!(!manager.match_geosite("google.com", "ir"));
    }

    #[test]
    fn test_get_country_iran() {
        let manager = GeoManager::new();

        let ir_ip: IpAddr = "2.176.1.1".parse().unwrap();
        let country = manager.get_country(ir_ip);
        assert_eq!(country, Some("IR".to_string()));
    }

    #[test]
    fn test_stats() {
        let manager = GeoManager::new();

        // Perform some lookups
        let ip: IpAddr = "2.176.1.1".parse().unwrap();
        manager.is_iranian_ip(ip);
        manager.is_iranian_ip(ip);

        let (lookups, _hits, iranian, _, _) = manager.get_stats();
        assert!(lookups >= 2);
        assert!(iranian >= 2);
    }
}
