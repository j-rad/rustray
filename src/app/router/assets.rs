use crate::app::platform_paths::get_asset_dir;
use crate::error::Result;
use prost::Message;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// --- Protobuf Definitions for RustRay .dat Files ---

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<DomainAttribute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DomainAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "domain_attribute::TypedValue", tags = "2, 3")]
    pub typed_value: Option<domain_attribute::TypedValue>,
}

pub mod domain_attribute {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

// --- Asset Loader ---

pub struct AssetLoader;

impl AssetLoader {
    /// Load GeoIP data from .dat file
    /// Handles large files (20MB+) efficiently using spawn_blocking
    pub async fn load_geoip(path: &Path) -> Result<HashMap<String, Vec<ipnetwork::IpNetwork>>> {
        let path = path.to_owned();

        info!("Loading GeoIP data from: {:?}", path);

        tokio::task::spawn_blocking(move || {
            // Check if file exists
            if !path.exists() {
                warn!("GeoIP file not found: {:?}", path);
                return Ok(HashMap::new());
            }

            // Read file (blocking I/O)
            let data = fs::read(&path)?;
            let file_size = data.len();
            info!(
                "GeoIP file size: {} bytes ({:.2} MB)",
                file_size,
                file_size as f64 / 1024.0 / 1024.0
            );

            // Decode protobuf
            let list = GeoIpList::decode(data.as_slice())
                .map_err(|e| anyhow::anyhow!("Failed to decode GeoIP protobuf: {}", e))?;

            info!("GeoIP entries loaded: {}", list.entry.len());

            // Build HashMap
            let mut map = HashMap::new();
            let mut total_cidrs = 0;

            for entry in list.entry {
                let mut networks = Vec::new();

                for cidr in entry.cidr {
                    let ip_addr = if cidr.ip.len() == 4 {
                        // IPv4
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3],
                        ))
                    } else if cidr.ip.len() == 16 {
                        // IPv6
                        let b = cidr.ip;
                        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                            u16::from_be_bytes([b[0], b[1]]),
                            u16::from_be_bytes([b[2], b[3]]),
                            u16::from_be_bytes([b[4], b[5]]),
                            u16::from_be_bytes([b[6], b[7]]),
                            u16::from_be_bytes([b[8], b[9]]),
                            u16::from_be_bytes([b[10], b[11]]),
                            u16::from_be_bytes([b[12], b[13]]),
                            u16::from_be_bytes([b[14], b[15]]),
                        ))
                    } else {
                        warn!("Invalid IP length in GeoIP: {} bytes", cidr.ip.len());
                        continue;
                    };

                    // Create network with prefix
                    if let Ok(net) = ipnetwork::IpNetwork::new(ip_addr, cidr.prefix as u8) {
                        networks.push(net);
                        total_cidrs += 1;
                    } else {
                        warn!("Invalid CIDR: {:?}/{}", ip_addr, cidr.prefix);
                    }
                }

                if !networks.is_empty() {
                    map.insert(entry.country_code.to_uppercase(), networks);
                }
            }

            info!(
                "GeoIP loaded: {} countries, {} total CIDR entries",
                map.len(),
                total_cidrs
            );
            Ok(map)
        })
        .await?
    }

    /// Load GeoSite data from .dat file
    /// Handles large files (20MB+) efficiently using spawn_blocking
    pub async fn load_geosite(path: &Path) -> Result<HashMap<String, Vec<Domain>>> {
        let path = path.to_owned();

        info!("Loading GeoSite data from: {:?}", path);

        tokio::task::spawn_blocking(move || {
            // Check if file exists
            if !path.exists() {
                warn!("GeoSite file not found: {:?}", path);
                return Ok(HashMap::new());
            }

            // Read file (blocking I/O)
            let data = fs::read(&path)?;
            let file_size = data.len();
            info!(
                "GeoSite file size: {} bytes ({:.2} MB)",
                file_size,
                file_size as f64 / 1024.0 / 1024.0
            );

            // Decode protobuf
            let list = GeoSiteList::decode(data.as_slice())
                .map_err(|e| anyhow::anyhow!("Failed to decode GeoSite protobuf: {}", e))?;

            info!("GeoSite entries loaded: {}", list.entry.len());

            // Build HashMap
            let mut map = HashMap::new();
            let mut total_domains = 0;

            for entry in list.entry {
                let domain_count = entry.domain.len();
                total_domains += domain_count;
                map.insert(entry.country_code.to_uppercase(), entry.domain);
            }

            info!(
                "GeoSite loaded: {} categories, {} total domain rules",
                map.len(),
                total_domains
            );
            Ok(map)
        })
        .await?
    }

    /// Load GeoIP from custom path with fallback to standard locations
    pub async fn load_geoip_with_fallback() -> Result<HashMap<String, Vec<ipnetwork::IpNetwork>>> {
        // Use configured asset dir (e.g., app data) as priority
        let asset_dir = get_asset_dir("org.edgeray.rustray");
        let primary_path = asset_dir.join("geoip.dat");

        // Try standard locations
        let paths = vec![
            primary_path,
            PathBuf::from("geoip.dat"),
            PathBuf::from("/usr/share/rustray/geoip.dat"),
            PathBuf::from("/usr/local/share/rustray/geoip.dat"),
            PathBuf::from("./assets/geoip.dat"),
        ];

        for path in paths {
            if path.exists() {
                return Self::load_geoip(&path).await;
            }
        }

        warn!("GeoIP file not found in any standard location");
        Ok(HashMap::new())
    }

    /// Load GeoSite from custom path with fallback to standard locations
    pub async fn load_geosite_with_fallback() -> Result<HashMap<String, Vec<Domain>>> {
        // Use configured asset dir (e.g., app data) as priority
        let asset_dir = get_asset_dir("org.edgeray.rustray");
        let primary_path = asset_dir.join("geosite.dat");

        // Try standard locations
        let paths = vec![
            primary_path,
            PathBuf::from("geosite.dat"),
            PathBuf::from("/usr/share/rustray/geosite.dat"),
            PathBuf::from("/usr/local/share/rustray/geosite.dat"),
            PathBuf::from("./assets/geosite.dat"),
        ];

        for path in paths {
            if path.exists() {
                return Self::load_geosite(&path).await;
            }
        }

        warn!("GeoSite file not found in any standard location");
        Ok(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_type_conversion() {
        assert_eq!(DomainType::try_from(0), Ok(DomainType::Plain));
        assert_eq!(DomainType::try_from(1), Ok(DomainType::Regex));
        assert_eq!(DomainType::try_from(2), Ok(DomainType::Domain));
        assert_eq!(DomainType::try_from(3), Ok(DomainType::Full));
        assert!(DomainType::try_from(99).is_err());
    }
}
