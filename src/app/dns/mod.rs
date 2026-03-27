// src/app/dns/mod.rs
pub mod fakedns;
use self::fakedns::FakeDns;
use crate::config::DnsConfig;
use crate::error::Result;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tracing::{debug, info};

#[derive(Debug)]
pub struct DnsServer {
    resolver: TokioAsyncResolver,
    hosts: HashMap<String, IpAddr>,
    fakedns: Option<FakeDns>,
}

impl DnsServer {
    pub fn new(config: DnsConfig) -> Result<Self> {
        let mut resolver_config = ResolverConfig::new();
        let mut hosts = HashMap::new();

        // 1. Load static hosts
        if let Some(config_hosts) = config.hosts {
            for (domain, ip_str) in config_hosts {
                if let Ok(ip) = IpAddr::from_str(&ip_str) {
                    hosts.insert(domain, ip);
                }
            }
        }

        // 2. Smart DNS / Upstream Servers
        let mut loaded_servers = false;
        if config.auto_detect_system_dns.unwrap_or(false) {
            info!("DNS: Auto-detecting system nameservers...");

            // Try parsing /etc/resolv.conf
            if let Ok(file) = File::open("/etc/resolv.conf") {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(l) = line
                        && l.starts_with("nameserver ")
                            && let Some(ip_str) = l.split_whitespace().nth(1)
                                && let Ok(ip) = IpAddr::from_str(ip_str) {
                                    let socket = SocketAddr::new(ip, 53);
                                    resolver_config.add_name_server(NameServerConfig::new(
                                        socket,
                                        Protocol::Udp,
                                    ));
                                    loaded_servers = true;
                                    debug!("DNS: Found system nameserver: {}", ip);
                                }
                }
            }
        }

        if !loaded_servers
            && let Some(servers) = config.servers {
                for server_str in servers {
                    if let Ok(addr) = server_str.parse::<SocketAddr>() {
                        resolver_config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
                    } else if let Ok(ip) = server_str.parse::<IpAddr>() {
                        resolver_config.add_name_server(NameServerConfig::new(
                            SocketAddr::new(ip, 53),
                            Protocol::Udp,
                        ));
                    }
                }
            }

        if resolver_config.name_servers().is_empty() {
            // Fallback to Google DNS if nothing configured
            resolver_config.add_name_server(NameServerConfig::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                Protocol::Udp,
            ));
        }

        // 3. Initialize FakeDNS
        let fakedns = match &config.fakedns {
            Some(c) => Some(FakeDns::new(c.clone())?),
            None => None,
        };

        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

        let dns_server = Self {
            resolver,
            hosts,
            fakedns: fakedns.clone(),
        };

        // Spawn periodic save task if FakeDNS persistence is enabled
        if let Some(ref fake) = fakedns
            && let Some(ref path) = config.fakedns.as_ref().and_then(|c| c.persist_path.clone()) {
                let save_interval = config
                    .fakedns
                    .as_ref()
                    .map(|c| c.save_interval_secs)
                    .unwrap_or(300);
                Self::spawn_save_task(fake.clone(), path.clone(), save_interval);
            }

        Ok(dns_server)
    }

    fn spawn_save_task(fakedns: FakeDns, path: String, interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = fakedns.save_state(&path) {
                    tracing::error!("FakeDNS: Failed to auto-save state: {}", e);
                }
            }
        });
        info!(
            "FakeDNS: Started periodic save task (interval: {}s)",
            interval_secs
        );
    }

    pub async fn resolve_ip(&self, host: &str) -> Result<Vec<IpAddr>> {
        // 1. IP literal check
        if let Ok(ip) = IpAddr::from_str(host) {
            return Ok(vec![ip]);
        }

        // 2. Static Hosts
        if let Some(ip) = self.hosts.get(host) {
            return Ok(vec![*ip]);
        }

        // 3. FakeDNS (Strategy: UseIP is implied if fakedns is configured for now,
        // normally controlled by queryStrategy config in Xray)
        if let Some(fakedns) = &self.fakedns {
            let ip = fakedns.get_fake_ip(host);
            return Ok(vec![IpAddr::V4(ip)]);
        }

        // 4. Real Resolution
        let response = self.resolver.lookup_ip(host).await?;
        Ok(response.iter().collect())
    }

    pub fn get_domain_from_fake_ip(&self, ip: IpAddr) -> Option<String> {
        self.fakedns.as_ref().and_then(|f| f.get_domain_from_ip(ip))
    }
}
