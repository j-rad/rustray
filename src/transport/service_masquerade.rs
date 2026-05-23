// src/transport/service_masquerade.rs
//! Phase 14b — Service-Specific Masquerading Orchestrator
//!
//! Master decision engine for selecting evasion lanes (Browser, Enterprise,
//! System Update, CLI) based on user-configured weights and destination heuristics.

use crate::config::MasqueradeWeights;
use crate::transport::tls_mimicry::{GhostHeader, GhostHeaderGenerator, GhostProtocol};
use crate::transport::tls_profile::{
    AlpnPortfolio, BrowserProfile, ProfileFactory, ServiceCategory, TlsProfile,
};
use rand::Rng;
use rand::seq::SliceRandom;

/// A selected masquerade strategy for a connection.
#[derive(Debug, Clone)]
pub struct MasqueradeStrategy<'a> {
    pub category: ServiceCategory,
    pub profile: &'a TlsProfile,
    pub ghost: Option<GhostHeader>,
    pub alpn: Vec<String>,
}

pub struct ServiceMasquerade {
    factory: ProfileFactory,
    portfolio: AlpnPortfolio,
}

impl ServiceMasquerade {
    pub fn new() -> Self {
        Self {
            factory: ProfileFactory::new(),
            portfolio: AlpnPortfolio::new(),
        }
    }

    /// Orchestrate a masquerade strategy for an outbound connection.
    pub fn select<'a>(
        &'a self,
        sni: Option<&str>,
        weights: Option<&MasqueradeWeights>,
        decoy_headers: Option<&std::collections::HashMap<String, String>>,
    ) -> MasqueradeStrategy<'a> {
        let mut rng = rand::thread_rng();

        // 1. Destination classification (Heuristic override)
        if let Some(domain) = sni {
            let cat = self.portfolio.classify(domain);
            if cat != ServiceCategory::Web {
                // If the domain is recognized as a specific service (e.g. MS Update),
                // use that lane automatically for maximum realism.
                return self.strategy_for_category(cat, sni, decoy_headers);
            }
        }

        // 2. Weighted selection (User preference)
        let w = weights.cloned().unwrap_or_default();
        let total = w.browser + w.enterprise + w.os_update + w.cli + w.domestic;
        let roll = rng.gen_range(0..total.max(1));

        if roll < w.browser {
            self.strategy_for_category(ServiceCategory::Web, sni, decoy_headers)
        } else if roll < w.browser + w.enterprise {
            self.strategy_for_category(ServiceCategory::DatabaseNative, sni, decoy_headers)
        } else if roll < w.browser + w.enterprise + w.os_update {
            self.strategy_for_category(ServiceCategory::OsUpdate, sni, decoy_headers)
        } else if roll < w.browser + w.enterprise + w.os_update + w.cli {
            self.strategy_for_category(ServiceCategory::CliTool, sni, decoy_headers)
        } else {
            self.strategy_for_category(ServiceCategory::Domestic, sni, decoy_headers)
        }
    }

    fn strategy_for_category<'a>(
        &'a self,
        cat: ServiceCategory,
        sni: Option<&str>,
        decoy_headers: Option<&std::collections::HashMap<String, String>>,
    ) -> MasqueradeStrategy<'a> {
        let mut rng = rand::thread_rng();

        match cat {
            ServiceCategory::Web => {
                let profile = self.factory.random_profile();
                MasqueradeStrategy {
                    category: cat,
                    profile,
                    ghost: Some(GhostHeaderGenerator::generate(
                        GhostProtocol::Http2Preface,
                        sni,
                    )),
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                }
            }
            ServiceCategory::DatabaseNative => {
                let db_protos = [
                    GhostProtocol::PsqlSslRequest,
                    GhostProtocol::MysqlSslRequest,
                    GhostProtocol::MongoshHello,
                    GhostProtocol::RedisClusterInfo,
                ];
                let ghost_proto = db_protos.choose(&mut rng).unwrap().clone();

                // Native DBs often have very simple TLS fingerprints
                let profile = self
                    .factory
                    .get_profile(BrowserProfile::CurlOpenssl)
                    .unwrap();

                MasqueradeStrategy {
                    category: cat,
                    profile,
                    ghost: Some(GhostHeaderGenerator::generate(ghost_proto, sni)),
                    alpn: vec![], // No ALPN for native DBs
                }
            }
            ServiceCategory::OsUpdate => {
                let (ghost_proto, profile_id) = match rng.gen_range(0..3) {
                    0 => (GhostProtocol::WindowsUpdate, BrowserProfile::Edge140),
                    1 => (GhostProtocol::MacOsSoftwareUpdate, BrowserProfile::Safari18),
                    _ => (GhostProtocol::AptTransport, BrowserProfile::CurlOpenssl),
                };

                MasqueradeStrategy {
                    category: cat,
                    profile: self.factory.get_profile(profile_id).unwrap(),
                    ghost: Some(GhostHeaderGenerator::generate(ghost_proto, sni)),
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                }
            }
            ServiceCategory::CliTool => {
                let (ghost_proto, profile_id) = match rng.gen_range(0..3) {
                    0 => (GhostProtocol::CurlHttpGet, BrowserProfile::CurlOpenssl),
                    1 => (GhostProtocol::WgetHttpGet, BrowserProfile::WgetGnuTls),
                    _ => (GhostProtocol::CurlHttpGet, BrowserProfile::PythonUrllib),
                };

                MasqueradeStrategy {
                    category: cat,
                    profile: self.factory.get_profile(profile_id).unwrap(),
                    ghost: Some(GhostHeaderGenerator::generate(ghost_proto, sni)),
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                }
            }
            ServiceCategory::Domestic => {
                // Select a random domestic decoy from the scraped headers
                let ghost = if let Some(headers_map) = decoy_headers
                    && !headers_map.is_empty()
                {
                    let sites: Vec<_> = headers_map.keys().collect();
                    let site = sites.choose(&mut rng).unwrap();
                    let headers = headers_map.get(*site).unwrap();
                    Some(GhostHeaderGenerator::generate(
                        GhostProtocol::DomesticDecoy(headers.clone()),
                        sni,
                    ))
                } else {
                    // Fallback to standard web if no domestic headers are available
                    Some(GhostHeaderGenerator::generate(
                        GhostProtocol::Http2Preface,
                        sni,
                    ))
                };

                MasqueradeStrategy {
                    category: cat,
                    profile: self.factory.random_profile(),
                    ghost,
                    alpn: vec!["h2".to_string(), "http/1.1".to_string()],
                }
            }
            _ => {
                // Default to Web for other categories (Database, Grpc, Mqtt, etc.)
                self.strategy_for_category(ServiceCategory::Web, sni, decoy_headers)
            }
        }
    }
}

impl Default for ServiceMasquerade {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_select_by_domain_heuristic() {
        let sm = ServiceMasquerade::new();
        // Domain heuristic should override weights
        let strategy = sm.select(Some("update.microsoft.com"), None, None);
        assert_eq!(strategy.category, ServiceCategory::OsUpdate);
        assert!(strategy.ghost.unwrap().description.contains("Windows"));
    }

    #[test]
    fn test_select_by_weights() {
        let sm = ServiceMasquerade::new();
        let weights = MasqueradeWeights {
            browser: 0,
            enterprise: 100,
            os_update: 0,
            cli: 0,
            domestic: 0,
        };
        let strategy = sm.select(Some("example.com"), Some(&weights), None);
        assert_eq!(strategy.category, ServiceCategory::DatabaseNative);
    }
}
