// src/transport/tls_profile.rs
//! Phase 14 — ALPN Portfolio & Profile Factory
//!
//! Provides browser-grade TLS profile generation with service-aware ALPN
//! selection and per-connection fingerprint rotation.

use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// ALPN Portfolio
// ─────────────────────────────────────────────────────────────────────────────

/// Service category for ALPN selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceCategory {
    Web,
    Grpc,
    Mqtt,
    Database,
    /// Native database wire protocol (no ALPN — raw TLS like psql/mongosh).
    DatabaseNative,
    Mail,
    Cdn,
    Gaming,
    Streaming,
    /// OS update services (Windows Update, macOS SUS, apt/yum).
    OsUpdate,
    /// CLI tools (curl, wget, pip, npm).
    CliTool,
    /// Domestic site mimicry (scraped headers).
    Domestic,
}

/// ALPN portfolio entry — maps a service category to its expected ALPN set.
#[derive(Debug, Clone)]
pub struct AlpnEntry {
    pub category: ServiceCategory,
    pub protocols: Vec<&'static str>,
    pub description: &'static str,
}

/// The complete ALPN portfolio covering all major service categories.
pub struct AlpnPortfolio {
    entries: HashMap<ServiceCategory, AlpnEntry>,
    domain_rules: Vec<(Vec<&'static str>, ServiceCategory)>,
}

impl AlpnPortfolio {
    /// Build the default portfolio with all known service mappings.
    pub fn new() -> Self {
        let mut entries = HashMap::new();

        entries.insert(
            ServiceCategory::Web,
            AlpnEntry {
                category: ServiceCategory::Web,
                protocols: vec!["h2", "http/1.1"],
                description: "Standard HTTPS web traffic",
            },
        );
        entries.insert(
            ServiceCategory::Grpc,
            AlpnEntry {
                category: ServiceCategory::Grpc,
                protocols: vec!["h2"],
                description: "gRPC over HTTP/2",
            },
        );
        entries.insert(
            ServiceCategory::Mqtt,
            AlpnEntry {
                category: ServiceCategory::Mqtt,
                protocols: vec!["mqtt"],
                description: "MQTT IoT messaging",
            },
        );
        entries.insert(
            ServiceCategory::Database,
            AlpnEntry {
                category: ServiceCategory::Database,
                protocols: vec!["h2", "http/1.1"],
                description: "Database admin panels (PgAdmin, Redis Insight)",
            },
        );
        entries.insert(
            ServiceCategory::DatabaseNative,
            AlpnEntry {
                category: ServiceCategory::DatabaseNative,
                protocols: vec![], // No ALPN — real psql/mongosh/mysql-client omit it
                description: "Native database wire protocol (psql, mongosh, mysql-client)",
            },
        );
        entries.insert(
            ServiceCategory::Mail,
            AlpnEntry {
                category: ServiceCategory::Mail,
                protocols: vec!["http/1.1"],
                description: "Webmail interfaces",
            },
        );
        entries.insert(
            ServiceCategory::Cdn,
            AlpnEntry {
                category: ServiceCategory::Cdn,
                protocols: vec!["h2", "http/1.1"],
                description: "CDN edge nodes",
            },
        );
        entries.insert(
            ServiceCategory::Gaming,
            AlpnEntry {
                category: ServiceCategory::Gaming,
                protocols: vec!["h2", "http/1.1"],
                description: "Game platform APIs",
            },
        );
        entries.insert(
            ServiceCategory::Streaming,
            AlpnEntry {
                category: ServiceCategory::Streaming,
                protocols: vec!["h2", "http/1.1"],
                description: "Media streaming services",
            },
        );
        entries.insert(
            ServiceCategory::OsUpdate,
            AlpnEntry {
                category: ServiceCategory::OsUpdate,
                protocols: vec!["h2", "http/1.1"],
                description: "OS update services (Windows Update, macOS SUS, apt/yum)",
            },
        );
        entries.insert(
            ServiceCategory::CliTool,
            AlpnEntry {
                category: ServiceCategory::CliTool,
                protocols: vec!["h2", "http/1.1"],
                description: "CLI tools (curl, wget, pip, npm)",
            },
        );
        entries.insert(
            ServiceCategory::Domestic,
            AlpnEntry {
                category: ServiceCategory::Domestic,
                protocols: vec!["h2", "http/1.1"],
                description: "Domestic site traffic mimicry",
            },
        );

        let domain_rules = vec![
            // OS Update servers (highest priority — VIP lane)
            (
                vec![
                    "windowsupdate",
                    "update.microsoft",
                    "download.windowsupdate",
                ],
                ServiceCategory::OsUpdate,
            ),
            (
                vec!["swscan.apple", "mesu.apple", "swdist.apple", "oscdn.apple"],
                ServiceCategory::OsUpdate,
            ),
            (
                vec!["archive.ubuntu", "deb.debian", "security.debian"],
                ServiceCategory::OsUpdate,
            ),
            (
                vec!["mirrors.fedora", "download.fedora", "yum."],
                ServiceCategory::OsUpdate,
            ),
            // Domestic sites (Decoy targets)
            (
                vec![
                    "baidu.com",
                    "taobao.com",
                    "qq.com",
                    "sina.com.cn",
                    "jd.com",
                    "163.com",
                ],
                ServiceCategory::Domestic,
            ),
            // CLI / package registries
            (
                vec!["pypi.org", "registry.npmjs", "crates.io", "download.docker"],
                ServiceCategory::CliTool,
            ),
            (
                vec!["rubygems.org", "packagist.org", "repo.maven"],
                ServiceCategory::CliTool,
            ),
            // IoT / messaging
            (
                vec!["mqtt", "iot", "telemetry", "sensor", "device"],
                ServiceCategory::Mqtt,
            ),
            (vec!["grpc", "api.internal", "rpc"], ServiceCategory::Grpc),
            (
                vec!["mail", "smtp", "imap", "webmail"],
                ServiceCategory::Mail,
            ),
            (
                vec!["cdn", "edge", "cache", "static", "assets"],
                ServiceCategory::Cdn,
            ),
            (
                vec!["steam", "game", "play", "xbox", "psn"],
                ServiceCategory::Gaming,
            ),
            (
                vec!["stream", "video", "media", "netflix", "youtube"],
                ServiceCategory::Streaming,
            ),
            (
                vec!["postgres", "mysql", "redis", "mongo", "db"],
                ServiceCategory::Database,
            ),
        ];

        Self {
            entries,
            domain_rules,
        }
    }

    /// Classify a domain into a service category.
    pub fn classify(&self, domain: &str) -> ServiceCategory {
        let lower = domain.to_lowercase();
        for (keywords, category) in &self.domain_rules {
            for kw in keywords {
                if lower.contains(kw) {
                    return *category;
                }
            }
        }
        ServiceCategory::Web
    }

    /// Get the ALPN protocol list for a given domain.
    pub fn alpn_for(&self, domain: &str) -> Vec<String> {
        let cat = self.classify(domain);
        self.entries
            .get(&cat)
            .map(|e| e.protocols.iter().map(|s| s.to_string()).collect())
            .unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()])
    }

    /// Get the entry for a specific category.
    pub fn get(&self, cat: ServiceCategory) -> Option<&AlpnEntry> {
        self.entries.get(&cat)
    }
}

impl Default for AlpnPortfolio {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile Factory
// ─────────────────────────────────────────────────────────────────────────────

/// Browser profile identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserProfile {
    Chrome140,
    Chrome139,
    Firefox128,
    Safari18,
    Edge140,
    /// curl 8.x with OpenSSL 3.3 backend.
    CurlOpenssl,
    /// wget 1.24 with GnuTLS 3.8 backend.
    WgetGnuTls,
    /// Python 3.12 urllib3 / requests with OpenSSL.
    PythonUrllib,
}

/// Extension ordering template for a browser profile.
#[derive(Debug, Clone)]
pub struct ExtensionTemplate {
    /// Fixed-position extensions (must appear at these indices).
    pub fixed_head: Vec<u16>,
    /// Shuffleable middle-band extension type codes.
    pub middle_band: Vec<u16>,
    /// Fixed-position tail extensions.
    pub fixed_tail: Vec<u16>,
}

/// Complete TLS profile specification.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub browser: BrowserProfile,
    pub cipher_suites: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub extensions: ExtensionTemplate,
    pub record_size_limit: u16,
    pub compress_certificate_algos: Vec<u16>,
    pub uses_grease: bool,
    pub uses_psk: bool,
}

/// Factory that produces randomized TLS profiles from a curated set.
pub struct ProfileFactory {
    profiles: Vec<TlsProfile>,
    portfolio: AlpnPortfolio,
}

impl ProfileFactory {
    /// Build the factory with all built-in browser profiles.
    pub fn new() -> Self {
        Self {
            profiles: vec![
                Self::chrome_140(),
                Self::chrome_139(),
                Self::firefox_128(),
                Self::safari_18(),
                Self::edge_140(),
                Self::curl_openssl(),
                Self::wget_gnutls(),
                Self::python_urllib(),
            ],
            portfolio: AlpnPortfolio::new(),
        }
    }

    /// Select a random profile weighted by browser market share.
    pub fn random_profile(&self) -> &TlsProfile {
        let mut rng = rand::thread_rng();
        // Weights: Chrome ~65%, Edge ~5%, Firefox ~15%, Safari ~15%
        let weights = [40, 25, 15, 15, 5]; // indices: chrome140, chrome139, firefox128, safari18, edge140
        let total: u32 = weights.iter().sum();
        let roll = rng.gen_range(0..total);
        let mut acc = 0;
        for (i, w) in weights.iter().enumerate() {
            acc += w;
            if roll < acc {
                return &self.profiles[i];
            }
        }
        &self.profiles[0]
    }

    /// Get a specific browser profile.
    pub fn get_profile(&self, browser: BrowserProfile) -> Option<&TlsProfile> {
        self.profiles.iter().find(|p| p.browser == browser)
    }

    /// Get the ALPN portfolio.
    pub fn portfolio(&self) -> &AlpnPortfolio {
        &self.portfolio
    }

    /// Generate a shuffled extension order for a given profile.
    pub fn shuffled_extensions(&self, profile: &TlsProfile) -> Vec<u16> {
        let mut rng = rand::thread_rng();
        let mut result = profile.extensions.fixed_head.clone();
        let mut middle = profile.extensions.middle_band.clone();
        middle.shuffle(&mut rng);
        result.extend(middle);
        result.extend(profile.extensions.fixed_tail.clone());
        result
    }

    // --- Built-in Profile Definitions ---

    fn chrome_140() -> TlsProfile {
        TlsProfile {
            browser: BrowserProfile::Chrome140,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0808,
                0x0809, 0x0203,
            ],
            supported_groups: vec![0x6399, 0x001d, 0x0017, 0x0018, 0x0019],
            extensions: ExtensionTemplate {
                fixed_head: vec![0x0000], // SNI
                middle_band: vec![
                    0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x000d, 0x0012,
                    0x001b,
                ],
                fixed_tail: vec![0x0033, 0x002b, 0x002d, 0x001c, 0x4469, 0x0015],
            },
            record_size_limit: 16385,
            compress_certificate_algos: vec![0x0002], // brotli
            uses_grease: true,
            uses_psk: true,
        }
    }

    fn chrome_139() -> TlsProfile {
        let mut p = Self::chrome_140();
        p.browser = BrowserProfile::Chrome139;
        // Chrome 139 uses the same suite but without secp521r1
        p.supported_groups = vec![0x6399, 0x001d, 0x0017, 0x0018];
        p
    }

    fn firefox_128() -> TlsProfile {
        TlsProfile {
            browser: BrowserProfile::Firefox128,
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0100],
            extensions: ExtensionTemplate {
                fixed_head: vec![0x0000],
                middle_band: vec![
                    0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x001c,
                ],
                fixed_tail: vec![0x0033, 0x002b, 0x002d, 0x0015],
            },
            record_size_limit: 16385,
            compress_certificate_algos: vec![0x0002],
            uses_grease: false,
            uses_psk: true,
        }
    }

    fn safari_18() -> TlsProfile {
        TlsProfile {
            browser: BrowserProfile::Safari18,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xcca8, 0xc030, 0xc02f, 0x009d,
                0x009c, 0x0035, 0x002f,
            ],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0019],
            extensions: ExtensionTemplate {
                fixed_head: vec![0x0000],
                middle_band: vec![
                    0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012,
                ],
                fixed_tail: vec![0x0033, 0x002b, 0x002d, 0x0015],
            },
            record_size_limit: 16384,
            compress_certificate_algos: Vec::new(),
            uses_grease: true,
            uses_psk: true,
        }
    }

    fn edge_140() -> TlsProfile {
        // Edge uses Chromium engine — nearly identical to Chrome
        let mut p = Self::chrome_140();
        p.browser = BrowserProfile::Edge140;
        p
    }

    /// curl 8.x / OpenSSL 3.3 — no GREASE, no PSK, no compress_certificate.
    /// Matches the default cipher ordering emitted by libcurl + OpenSSL.
    fn curl_openssl() -> TlsProfile {
        TlsProfile {
            browser: BrowserProfile::CurlOpenssl,
            cipher_suites: vec![
                0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009d, 0x009c, 0xc024,
                0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x0035, 0x002f, 0x00ff,
            ],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            extensions: ExtensionTemplate {
                fixed_head: vec![0x0000], // SNI
                middle_band: vec![
                    0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002b,
                    0x002d,
                ],
                fixed_tail: vec![0x0015],
            },
            record_size_limit: 16384,
            compress_certificate_algos: Vec::new(), // OpenSSL doesn't support
            uses_grease: false,
            uses_psk: false,
        }
    }

    /// wget 1.24 / GnuTLS 3.8 — GnuTLS-specific ordering, no GREASE or PSK.
    fn wget_gnutls() -> TlsProfile {
        TlsProfile {
            browser: BrowserProfile::WgetGnuTls,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c,
                0x009d, 0xc09c, 0xc09d, 0xc0a0, 0xc0a1, 0x002f, 0x0035, 0x003c, 0x003d, 0x00ff,
            ],
            signature_algorithms: vec![
                0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0201,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100],
            extensions: ExtensionTemplate {
                fixed_head: vec![0x0000], // SNI
                middle_band: vec![
                    0xff01, 0x000a, 0x000b, 0x000d, 0x0010, 0x0016, 0x0033, 0x002b, 0x002d,
                ],
                fixed_tail: vec![0x0015],
            },
            record_size_limit: 16384,
            compress_certificate_algos: Vec::new(),
            uses_grease: false,
            uses_psk: false,
        }
    }

    /// Python 3.12 urllib3/requests — OpenSSL backend, matches `requests` library.
    fn python_urllib() -> TlsProfile {
        TlsProfile {
            browser: BrowserProfile::PythonUrllib,
            cipher_suites: vec![
                0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009d, 0x009c, 0xc024,
                0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x0035, 0x002f,
            ],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            extensions: ExtensionTemplate {
                fixed_head: vec![0x0000],
                middle_band: vec![
                    0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002b,
                    0x002d,
                ],
                fixed_tail: vec![0x0015],
            },
            record_size_limit: 16384,
            compress_certificate_algos: Vec::new(),
            uses_grease: false,
            uses_psk: false,
        }
    }
}

impl Default for ProfileFactory {
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
    fn test_alpn_portfolio_web() {
        let portfolio = AlpnPortfolio::new();
        let alpn = portfolio.alpn_for("google.com");
        assert!(alpn.contains(&"h2".to_string()));
        assert!(alpn.contains(&"http/1.1".to_string()));
    }

    #[test]
    fn test_alpn_portfolio_mqtt() {
        let portfolio = AlpnPortfolio::new();
        let alpn = portfolio.alpn_for("iot-gateway.local");
        assert!(alpn.contains(&"mqtt".to_string()));
    }

    #[test]
    fn test_alpn_portfolio_grpc() {
        let portfolio = AlpnPortfolio::new();
        let alpn = portfolio.alpn_for("grpc.service.internal");
        assert_eq!(alpn, vec!["h2".to_string()]);
    }

    #[test]
    fn test_classify_domain() {
        let portfolio = AlpnPortfolio::new();
        assert_eq!(
            portfolio.classify("mqtt-broker.local"),
            ServiceCategory::Mqtt
        );
        assert_eq!(portfolio.classify("grpc.api.com"), ServiceCategory::Grpc);
        assert_eq!(portfolio.classify("example.com"), ServiceCategory::Web);
        assert_eq!(portfolio.classify("cdn.assets.net"), ServiceCategory::Cdn);
    }

    #[test]
    fn test_profile_factory_all_profiles_present() {
        let factory = ProfileFactory::new();
        assert!(factory.get_profile(BrowserProfile::Chrome140).is_some());
        assert!(factory.get_profile(BrowserProfile::Firefox128).is_some());
        assert!(factory.get_profile(BrowserProfile::Safari18).is_some());
        assert!(factory.get_profile(BrowserProfile::Edge140).is_some());
        assert!(factory.get_profile(BrowserProfile::CurlOpenssl).is_some());
        assert!(factory.get_profile(BrowserProfile::WgetGnuTls).is_some());
        assert!(factory.get_profile(BrowserProfile::PythonUrllib).is_some());
    }

    #[test]
    fn test_chrome140_cipher_count() {
        let factory = ProfileFactory::new();
        let chrome = factory.get_profile(BrowserProfile::Chrome140).unwrap();
        assert_eq!(chrome.cipher_suites.len(), 15);
    }

    #[test]
    fn test_shuffled_extensions_preserves_fixed() {
        let factory = ProfileFactory::new();
        let chrome = factory.get_profile(BrowserProfile::Chrome140).unwrap();
        let ext = factory.shuffled_extensions(chrome);
        assert_eq!(ext[0], 0x0000);
        assert_eq!(*ext.last().unwrap(), 0x0015);
    }

    #[test]
    fn test_random_profile_returns_valid() {
        let factory = ProfileFactory::new();
        for _ in 0..100 {
            let profile = factory.random_profile();
            assert!(!profile.cipher_suites.is_empty());
            assert!(!profile.signature_algorithms.is_empty());
        }
    }

    #[test]
    fn test_firefox_no_grease() {
        let factory = ProfileFactory::new();
        let ff = factory.get_profile(BrowserProfile::Firefox128).unwrap();
        assert!(!ff.uses_grease);
    }

    #[test]
    fn test_curl_no_grease_no_psk() {
        let factory = ProfileFactory::new();
        let curl = factory.get_profile(BrowserProfile::CurlOpenssl).unwrap();
        assert!(!curl.uses_grease);
        assert!(!curl.uses_psk);
        assert!(curl.compress_certificate_algos.is_empty());
    }

    #[test]
    fn test_wget_gnutls_no_grease() {
        let factory = ProfileFactory::new();
        let wget = factory.get_profile(BrowserProfile::WgetGnuTls).unwrap();
        assert!(!wget.uses_grease);
        assert!(!wget.uses_psk);
    }

    #[test]
    fn test_python_urllib_profile() {
        let factory = ProfileFactory::new();
        let py = factory.get_profile(BrowserProfile::PythonUrllib).unwrap();
        assert!(!py.uses_grease);
        assert!(!py.uses_psk);
        assert!(py.cipher_suites.len() >= 15);
    }

    #[test]
    fn test_classify_os_update_domains() {
        let portfolio = AlpnPortfolio::new();
        assert_eq!(
            portfolio.classify("slscr.update.microsoft.com"),
            ServiceCategory::OsUpdate
        );
        assert_eq!(
            portfolio.classify("swscan.apple.com"),
            ServiceCategory::OsUpdate
        );
        assert_eq!(
            portfolio.classify("archive.ubuntu.com"),
            ServiceCategory::OsUpdate
        );
    }

    #[test]
    fn test_classify_cli_tool_domains() {
        let portfolio = AlpnPortfolio::new();
        assert_eq!(portfolio.classify("pypi.org"), ServiceCategory::CliTool);
        assert_eq!(
            portfolio.classify("registry.npmjs.org"),
            ServiceCategory::CliTool
        );
        assert_eq!(portfolio.classify("crates.io"), ServiceCategory::CliTool);
    }

    #[test]
    fn test_database_native_no_alpn() {
        let portfolio = AlpnPortfolio::new();
        let entry = portfolio.get(ServiceCategory::DatabaseNative).unwrap();
        assert!(entry.protocols.is_empty(), "Native DB clients send no ALPN");
    }
}
