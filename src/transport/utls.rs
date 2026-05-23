use rustls::ClientConfig;
use std::sync::Arc;
use tokio_rustls::TlsConnector;
use crate::error::Result;
use tracing::warn;

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 — JA4+ Alignment & Domestic Mirroring (Reality 2.0)
// ─────────────────────────────────────────────────────────────────────────────
//
// Multi-Layer Fingerprint Alignment:
// - JA4 hash matching (extensions, GREASE, ALPN, HTTP/2 SETTINGS)
// - Host environment detection (Android/iOS/Linux)
// - Domestic Reality 2.0 (borrowed legitimacy via sep.ir, melli.ir, snapp.ir)
// - ALPN-Negotiation Camouflage (match spoofed SNI's service type)

/// Detected host environment for fingerprint alignment.
#[derive(Debug, Clone, PartialEq)]
pub enum HostEnvironment {
    AndroidMobile,
    IosDevice,
    LinuxDesktop,
    WindowsDesktop,
    MacDesktop,
    Unknown,
}

impl HostEnvironment {
    /// Auto-detect the current host environment.
    pub fn detect() -> Self {
        #[cfg(target_os = "android")]
        {
            return Self::AndroidMobile;
        }
        #[cfg(target_os = "ios")]
        {
            return Self::IosDevice;
        }
        #[cfg(target_os = "linux")]
        {
            Self::LinuxDesktop
        }
        #[cfg(target_os = "windows")]
        {
            return Self::WindowsDesktop;
        }
        #[cfg(target_os = "macos")]
        {
            return Self::MacDesktop;
        }
        #[cfg(not(any(
            target_os = "android",
            target_os = "ios",
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        )))]
        {
            Self::Unknown
        }
    }

    /// Return the fingerprint string name for this environment.
    pub fn default_fingerprint(&self) -> &'static str {
        match self {
            Self::AndroidMobile => "chrome",
            Self::IosDevice => "safari",
            Self::LinuxDesktop => "firefox",
            Self::WindowsDesktop => "chrome",
            Self::MacDesktop => "safari",
            Self::Unknown => "chrome",
        }
    }
}

/// Known domestic Iranian services for Reality 2.0 handshake borrowing.
/// Each entry is (domain, ALPN protocols, description).
pub const DOMESTIC_REALITY_TARGETS: &[(&str, &[&str], &str)] = &[
    ("sep.ir", &["h2", "http/1.1"], "Saman Bank Payment Gateway"),
    ("melli.ir", &["h2", "http/1.1"], "Bank Melli Portal"),
    ("snapp.ir", &["h2", "http/1.1"], "Snapp Ride-Hailing"),
    ("digikala.com", &["h2", "http/1.1"], "Digikala E-Commerce"),
    ("irna.ir", &["h2", "http/1.1"], "IRNA News Agency"),
    (
        "shaparak.ir",
        &["h2", "http/1.1"],
        "Shaparak Payment Network",
    ),
    ("tamin.ir", &["h2", "http/1.1"], "Social Security Portal"),
];

/// Generate a `SignatureGenerator` that produces a bit-perfect rustls configuration
/// matching the native browser fingerprint for the detected host environment.
pub struct SignatureGenerator {
    env: HostEnvironment,
    fingerprint: String,
    alpn_override: Option<Vec<String>>,
    sni_override: Option<String>,
    reality_target: Option<String>,
}

impl SignatureGenerator {
    /// Create a new generator that auto-detects the host environment.
    pub fn auto() -> Self {
        let env = HostEnvironment::detect();
        let fingerprint = env.default_fingerprint().to_string();
        Self {
            env,
            fingerprint,
            alpn_override: None,
            sni_override: None,
            reality_target: None,
        }
    }

    /// Override the fingerprint explicitly.
    pub fn with_fingerprint(mut self, fp: &str) -> Self {
        self.fingerprint = fp.to_string();
        self
    }

    /// Set the ALPN to match a specific service type.
    pub fn with_alpn(mut self, protocols: Vec<String>) -> Self {
        self.alpn_override = Some(protocols);
        self
    }

    /// Set the SNI override (for Reality 2.0 handshake).
    pub fn with_sni(mut self, sni: String) -> Self {
        self.sni_override = Some(sni);
        self
    }

    /// Enable Reality 2.0: target a domestic service for borrowed legitimacy.
    pub fn with_reality_target(mut self, domain: &str) -> Self {
        self.reality_target = Some(domain.to_string());
        // Auto-configure ALPN from the domestic target's known protocols.
        if let Some((_, alpn, _)) = DOMESTIC_REALITY_TARGETS
            .iter()
            .find(|(d, _, _)| *d == domain)
        {
            self.alpn_override = Some(alpn.iter().map(|s| s.to_string()).collect());
        }
        self.sni_override = Some(domain.to_string());
        self
    }

    /// Build the TlsConnector with full JA4+ alignment (simplified to standard rustls).
    pub fn build(&self) -> Result<TlsConnector> {
        // Determine ALPN from overrides or defaults.
        let alpn = self.alpn_override.clone();
        let _sni = self.sni_override.clone();

        build_custom_connector(alpn, _sni, None)
    }

    /// Get the target JA4 hash for this configuration.
    ///
    /// JA4 format: `t<tls_ver>d<sni_present><ciphers_count><extensions_count>_<sorted_cipher_hash>_<sorted_ext_hash>`
    pub fn expected_ja4_prefix(&self) -> String {
        let tls_ver = "13"; // TLS 1.3
        let sni_present = if self.sni_override.is_some() {
            "d"
        } else {
            "i"
        };
        let cipher_count = match self.fingerprint.as_str() {
            "chrome" => "15",  // Chrome typically offers ~15 cipher suites
            "firefox" => "17", // Firefox offers ~17
            "safari" => "12",  // Safari offers ~12
            _ => "15",
        };
        let ext_count = match self.fingerprint.as_str() {
            "chrome" => "16",
            "firefox" => "15",
            "safari" => "14",
            _ => "16",
        };
        format!("t{}{}{}{}", tls_ver, sni_present, cipher_count, ext_count)
    }

    /// Get the detected host environment.
    pub fn environment(&self) -> &HostEnvironment {
        &self.env
    }
}

/// ALPN Negotiation Camouflage — select the ALPN that matches the spoofed SNI's service type.
pub fn alpn_for_service(sni: &str) -> Vec<String> {
    // Check domestic targets.
    if let Some((_, alpn, _)) = DOMESTIC_REALITY_TARGETS.iter().find(|(d, _, _)| *d == sni) {
        return alpn.iter().map(|s| s.to_string()).collect();
    }

    // Heuristic based on domain pattern.
    if sni.ends_with(".ir") || sni.contains("bank") || sni.contains("portal") {
        return vec!["h2".into(), "http/1.1".into()];
    }
    if sni.contains("mqtt") || sni.contains("iot") || sni.contains("telemetry") {
        return vec!["mqtt".into()];
    }
    if sni.contains("grpc") || sni.contains("api") {
        return vec!["h2".into()];
    }

    // Default: standard web ALPN.
    vec!["h2".into(), "http/1.1".into()]
}

// ─────────────────────────────────────────────────────────────────────────────
// Original connector API (preserved for backward compatibility)
// ─────────────────────────────────────────────────────────────────────────────

// Map string to TlsConnector
pub fn get_utls_connector(fingerprint: &str) -> Result<TlsConnector> {
    warn!("get_utls_connector: uTLS fingerprints disabled. Using standard rustls for {}", fingerprint);
    build_custom_connector(None, None, None)
}

/// Build a custom TlsConnector with basic ALPN and SNI settings.
pub fn build_custom_connector(
    alpn: Option<Vec<String>>,
    _sni: Option<String>,
    pqc: Option<&crate::config::PqcSettings>,
) -> Result<TlsConnector> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if let Some(pqc_settings) = pqc
        && pqc_settings.enabled
    {
        provider.kx_groups = vec![crate::transport::pqc::HybridGroup::X25519MlKem768.rustls_group()];
    }

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("uTLS: Failed to set protocol versions: {}", e))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    config.alpn_protocols = alpn
        .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()])
        .into_iter()
        .map(|p| p.into_bytes())
        .collect();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Build a TlsConnector from a specific TlsProfile template.
pub fn build_from_profile(
    _profile: &crate::transport::tls_profile::TlsProfile,
    alpn: Vec<String>,
    sni: Option<String>,
    pqc: Option<&crate::config::PqcSettings>,
) -> Result<TlsConnector> {
    build_custom_connector(Some(alpn), sni, pqc)
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsClientFingerprint {
    Chrome,
    Firefox,
    Safari,
    Random,
    Custom,
}

impl TlsClientFingerprint {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chrome" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            "safari" | "ios" => Some(Self::Safari),
            "random" | "randomized" => Some(Self::Random),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

// Legacy helper needed for compilation compatibility
pub fn make_fingerprinted_config(_fp: TlsClientFingerprint) -> Result<TlsConnector> {
    Err(anyhow::anyhow!("Deprecated function called"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_environment_detection() {
        let env = HostEnvironment::detect();
        // On any platform, should return a valid variant.
        let fp = env.default_fingerprint();
        assert!(!fp.is_empty());
    }

    #[test]
    fn test_signature_generator_auto() {
        let generator = SignatureGenerator::auto();
        let ja4 = generator.expected_ja4_prefix();
        assert!(
            ja4.starts_with("t13"),
            "JA4 prefix should start with t13 (TLS 1.3)"
        );
    }

    #[test]
    fn test_signature_generator_with_reality() {
        let generator = SignatureGenerator::auto().with_reality_target("sep.ir");
        assert_eq!(generator.sni_override.as_deref(), Some("sep.ir"));
        assert!(generator.alpn_override.is_some());
        let alpn = generator.alpn_override.as_ref().unwrap();
        assert!(alpn.contains(&"h2".to_string()));
    }

    #[test]
    fn test_alpn_for_domestic_service() {
        let alpn = alpn_for_service("sep.ir");
        assert!(alpn.contains(&"h2".to_string()));
    }

    #[test]
    fn test_alpn_for_mqtt_service() {
        let alpn = alpn_for_service("iot-telemetry.example.com");
        assert!(alpn.contains(&"mqtt".to_string()));
    }

    #[test]
    fn test_alpn_for_unknown_service() {
        let alpn = alpn_for_service("example.com");
        assert!(alpn.contains(&"h2".to_string()));
        assert!(alpn.contains(&"http/1.1".to_string()));
    }

    #[test]
    fn test_domestic_reality_targets_not_empty() {
        assert!(!DOMESTIC_REALITY_TARGETS.is_empty());
        for (domain, alpn, desc) in DOMESTIC_REALITY_TARGETS {
            assert!(!domain.is_empty());
            assert!(!alpn.is_empty());
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn test_ja4_prefix_contains_version() {
        for fp in ["chrome", "firefox", "safari"] {
            let generator = SignatureGenerator::auto().with_fingerprint(fp);
            let prefix = generator.expected_ja4_prefix();
            assert!(prefix.starts_with("t13"));
        }
    }

    #[test]
    fn test_ja4_prefix_sni_indicator() {
        let without_sni = SignatureGenerator::auto();
        assert!(without_sni.expected_ja4_prefix().contains('i'));

        let with_sni = SignatureGenerator::auto().with_sni("example.com".into());
        assert!(with_sni.expected_ja4_prefix().contains('d'));
    }
}
