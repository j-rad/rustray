use crate::app::router::geo_loader::GeoManager;
use crate::app::router::matcher::{DomainMatcher, IpMatcher, PortMatcher};
use crate::config::Rule;
use ipnetwork::IpNetwork;
use std::sync::Arc;
use tracing::{info, warn};

/// Compiles a list of [Rule]s into optimized Matchers.
pub struct RuleCompiler;

impl RuleCompiler {
    /// Compile rules into IP, Domain, and Port matchers.
    ///
    /// # Arguments
    /// * `rules` - The list of routing rules from config.
    /// * `geo` - The GeoManager for expanding geoip/geosite tags.
    pub fn compile(
        rules: &[Rule],
        geo: &Arc<GeoManager>,
    ) -> (IpMatcher, DomainMatcher, PortMatcher) {
        let mut ip_matcher = IpMatcher::new();
        let mut domain_matcher = DomainMatcher::new();
        let mut port_matcher = PortMatcher::new();

        info!("Router: Compiling {} rules...", rules.len());

        for (i, rule) in rules.iter().enumerate() {
            // 1. IP Rules
            if let Some(ips) = &rule.ip {
                for ip_str in ips {
                    Self::compile_ip_rule(ip_str, i, &rule.outbound_tag, &mut ip_matcher, geo);
                }
            }

            // 2. Domain Rules
            if let Some(domains) = &rule.domain {
                for domain_str in domains {
                    Self::compile_domain_rule(domain_str, i, &mut domain_matcher, geo);
                }
            }

            // 3. Port Rules
            if let Some(port_str) = &rule.port {
                port_matcher.add_port_rule(port_str, i);
            }

            // Note: Complex rules (e.g. user, protocol attrs) are not handled by these
            // basic matchers and would require a secondary check or "Complex Matcher"
            // which is outside the current scope of "Trie Matcher".
        }

        (ip_matcher, domain_matcher, port_matcher)
    }

    fn compile_ip_rule(
        ip_str: &str,
        rule_idx: usize,
        tag: &str,
        matcher: &mut IpMatcher,
        geo: &Arc<GeoManager>,
    ) {
        if let Some(code) = ip_str.strip_prefix("geoip:") {
            // Expand GeoIP
            if let Some(nets) = geo.get_geoip_cidrs(code) {
                for net in nets {
                    matcher.insert(net, rule_idx, tag.to_string());
                }
            } else {
                warn!("Router: GeoIP code '{}' not found in assets", code);
            }
        } else if let Ok(net) = ip_str.parse::<IpNetwork>() {
            matcher.insert(net, rule_idx, tag.to_string());
        } else {
            // Try parsing single IP as /32 or /128
            if let Ok(ip) = ip_str.parse::<std::net::IpAddr>()
                && let Ok(net) = IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 }) {
                    matcher.insert(net, rule_idx, tag.to_string());
                }
        }
    }

    fn compile_domain_rule(
        domain_str: &str,
        rule_idx: usize,
        matcher: &mut DomainMatcher,
        geo: &Arc<GeoManager>,
    ) {
        if let Some(category) = domain_str.strip_prefix("geosite:") {
            if let Some(domains) = geo.get_geosite_domains(category) {
                for d in domains {
                    // d is `assets::Domain` struct (protobuf)
                    // type: Plain, Regex, Domain, Full
                    // We need to map to string prefix for `DomainMatcher`.
                    // `DomainMatcher` handles `domain:`, `full:`, `keyword:`.
                    // We map `DomainType` to these prefixes.
                    use crate::app::router::assets::DomainType;
                    let prefix = match DomainType::try_from(d.r#type) {
                        Ok(DomainType::Plain) => "keyword:",
                        Ok(DomainType::Regex) => continue, // Regex not supported in Trie
                        Ok(DomainType::Domain) => "domain:",
                        Ok(DomainType::Full) => "full:",
                        _ => "domain:", // Default
                    };
                    let rule_str = format!("{}{}", prefix, d.value);
                    matcher.add_domain_rule(&rule_str, rule_idx);
                }
            } else {
                warn!("Router: GeoSite code '{}' not found in assets", category);
            }
        } else {
            matcher.add_domain_rule(domain_str, rule_idx);
        }
    }
}
