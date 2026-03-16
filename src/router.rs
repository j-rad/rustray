// src/router.rs
use crate::app::dns::DnsServer;
use crate::app::router::assets::DomainType;
use crate::app::router::geo_loader::GeoManager;
use crate::app::router::matcher::{DomainMatcher, IpMatcher, PortMatcher};
use crate::app::sniffer::{SniffResult, Sniffer};
use crate::app::stats::StatsManager;
use crate::config::{LevelPolicy, Rule};
use crate::error::Result;
use crate::outbounds::OutboundManager;
use crate::transport::prefix_stream::PrefixedStream;
use crate::transport::{BoxedStream, Packet};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;

// use futures::StreamExt;
// use futures::stream::FuturesUnordered;
use std::sync::Arc;
// use tokio::time::{Duration, sleep};
use tracing::{debug, info, warn};

// --- Balancer Strategy ---

trait BalancerStrategy: Send + Sync {
    fn select(&self, candidates: &[String], stats: &StatsManager, tag: &str) -> Vec<String>;
}

struct RandomStrategy;
impl BalancerStrategy for RandomStrategy {
    fn select(&self, candidates: &[String], _stats: &StatsManager, _tag: &str) -> Vec<String> {
        use rand::seq::SliceRandom;
        let mut shuffled = candidates.to_vec();
        shuffled.shuffle(&mut rand::thread_rng());
        shuffled
    }
}

struct LeastPingStrategy;
impl BalancerStrategy for LeastPingStrategy {
    fn select(&self, candidates: &[String], stats: &StatsManager, _tag: &str) -> Vec<String> {
        let mut sorted = candidates.to_vec();
        sorted.sort_by_key(|candidate| {
            if let Some(s) = stats.outbound_stats.get(candidate) {
                if s.avg_latency > 0 {
                    return s.avg_latency;
                }
            }
            // Fallback to legacy stats if necessary
            let rtt = stats.get_stats(&format!("outbound>>{}>>observatory>>latency_ms", candidate));
            if rtt > 0 {
                return rtt;
            }
            u64::MAX
        });
        sorted
    }
}

struct ReliabilityStrategy;
impl BalancerStrategy for ReliabilityStrategy {
    fn select(&self, candidates: &[String], stats: &StatsManager, _tag: &str) -> Vec<String> {
        let mut sorted = candidates.to_vec();
        sorted.sort_by(|a, b| {
            let score = |candidate: &String| {
                if let Some(s) = stats.outbound_stats.get(candidate) {
                    // Score = success_rate / (avg_latency + jitter + 1)
                    let denominator = (s.avg_latency + s.jitter + 1) as f64;
                    return s.success_rate / denominator;
                }
                -1.0
            };
            score(b)
                .partial_cmp(&score(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted
    }
}

// --- Router ---

use arc_swap::ArcSwap;

// --- Router Inner ---
struct RouterInner {
    rules: Vec<Rule>,
    domain_matcher: DomainMatcher,
    ip_matcher: IpMatcher,
    port_matcher: PortMatcher,
    regex_rules: HashMap<usize, Vec<Regex>>,
}

// --- Router ---

pub struct Router {
    inner: ArcSwap<RouterInner>,
    outbound_manager: Arc<OutboundManager>,
    dns_server: Arc<DnsServer>,
    stats_manager: Arc<StatsManager>,
}

impl Router {
    pub async fn new(
        stats_manager: Arc<StatsManager>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self> {
        let rules = {
            let config = stats_manager.config.load();
            config
                .routing
                .as_ref()
                .map_or(Vec::new(), |r| r.rules.clone().unwrap_or_default())
        };
        info!("Router initialized with {} rules.", rules.len());

        // Initialize GeoManager (On-Demand Loading)
        let geo_manager = GeoManager::new();
        if let Err(e) = geo_manager.init().await {
            warn!("Failed to initialize GeoManager: {}", e);
        }

        let inner = Self::build_inner(rules, &geo_manager).await;

        Ok(Self {
            inner: ArcSwap::from_pointee(inner),
            outbound_manager,
            dns_server: stats_manager.dns_server.clone(),
            stats_manager,
        })
    }

    pub fn start_monitor(self: &Arc<Self>) {
        let router = self.clone();
        let mut rx = router.stats_manager.config_event_tx.subscribe();

        // 1. Config Event Monitor
        tokio::spawn(async move {
            use crate::app::stats::ConfigEvent;
            while let Ok(event) = rx.recv().await {
                match event {
                    ConfigEvent::FullReload
                    | ConfigEvent::InboundAdded(_)
                    | ConfigEvent::OutboundAdded(_) => {
                        router.reload_rules().await;
                    }
                    _ => {}
                }
            }
        });

        // 2. Asset File Monitor (Hot-Reload)
        let router_assets = self.clone();
        tokio::spawn(async move {
            use crate::app::assets::updater::AssetUpdater;
            use crate::app::platform_paths::get_asset_dir;
            use tokio::sync::mpsc;

            // Determine app_id - usually from config or env, defaulting here
            let app_id = "org.edgeray.rustray";
            let asset_dir = get_asset_dir(app_id);

            // Ensure dir exists
            if !asset_dir.exists() {
                let _ = std::fs::create_dir_all(&asset_dir);
            }

            let (tx, mut rx) = mpsc::channel(10);

            // Start watcher
            info!("Starting asset watcher on {:?}", asset_dir);
            if let Err(e) = AssetUpdater::watch_assets(asset_dir, tx) {
                warn!("Failed to start asset watcher: {}", e);
                return;
            }

            // Handle events
            while let Some(filename) = rx.recv().await {
                info!("Asset changed: {}. Reloading router rules...", filename);
                // Debounce could be added here, but for now direct reload
                router_assets.reload_rules().await;
            }
        });
    }

    /// Atomically update routing rules from current configuration
    pub async fn reload_rules(&self) {
        let rules = {
            let config = self.stats_manager.config.load();
            config
                .routing
                .as_ref()
                .map_or(Vec::new(), |r| r.rules.clone().unwrap_or_default())
        };
        info!("Reloading Router with {} rules...", rules.len());

        let geo_manager = GeoManager::new(); // Re-use singleton internally
        let inner = Self::build_inner(rules, &geo_manager).await;

        self.inner.store(Arc::new(inner));
        info!("Router rules reloaded successfully.");
    }

    async fn build_inner(rules: Vec<Rule>, geo_manager: &GeoManager) -> RouterInner {
        let mut ip_matcher = IpMatcher::new();
        let mut domain_matcher = DomainMatcher::new();
        let mut port_matcher = PortMatcher::new();
        let mut regex_rules = HashMap::new();

        // Build Optimized Index
        for (idx, rule) in rules.iter().enumerate() {
            if rule.rule_type != "field" {
                continue;
            }

            // 1. Compile Domain Rules
            if let Some(domains) = &rule.domain {
                for d in domains {
                    if let Some(re_str) = d.strip_prefix("regexp:") {
                        // Compile Regex
                        match Regex::new(re_str) {
                            Ok(re) => {
                                regex_rules.entry(idx).or_insert_with(Vec::new).push(re);
                            }
                            Err(e) => {
                                warn!("Invalid regex in rule {}: {} ({})", idx, re_str, e);
                            }
                        }
                    } else if let Some(tag) = d.strip_prefix("geosite:") {
                        // GeoSite Lookup via GeoManager
                        let entries = geo_manager.get_geosite_domains(tag).unwrap_or_default();
                        if !entries.is_empty() {
                            for entry in entries {
                                match DomainType::try_from(entry.r#type).ok() {
                                    Some(DomainType::Regex) => match Regex::new(&entry.value) {
                                        Ok(re) => {
                                            regex_rules
                                                .entry(idx)
                                                .or_insert_with(Vec::new)
                                                .push(re);
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Invalid regex in geosite {}: {} ({})",
                                                tag, entry.value, e
                                            );
                                        }
                                    },
                                    Some(DomainType::Plain) => {
                                        domain_matcher.add_domain_rule(
                                            &format!("keyword:{}", entry.value),
                                            idx,
                                        );
                                    }
                                    Some(DomainType::Domain) => {
                                        domain_matcher.add_domain_rule(
                                            &format!("domain:{}", entry.value),
                                            idx,
                                        );
                                    }
                                    Some(DomainType::Full) => {
                                        domain_matcher
                                            .add_domain_rule(&format!("full:{}", entry.value), idx);
                                    }
                                    _ => {
                                        // Default to domain matching for unknown types
                                        domain_matcher.add_domain_rule(
                                            &format!("domain:{}", entry.value),
                                            idx,
                                        );
                                    }
                                }
                            }
                        } else {
                            warn!("GeoSite tag '{}' not found or empty", tag);
                        }
                    } else {
                        // Standard Domain Rule
                        domain_matcher.add_domain_rule(d, idx);
                    }
                }
            }

            // 2. Compile IP Rules (CIDR & GeoIP)
            if let Some(ips) = &rule.ip {
                for ip_str in ips {
                    if let Some(country) = ip_str.strip_prefix("geoip:") {
                        // GeoIP Lookup via GeoManager
                        let networks = geo_manager.get_geoip_cidrs(country).unwrap_or_default();
                        if !networks.is_empty() {
                            for net in networks {
                                ip_matcher.insert(net, idx, rule.outbound_tag.clone());
                            }
                        } else {
                            warn!("GeoIP country code '{}' not found in assets", country);
                        }
                    } else {
                        // Parse as CIDR or IP
                        if let Ok(net) = ip_str.parse::<ipnetwork::IpNetwork>() {
                            ip_matcher.insert(net, idx, rule.outbound_tag.clone());
                        } else if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let net =
                                ipnetwork::IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 })
                                    .unwrap();
                            ip_matcher.insert(net, idx, rule.outbound_tag.clone());
                        } else {
                            warn!("Invalid IP rule: {}", ip_str);
                        }
                    }
                }
            }

            // 3. Compile Port Rules
            if let Some(port_str) = &rule.port {
                port_matcher.add_port_rule(port_str, idx);
            }
        }

        // Finalize matchers
        domain_matcher.build();

        RouterInner {
            rules,
            domain_matcher,
            ip_matcher,
            port_matcher,
            regex_rules,
        }
    }

    async fn resolve_outbound(&self, outbound_tag: &str) -> Vec<String> {
        if outbound_tag.starts_with("balancer:") {
            let balancer_tag = outbound_tag.strip_prefix("balancer:").unwrap();
            let config = self.stats_manager.config.load();
            if let Some(routing) = &config.routing {
                if let Some(balancers) = &routing.balancers {
                    if let Some(b) = balancers.iter().find(|x| x.tag == balancer_tag) {
                        // Gather candidates
                        let mut candidates = Vec::new();
                        if let Some(outbounds) = &config.outbounds {
                            for out in outbounds {
                                for selector in &b.selector {
                                    if out.tag.starts_with(selector) {
                                        candidates.push(out.tag.clone());
                                    }
                                }
                            }
                        }

                        let strategy: Box<dyn BalancerStrategy> = match b.strategy.as_deref() {
                            Some("leastPing") => Box::new(LeastPingStrategy),
                            Some("reliability") => Box::new(ReliabilityStrategy),
                            _ => Box::new(RandomStrategy),
                        };

                        return strategy.select(&candidates, &self.stats_manager, balancer_tag);
                    }
                }
            }
        }
        vec![outbound_tag.to_string()]
    }

    fn resolve_fake_ip(&self, host: &str) -> Option<String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.dns_server.get_domain_from_fake_ip(ip);
        }
        None
    }

    async fn find_matching_tag(&self, host: &str, port: u16) -> String {
        let inner = self.inner.load();

        // Collect optimized candidates
        let mut candidates = Vec::new();

        // 1. IP Match
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Some((idx, _tag)) = inner.ip_matcher.match_ip(ip) {
                candidates.push(idx);
            }
        } else {
            // 2. Domain Match
            if let Some(idx) = inner.domain_matcher.match_domain(host) {
                candidates.push(idx);
            }
        }

        // 3. Port Match
        if let Some(idx) = inner.port_matcher.match_port(port) {
            candidates.push(idx);
        }

        candidates.sort_unstable();
        candidates.dedup();

        // Optimized Scan Logic
        let mut next_scan_idx = 0;
        let limit = inner.rules.len();

        for &cand_idx in &candidates {
            if cand_idx >= limit {
                break;
            }

            // 1. Scan gap [next_scan_idx .. cand_idx)
            for i in next_scan_idx..cand_idx {
                if self.check_rule(&inner, i, host, port) {
                    return inner.rules[i].outbound_tag.clone();
                }
            }

            // 2. Check Candidate
            if self.check_rule(&inner, cand_idx, host, port) {
                return inner.rules[cand_idx].outbound_tag.clone();
            }

            next_scan_idx = cand_idx + 1;
        }

        // 3. Scan remaining [next_scan_idx .. limit)
        for i in next_scan_idx..limit {
            if self.check_rule(&inner, i, host, port) {
                return inner.rules[i].outbound_tag.clone();
            }
        }

        // 4. DNS / IP-On-Demand Fallback
        if host.parse::<IpAddr>().is_err() {
            if let Ok(ips) = self.dns_server.resolve_ip(host).await {
                for ip in ips {
                    if let Some((idx, tag)) = inner.ip_matcher.match_ip(ip) {
                        debug!("IP-On-Demand matched: {} -> {} (Rule {})", host, tag, idx);
                        if self.check_rule(&inner, idx, &ip.to_string(), port) {
                            return tag;
                        }
                    }
                }
            }
        }

        "direct".to_string()
    }

    fn check_rule(&self, inner: &RouterInner, idx: usize, host: &str, port: u16) -> bool {
        let rule = &inner.rules[idx];
        if rule.rule_type != "field" {
            return false;
        }

        // Check Port
        if let Some(port_range) = &rule.port {
            if !self.check_port_rule(port_range, port) {
                return false;
            }
        }

        // Check Domain / Regex
        if let Some(domains) = &rule.domain {
            let mut domain_matched = false;
            if let Some(regexes) = inner.regex_rules.get(&idx) {
                for re in regexes {
                    if re.is_match(host) {
                        domain_matched = true;
                        break;
                    }
                }
            }

            if !domain_matched {
                // Fallback scan for plain domains
                for d in domains {
                    if !d.starts_with("regexp:") && !d.starts_with("geosite:") {
                        if self.check_domain_string(d, host) {
                            domain_matched = true;
                            break;
                        }
                    }
                }
            }

            if !domain_matched {
                return false;
            }
        }

        true
    }

    fn check_port_rule(&self, port_range: &str, port: u16) -> bool {
        for part in port_range.split(',') {
            let part = part.trim();
            if let Some((start, end)) = part.split_once('-') {
                if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
                    if port >= std::cmp::min(s, e) && port <= std::cmp::max(s, e) {
                        return true;
                    }
                }
            } else {
                if let Ok(p) = part.parse::<u16>() {
                    if p == port {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn check_domain_string(&self, rule_domain: &str, host: &str) -> bool {
        if let Some(d) = rule_domain.strip_prefix("domain:") {
            host.ends_with(d)
        } else if let Some(d) = rule_domain.strip_prefix("full:") {
            host == d
        } else if let Some(d) = rule_domain.strip_prefix("keyword:") {
            host.contains(d)
        } else {
            host.ends_with(rule_domain) // Default suffix
        }
    }

    pub async fn route_stream(
        &self,
        stream: BoxedStream,
        host: String,
        port: u16,
        source: String,
        policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        // --- Connection Tracking ---
        use crate::app::connection_tracker::{ActiveSession, TrackedStream, global_tracker};
        use uuid::Uuid;

        let session_id = Uuid::new_v4().to_string();
        let session = ActiveSession::new(
            session_id.clone(),
            source.clone(),
            format!("{}:{}", host, port),
            "tcp".into(), // Defaulting to TCP for stream routing
        );
        let up_ref = session.uploaded_ref.clone();
        let down_ref = session.downloaded_ref.clone();

        global_tracker().register_session(session);

        // Wrap stream to track traffic
        let tracked_stream = TrackedStream::new(stream, session_id, up_ref, down_ref);
        let stream = Box::new(tracked_stream) as BoxedStream;

        let mut target_host = host;

        if let Some(domain) = self.resolve_fake_ip(&target_host) {
            info!("FakeDNS mapped {} -> {}", target_host, domain);
            target_host = domain;
        }

        // --- Sniffing Logic ---
        let mut stream = stream;

        // Sniff if target is IP to detect domain for routing rules
        if target_host.parse::<IpAddr>().is_ok() {
            match Sniffer::sniff(&mut stream, 4096).await {
                Ok((res, buffer)) => {
                    if !buffer.is_empty() {
                        stream = Box::new(PrefixedStream::new(stream, buffer));
                    }

                    match res {
                        SniffResult::Tls { domain: Some(d) } => {
                            info!("Sniffed TLS SNI: {}", d);
                            target_host = d;
                        }
                        SniffResult::Http { host: Some(h) } => {
                            info!("Sniffed HTTP Host: {}", h);
                            target_host = h;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    warn!("Sniffing failed: {}", e);
                    // Proceed with original stream if possible, or fail?
                    // If read failed, likely stream error.
                    return Err(crate::error::Error::Io(e).into());
                }
            }
        }

        info!("Routing request for {}:{}", target_host, port);

        let initial_tag = self.find_matching_tag(&target_host, port).await;
        // Resolve balancer if needed
        let tags = self.resolve_outbound(&initial_tag).await;

        if tags.is_empty() {
            return Err(anyhow::anyhow!("No outbound tags found"));
        }

        // --- Connection Racing (Happy Eyeballs) ---
        if tags.len() > 1 {
            use futures::StreamExt;
            use futures::stream::FuturesUnordered;
            use tokio::time::{Duration, sleep};

            debug!(
                "Racing {} outbound candidates for {}:{}",
                tags.len(),
                target_host,
                port
            );

            let mut tasks = FuturesUnordered::new();
            let mut errors = Vec::new();

            for (idx, tag) in tags.iter().enumerate() {
                if let Some(handler) = self.outbound_manager.get(tag) {
                    let host = target_host.clone();
                    let h_port = port;
                    let h_tag = tag.clone();

                    tasks.push(async move {
                        // Delay subsequent attempts per Happy Eyeballs v2 (RFC 8305)
                        // Recommended: 250ms
                        if idx > 0 {
                            sleep(Duration::from_millis(250 * idx as u64)).await;
                        }

                        match handler.dial(host, h_port).await {
                            Ok(stream) => Ok((stream, h_tag)),
                            Err(e) => Err((e, h_tag)),
                        }
                    });
                }
            }

            // Wait for the first success
            while let Some(res) = tasks.next().await {
                match res {
                    Ok((mut out_stream, tag)) => {
                        info!("Racing winner: {} for {}:{}", tag, target_host, port);
                        // Record success in stats
                        if let Some(mut s) = self.stats_manager.outbound_stats.get_mut(&tag) {
                            s.total_success += 1;
                        }

                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut out_stream).await;
                        return Ok(());
                    }
                    Err((e, tag)) => {
                        warn!("Racing candidate '{}' failed: {}", tag, e);
                        // Record failure in stats
                        if let Some(mut s) = self.stats_manager.outbound_stats.get_mut(&tag) {
                            s.total_fail += 1;
                        }
                        errors.push(format!("{}: {}", tag, e));
                    }
                }
            }

            return Err(anyhow::anyhow!(
                "All racing candidates failed: {:?}",
                errors
            ));
        }

        // Single fallback or single candidate
        let tag = &tags[0];
        if let Some(handler) = self.outbound_manager.get(tag) {
            match handler.handle(stream, target_host, port, policy).await {
                Ok(()) => {
                    if let Some(mut s) = self.stats_manager.outbound_stats.get_mut(tag) {
                        s.total_success += 1;
                    }
                    Ok(())
                }
                Err(e) => {
                    warn!("Outbound handler '{}' failed: {}", tag, e);
                    if let Some(mut s) = self.stats_manager.outbound_stats.get_mut(tag) {
                        s.total_fail += 1;
                    }
                    Err(e)
                }
            }
        } else {
            warn!(
                "No outbound found for tag '{}' (initial: '{}')",
                tag, initial_tag
            );
            Err(anyhow::anyhow!("No outbound found"))
        }
    }

    pub async fn route_packet(&self, packet: impl Packet + 'static) -> Result<()> {
        let dest = packet.dest();
        let mut ip_str = dest.ip().to_string();
        let port = dest.port();

        // --- DNS FIREWALL ---
        // Intercept all cleartext DNS traffic (Port 53) to prevent poisoning.
        // We force it through our tunnel to a trusted remote resolver (8.8.8.8 for now).
        if port == 53 {
            info!(
                "DNS Firewall: Intercepting cleartext DNS query from {}",
                packet.src()
            );

            // Override destination to Trusted DNS
            let trusted_dns: IpAddr = "8.8.8.8".parse().unwrap();
            let new_dest = std::net::SocketAddr::new(trusted_dns, 53);

            // Create redirected packet
            let new_packet = crate::transport::UdpPacket {
                src: packet.src(),
                dest: new_dest,
                data: packet.payload().to_vec(),
            };

            // Route the NEW packet
            // Recursive call logic or just route logic?
            // route_packet takes impl Packet, so we can recurse once or just proceed.
            // But we must change 'ip_str' and 'port' variables for matching tags.

            ip_str = trusted_dns.to_string();
            // Port remains 53

            // Use the NEW packet payload for handling
            // We need to Box the NEW packet, not the old one.

            let initial_tag = self.find_matching_tag(&ip_str, 53).await;
            let tags = self.resolve_outbound(&initial_tag).await;

            if let Some(handler) = self.outbound_manager.get(&tags[0]) {
                return handler.handle_packet(Box::new(new_packet), None).await;
            } else {
                return Err(anyhow::anyhow!("No outbound found for DNS Firewall"));
            }
        }
        // --------------------

        // FakeDNS Check
        if let Some(domain) = self.resolve_fake_ip(&ip_str) {
            debug!("FakeDNS mapped {} -> {}", ip_str, domain);
            ip_str = domain;
        }

        let initial_tag = self.find_matching_tag(&ip_str, port).await;
        let tags = self.resolve_outbound(&initial_tag).await;

        if let Some(handler) = self.outbound_manager.get(&tags[0]) {
            handler.handle_packet(Box::new(packet), None).await
        } else {
            Err(anyhow::anyhow!("No outbound found"))
        }
    }

    /// Determine if an IP address should be proxied (for VPN packet routing)
    pub async fn should_proxy_ip(&self, ip: &IpAddr) -> bool {
        let inner = self.inner.load();
        // Check if IP matches any proxy rules
        if let Some((_idx, tag)) = inner.ip_matcher.match_ip(*ip) {
            // If matched and tag is not "direct", proxy it
            return tag != "direct" && tag != "block";
        }

        // Default: don't proxy if no rule matches
        false
    }

    /// Get an outbound handler by tag
    pub fn get_outbound(&self, tag: &str) -> Option<Arc<dyn crate::outbounds::Outbound>> {
        self.outbound_manager.get(tag)
    }
}
