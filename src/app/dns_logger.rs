//! DNS query logger and statistics tracker
//!
//! Logs blocked domains and tracks DNS query statistics for the threat map

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct BlockedDomainEntry {
    pub domain: String,
    pub category: ThreatCategory,
    pub blocked_at: u64,
    pub request_count: u32,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    Malware,
    Phishing,
    Tracking,
    Advertising,
    Adult,
    Gambling,
    SocialMedia,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct DnsStats {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub allowed_queries: u64,
}

pub struct DnsLogger {
    blocked_domains: Arc<RwLock<HashMap<String, BlockedDomainEntry>>>,
    stats: Arc<RwLock<DnsStats>>,
    threat_lists: Arc<RwLock<ThreatLists>>,
}

#[derive(Default)]
struct ThreatLists {
    malware: Vec<String>,
    phishing: Vec<String>,
    tracking: Vec<String>,
    advertising: Vec<String>,
}

impl DnsLogger {
    pub fn new() -> Self {
        Self {
            blocked_domains: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DnsStats::default())),
            threat_lists: Arc::new(RwLock::new(ThreatLists::default())),
        }
    }

    /// Load threat lists from files or remote sources
    pub async fn load_threat_lists(&self) -> Result<(), String> {
        let mut lists = self.threat_lists.write().unwrap();

        // In production, these would be loaded from files or fetched from remote sources
        lists.malware = vec![
            "malicious-tracker.com".to_string(),
            "phishing-site.net".to_string(),
        ];

        lists.tracking = vec![
            "ad-tracker.io".to_string(),
            "analytics.example.com".to_string(),
        ];

        lists.advertising = vec!["doubleclick.net".to_string(), "ads.google.com".to_string()];

        Ok(())
    }

    /// Check if domain should be blocked
    pub fn should_block(&self, domain: &str) -> Option<ThreatCategory> {
        let lists = self.threat_lists.read().unwrap();

        if lists.malware.iter().any(|d| domain.contains(d)) {
            return Some(ThreatCategory::Malware);
        }

        if lists.phishing.iter().any(|d| domain.contains(d)) {
            return Some(ThreatCategory::Phishing);
        }

        if lists.tracking.iter().any(|d| domain.contains(d)) {
            return Some(ThreatCategory::Tracking);
        }

        if lists.advertising.iter().any(|d| domain.contains(d)) {
            return Some(ThreatCategory::Advertising);
        }

        None
    }

    /// Log a DNS query
    pub fn log_query(&self, domain: &str, source_ip: Option<String>, blocked: bool) {
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_queries += 1;

            if blocked {
                stats.blocked_queries += 1;
            } else {
                stats.allowed_queries += 1;
            }
        }

        // If blocked, add to blocked domains log
        if blocked {
            if let Some(category) = self.should_block(domain) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let mut blocked = self.blocked_domains.write().unwrap();

                blocked
                    .entry(domain.to_string())
                    .and_modify(|e| {
                        e.request_count += 1;
                        e.blocked_at = now;
                    })
                    .or_insert(BlockedDomainEntry {
                        domain: domain.to_string(),
                        category,
                        blocked_at: now,
                        request_count: 1,
                        source_ip,
                    });
            }
        }
    }

    /// Get all blocked domains
    pub fn get_blocked_domains(&self) -> Vec<BlockedDomainEntry> {
        let blocked = self.blocked_domains.read().unwrap();
        blocked.values().cloned().collect()
    }

    /// Get DNS statistics
    pub fn get_stats(&self) -> DnsStats {
        self.stats.read().unwrap().clone()
    }

    /// Clear old entries (older than 24 hours)
    pub fn cleanup_old_entries(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff = now - (24 * 60 * 60); // 24 hours ago

        let mut blocked = self.blocked_domains.write().unwrap();
        blocked.retain(|_, entry| entry.blocked_at > cutoff);
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        *stats = DnsStats::default();
    }
}

impl Default for DnsLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_logging() {
        let logger = DnsLogger::new();
        logger.load_threat_lists().await.unwrap();

        // Log some queries
        logger.log_query("google.com", Some("192.168.1.100".to_string()), false);
        logger.log_query("doubleclick.net", Some("192.168.1.100".to_string()), true);
        logger.log_query(
            "malicious-tracker.com",
            Some("192.168.1.101".to_string()),
            true,
        );

        let stats = logger.get_stats();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.blocked_queries, 2);
        assert_eq!(stats.allowed_queries, 1);

        let blocked = logger.get_blocked_domains();
        assert_eq!(blocked.len(), 2);
    }

    #[test]
    fn test_threat_categorization() {
        let logger = DnsLogger::new();

        // Manually add threat lists for testing
        {
            let mut lists = logger.threat_lists.write().unwrap();
            lists.malware.push("malware.com".to_string());
            lists.tracking.push("tracker.io".to_string());
        }

        assert_eq!(
            logger.should_block("malware.com"),
            Some(ThreatCategory::Malware)
        );
        assert_eq!(
            logger.should_block("tracker.io"),
            Some(ThreatCategory::Tracking)
        );
        assert_eq!(logger.should_block("google.com"), None);
    }
}
