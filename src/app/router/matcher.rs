use aho_corasick::AhoCorasick;
use ip_network_table::IpNetworkTable;
use ipnetwork::IpNetwork;
use radix_trie::Trie;
use std::net::IpAddr;

/// O(1) / O(LPM) IP Matcher
/// Stores (RuleIndex, Tag) for IPs.
pub struct IpMatcher {
    table: IpNetworkTable<(usize, String)>,
}

impl IpMatcher {
    pub fn new() -> Self {
        Self {
            table: IpNetworkTable::new(),
        }
    }

    pub fn insert(&mut self, net: IpNetwork, rule_idx: usize, tag: String) {
        // Convert ipnetwork::IpNetwork to ip_network::IpNetwork for the table
        let net_internal = ip_network::IpNetwork::new(net.ip(), net.prefix())
            .expect("Invalid IP network conversion");
        self.table.insert(net_internal, (rule_idx, tag));
    }

    /// Returns (RuleIndex, Tag) - First matching rule (lowest index) wins
    pub fn match_ip(&self, ip: IpAddr) -> Option<(usize, String)> {
        // Iterate ALL matches (from specific to generic usually, but we check all)
        // and find the one with the lowest RuleIndex.
        self.table
            .matches(ip)
            .min_by_key(|(rule_idx, _)| *rule_idx)
            .map(|(_, val)| val.clone())
    }
}

/// Domain Matcher using Trie (suffix) and Aho-Corasick (keyword)
pub struct DomainMatcher {
    // Suffix match: "google.com" (reversed) -> RuleIndex
    trie: Trie<String, usize>,

    // Keyword match: "keyword" -> RuleIndex
    patterns: Vec<String>,
    pattern_indices: Vec<usize>,
    ac: Option<AhoCorasick>,
}

impl DomainMatcher {
    pub fn new() -> Self {
        Self {
            trie: Trie::new(),
            patterns: Vec::new(),
            pattern_indices: Vec::new(),
            ac: None,
        }
    }

    pub fn add_domain_rule(&mut self, domain: &str, rule_idx: usize) {
        if let Some(stripped) = domain.strip_prefix("domain:") {
            // Suffix match
            let rev: String = stripped.chars().rev().collect();
            // Insert or update with min rule_idx if strict overlap exists on same node
            if let Some(&existing) = self.trie.get(&rev) {
                if rule_idx < existing {
                    self.trie.insert(rev, rule_idx);
                }
            } else {
                self.trie.insert(rev, rule_idx);
            }
        } else if let Some(stripped) = domain.strip_prefix("full:") {
            // Exact match - treat as suffix with terminator
            let mut rev: String = stripped.chars().rev().collect();
            rev.push('$');
            self.trie.insert(rev, rule_idx);
        } else {
            // Keyword / Substring
            if let Some(kw) = domain.strip_prefix("keyword:") {
                self.patterns.push(kw.to_string());
                self.pattern_indices.push(rule_idx);
            // Xray: plain "google.com" is effectively "domain:google.com" (suffix)
            } else if !domain.contains(':') {
                let rev: String = domain.chars().rev().collect();
                if let Some(&existing) = self.trie.get(&rev) {
                    if rule_idx < existing {
                        self.trie.insert(rev, rule_idx);
                    }
                } else {
                    self.trie.insert(rev, rule_idx);
                }
            }
        }
    }

    pub fn build(&mut self) {
        if !self.patterns.is_empty() {
            // Use MatchKind::Standard which supports overlapping via find_overlapping_iter
            self.ac = Some(
                AhoCorasick::builder()
                    .match_kind(aho_corasick::MatchKind::Standard)
                    .build(&self.patterns)
                    .unwrap(),
            );
        }
    }

    pub fn match_domain(&self, domain: &str) -> Option<usize> {
        let mut best_match = None;

        // 1. Suffix/Full Match (Trie)
        // Reversed domain: "moc.elgoog", "ri.moc.elgoog"
        let rev: String = domain.chars().rev().collect();

        // A. Full Exact Match ("full:google.com") -> "moc.elgoog$"
        let mut full_rev = rev.clone();
        full_rev.push('$');
        if let Some(&idx) = self.trie.get(&full_rev) {
            best_match = Some(idx);
        }

        // B. Suffix Match ("domain:google.com")
        // We must check every dot boundary in the reversed string to emulate
        // "ancestor" checks while respecting first-match priority.
        // e.g. "moc.elgoog.liam" -> Check "moc", "moc.elgoog", "moc.elgoog.liam"

        // Manual iter over dots
        for (i, c) in rev.char_indices() {
            if c == '.' {
                let slice = &rev[0..i];
                if let Some(&idx) = self.trie.get(slice) {
                    best_match = match best_match {
                        Some(cur) => Some(std::cmp::min(cur, idx)),
                        None => Some(idx),
                    };
                }
            }
        }

        // Also check header (full string) as a suffix (e.g. domain:google.com matches google.com)
        if let Some(&idx) = self.trie.get(&rev) {
            best_match = match best_match {
                Some(cur) => Some(std::cmp::min(cur, idx)),
                None => Some(idx),
            };
        }

        // 2. Keyword Match (AC) - Check overlaps
        if let Some(ac) = &self.ac {
            // Find ALL matches (overlapping)
            for mat in ac.find_overlapping_iter(domain) {
                let pid = mat.pattern();
                let rule_idx = self.pattern_indices[pid];

                best_match = match best_match {
                    Some(current) => Some(std::cmp::min(current, rule_idx)),
                    None => Some(rule_idx),
                };
            }
        }

        best_match
    }
}

/// O(1) Port Matcher
/// Uses a flat array of 65536 entries to store the lowest rule index matching each port.
pub struct PortMatcher {
    // Index: port, Value: lowest rule index
    table: Vec<Option<usize>>,
}

impl PortMatcher {
    pub fn new() -> Self {
        Self {
            table: vec![None; 65536],
        }
    }

    pub fn add_port_rule(&mut self, port_str: &str, rule_idx: usize) {
        // Formats: "80", "80-100", "80,443", "80, 100-200"
        for part in port_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some((start, end)) = part.split_once('-') {
                // Range
                if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                    let min_p = std::cmp::min(s, e);
                    let max_p = std::cmp::max(s, e);
                    for p in min_p..=max_p {
                        self.update_entry(p, rule_idx);
                    }
                }
            } else {
                // Single
                if let Ok(p) = part.parse::<u16>() {
                    self.update_entry(p, rule_idx);
                }
            }
        }
    }

    fn update_entry(&mut self, port: u16, rule_idx: usize) {
        let idx = port as usize;
        match self.table[idx] {
            Some(existing) => {
                if rule_idx < existing {
                    self.table[idx] = Some(rule_idx);
                }
            }
            None => {
                self.table[idx] = Some(rule_idx);
            }
        }
    }

    pub fn match_port(&self, port: u16) -> Option<usize> {
        self.table[port as usize]
    }
}
