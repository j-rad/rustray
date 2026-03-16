// src/app/subscription_fetcher.rs
//! Subscription URL fetcher and parser
//!
//! Supports fetching and parsing v2rayN, Xray, and Clash subscription formats.

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::{debug, info, warn};

/// Subscription format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionFormat {
    /// Base64 encoded v2rayN format
    V2rayN,
    /// JSON format
    Json,
    /// Clash YAML format
    Clash,
}

/// Parsed server configuration from subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedServer {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub config_json: String,
}

/// Subscription fetcher
pub struct SubscriptionFetcher {
    client: reqwest::Client,
}

impl SubscriptionFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// Fetch subscription from URL
    pub async fn fetch(&self, url: &str) -> Result<String> {
        info!("Fetching subscription from: {}", url);

        let response = self.client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP error: {}", response.status()));
        }

        let content = response.text().await?;
        debug!("Fetched {} bytes", content.len());

        Ok(content)
    }

    /// Parse subscription content
    pub fn parse(&self, content: &str) -> Result<Vec<ParsedServer>> {
        // Detect format
        let format = self.detect_format(content);

        match format {
            SubscriptionFormat::V2rayN => self.parse_v2rayn(content),
            SubscriptionFormat::Json => self.parse_json(content),
            SubscriptionFormat::Clash => self.parse_clash(content),
        }
    }

    /// Detect subscription format
    fn detect_format(&self, content: &str) -> SubscriptionFormat {
        let trimmed = content.trim();

        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            SubscriptionFormat::Json
        } else if trimmed.contains("proxies:") || trimmed.contains("proxy-groups:") {
            SubscriptionFormat::Clash
        } else {
            // Assume base64 v2rayN
            SubscriptionFormat::V2rayN
        }
    }

    /// Parse v2rayN format (base64 encoded links)
    fn parse_v2rayn(&self, content: &str) -> Result<Vec<ParsedServer>> {
        let decoded = general_purpose::STANDARD.decode(content.trim())?;
        let decoded_str = String::from_utf8(decoded)?;

        let mut servers = Vec::new();

        for line in decoded_str.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(server) = self.parse_share_link(line) {
                servers.push(server);
            } else {
                warn!("Failed to parse line: {}", line);
            }
        }

        Ok(servers)
    }

    /// Parse share link (vmess://, vless://, trojan://, etc.)
    fn parse_share_link(&self, link: &str) -> Result<ParsedServer> {
        if link.starts_with("vmess://") {
            self.parse_vmess_link(link)
        } else if link.starts_with("vless://") {
            self.parse_vless_link(link)
        } else if link.starts_with("trojan://") {
            self.parse_trojan_link(link)
        } else if link.starts_with("ss://") {
            self.parse_shadowsocks_link(link)
        } else {
            Err(anyhow!("Unsupported protocol in link: {}", link))
        }
    }

    /// Parse vmess:// link
    fn parse_vmess_link(&self, link: &str) -> Result<ParsedServer> {
        let encoded = link
            .strip_prefix("vmess://")
            .ok_or_else(|| anyhow!("Invalid vmess link"))?;
        let decoded = general_purpose::STANDARD.decode(encoded)?;
        let json_str = String::from_utf8(decoded)?;

        let config: serde_json::Value = serde_json::from_str(&json_str)?;

        Ok(ParsedServer {
            name: config["ps"].as_str().unwrap_or("VMess Server").to_string(),
            protocol: "vmess".to_string(),
            address: config["add"].as_str().unwrap_or("").to_string(),
            port: config["port"].as_u64().unwrap_or(443) as u16,
            config_json: json_str,
        })
    }

    /// Parse vless:// link
    fn parse_vless_link(&self, link: &str) -> Result<ParsedServer> {
        // vless://uuid@host:port?params#name
        let without_prefix = link
            .strip_prefix("vless://")
            .ok_or_else(|| anyhow!("Invalid vless link"))?;

        let (uuid_and_addr, rest) = without_prefix
            .split_once('?')
            .unwrap_or((without_prefix, ""));
        let (uuid, addr) = uuid_and_addr
            .split_once('@')
            .ok_or_else(|| anyhow!("Invalid format"))?;
        let (host, port_str) = addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid address"))?;

        let name = rest
            .split_once('#')
            .map(|(_, name)| name)
            .unwrap_or("VLESS Server");

        Ok(ParsedServer {
            name: name.to_string(),
            protocol: "vless".to_string(),
            address: host.to_string(),
            port: port_str.parse()?,
            config_json: serde_json::json!({
                "uuid": uuid,
                "address": host,
                "port": port_str.parse::<u16>()?,
            })
            .to_string(),
        })
    }

    /// Parse trojan:// link
    fn parse_trojan_link(&self, link: &str) -> Result<ParsedServer> {
        // trojan://password@host:port#name
        let without_prefix = link
            .strip_prefix("trojan://")
            .ok_or_else(|| anyhow!("Invalid trojan link"))?;

        let (password_and_addr, name) = without_prefix
            .split_once('#')
            .unwrap_or((without_prefix, "Trojan Server"));
        let (password, addr) = password_and_addr
            .split_once('@')
            .ok_or_else(|| anyhow!("Invalid format"))?;
        let (host, port_str) = addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid address"))?;

        Ok(ParsedServer {
            name: name.to_string(),
            protocol: "trojan".to_string(),
            address: host.to_string(),
            port: port_str.parse()?,
            config_json: serde_json::json!({
                "password": password,
                "address": host,
                "port": port_str.parse::<u16>()?,
            })
            .to_string(),
        })
    }

    /// Parse ss:// link (Shadowsocks)
    fn parse_shadowsocks_link(&self, link: &str) -> Result<ParsedServer> {
        let _without_prefix = link
            .strip_prefix("ss://")
            .ok_or_else(|| anyhow!("Invalid ss link"))?;

        // Basic parsing, real implementation would be more complex
        Ok(ParsedServer {
            name: "Shadowsocks Server".to_string(),
            protocol: "shadowsocks".to_string(),
            address: "unknown".to_string(),
            port: 443,
            config_json: "{}".to_string(),
        })
    }

    /// Parse JSON format subscription
    fn parse_json(&self, content: &str) -> Result<Vec<ParsedServer>> {
        let json: JsonValue = serde_json::from_str(content)?;
        let mut servers = Vec::new();

        // Check if it's a list or object
        if let Some(list) = json.as_array() {
            // Assume list of outbound objects
            for (i, item) in list.iter().enumerate() {
                if let Ok(server) = self.parse_json_outbound(item, &format!("Server-{}", i)) {
                    servers.push(server);
                }
            }
        } else if let Some(outbounds) = json.get("outbounds").and_then(|v| v.as_array()) {
            // Standard Xray config
            for (i, item) in outbounds.iter().enumerate() {
                if let Ok(server) = self.parse_json_outbound(item, &format!("Server-{}", i)) {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    fn parse_json_outbound(&self, item: &JsonValue, default_name: &str) -> Result<ParsedServer> {
        let protocol = item
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let tag = item
            .get("tag")
            .and_then(|v| v.as_str())
            .unwrap_or(default_name);

        // Extract settings... this is complex for generic JSON,
        // simplifies to storing the whole block for now.
        // We try to extract address/port for UI display.
        let (address, port) = if let Some(settings) = item.get("settings") {
            if let Some(vnext) = settings
                .get("vnext")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
            {
                let addr = vnext.get("address").and_then(|v| v.as_str()).unwrap_or("");
                let port = vnext.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                (addr.to_string(), port)
            } else {
                ("".to_string(), 0)
            }
        } else {
            ("".to_string(), 0)
        };

        Ok(ParsedServer {
            name: tag.to_string(),
            protocol: protocol.to_string(),
            address,
            port,
            config_json: item.to_string(),
        })
    }

    /// Parse Clash YAML format subscription
    fn parse_clash(&self, content: &str) -> Result<Vec<ParsedServer>> {
        let yaml: serde_yaml::Value = serde_yaml::from_str(content)?;
        let mut servers = Vec::new();

        if let Some(proxies) = yaml.get("proxies").and_then(|v| v.as_sequence()) {
            for proxy in proxies {
                let name = proxy
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Clash Node");
                let type_ = proxy
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let server = proxy.get("server").and_then(|v| v.as_str()).unwrap_or("");
                let port = proxy.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;

                // Keep the raw JSON config representation for internal use
                let config_json = serde_json::to_string(proxy)?;

                // Map Clash type to internal protocol name
                let protocol = match type_ {
                    "ss" => "shadowsocks",
                    "vmess" => "vmess",
                    "vless" => "vless",
                    "trojan" => "trojan",
                    _ => type_,
                };

                servers.push(ParsedServer {
                    name: name.to_string(),
                    protocol: protocol.to_string(),
                    address: server.to_string(),
                    port,
                    config_json,
                });
            }
        }

        Ok(servers)
    }
}

impl Default for SubscriptionFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        let fetcher = SubscriptionFetcher::new();

        assert_eq!(fetcher.detect_format("{}"), SubscriptionFormat::Json);
        assert_eq!(
            fetcher.detect_format("proxies:\n  - name: test"),
            SubscriptionFormat::Clash
        );
        assert_eq!(
            fetcher.detect_format("dG1lc3M6Ly8="),
            SubscriptionFormat::V2rayN
        );
    }

    #[test]
    fn test_vless_link_parsing() {
        let fetcher = SubscriptionFetcher::new();
        let link = "vless://a18ecb8a-b18e-4285-86ba-898887ca8aae@example.com:443?encryption=none&security=tls#MyServer";

        let result = fetcher.parse_vless_link(link);
        assert!(result.is_ok());

        let server = result.unwrap();
        assert_eq!(server.protocol, "vless");
        assert_eq!(server.address, "example.com");
        assert_eq!(server.port, 443);
    }
}
