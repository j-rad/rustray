use crate::types::{Protocol, ServerConfig};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use url::Url;

// Zstd for high density link compression

/// Parse a share link (vmess, vless, trojan, ss, rr) into a ServerConfig
pub fn parse_share_link(link: &str) -> Result<ServerConfig> {
    let link = link.trim();
    if link.starts_with("vmess://") {
        parse_vmess(link)
    } else if link.starts_with("vless://") {
        parse_vless(link)
    } else if link.starts_with("trojan://") {
        parse_trojan(link)
    } else if link.starts_with("ss://") {
        parse_shadowsocks(link)
    } else if link.starts_with("rr://") {
        parse_high_density_link(link)
    } else {
        Err(anyhow!("Unsupported protocol or invalid link format"))
    }
}

/// Generate a standard share link for Vless/Trojan
pub fn generate_share_link(config: &ServerConfig) -> Result<String> {
    Ok(config.to_uri())
}

/// Generate a high-density, zstd compressed, base64 encoded link
pub fn generate_high_density_link(config: &ServerConfig) -> Result<String> {
    let json = serde_json::to_string(config)?;
    let compressed = zstd::stream::encode_all(json.as_bytes(), 3)?;
    let b64 = general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    Ok(format!("rr://{}", b64))
}

/// Parse a high-density `rr://` link
pub fn parse_high_density_link(link: &str) -> Result<ServerConfig> {
    let b64 = link.trim_start_matches("rr://");
    let compressed = decode_base64_flexible(b64)?;
    let json_bytes = zstd::stream::decode_all(&compressed[..])?;
    let json_str = String::from_utf8(json_bytes)?;
    let config: ServerConfig = serde_json::from_str(&json_str)?;
    Ok(config)
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VmessJson {
    v: String,
    ps: String,
    add: String,
    port: serde_json::Value, // Can be number or string
    id: String,
    aid: Option<serde_json::Value>,
    scy: Option<String>,
    net: Option<String>,
    #[serde(rename = "type")]
    type_field: Option<String>,
    host: Option<String>,
    path: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    fp: Option<String>,
}

fn parse_vmess(link: &str) -> Result<ServerConfig> {
    let base64_str = link.trim_start_matches("vmess://");
    let json_bytes = decode_base64_flexible(base64_str)?;
    let json_str = String::from_utf8(json_bytes).context("Invalid UTF-8 in vmess")?;
    let vmess: VmessJson = serde_json::from_str(&json_str).context("Invalid vmess JSON")?;

    let port = match vmess.port {
        serde_json::Value::Number(n) => n.as_u64().ok_or(anyhow!("Invalid port"))? as u16,
        serde_json::Value::String(s) => s.parse::<u16>().context("Invalid port string")?,
        _ => return Err(anyhow!("Invalid port format")),
    };

    // Safety check for empty remarks
    let remarks = if vmess.ps.is_empty() {
        vmess.add.clone()
    } else {
        vmess.ps
    };

    Ok(ServerConfig {
        id: Some(uuid::Uuid::new_v4().to_string()),
        remarks,
        protocol: Protocol::Vmess,
        address: vmess.add,
        port,
        uuid: Some(vmess.id),
        password: None,
        method: None,
        network: vmess.net.or(Some("tcp".to_string())),
        security: vmess.scy.or(Some("auto".to_string())),
        flow: None,
        fingerprint: vmess.fp,
        sni: vmess.sni,
        host: vmess.host,
        path: vmess.path,
        pbk: None,
        sid: None,
        service_name: None,
        group: None,
        allow_insecure: None, // Default
    })
}

fn parse_vless(link: &str) -> Result<ServerConfig> {
    let url = Url::parse(link).context("Invalid VLESS URL")?;
    let uuid = url.username();
    let address = url.host_str().ok_or(anyhow!("Missing host"))?.to_string();
    let port = url.port().ok_or(anyhow!("Missing port"))?;
    let query_pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
    let remarks = url.fragment().unwrap_or(&address).to_string();

    Ok(ServerConfig {
        id: Some(uuid::Uuid::new_v4().to_string()),
        remarks,
        protocol: Protocol::Vless,
        address,
        port,
        uuid: Some(uuid.to_string()),
        password: None,
        method: None,
        network: query_pairs
            .get("type")
            .map(|s| s.to_string())
            .or(Some("tcp".to_string())),
        security: query_pairs
            .get("security")
            .map(|s| s.to_string())
            .or(Some("none".to_string())),
        flow: query_pairs.get("flow").map(|s| s.to_string()),
        fingerprint: query_pairs.get("fp").map(|s| s.to_string()),
        sni: query_pairs.get("sni").map(|s| s.to_string()),
        host: query_pairs.get("host").map(|s| s.to_string()),
        path: query_pairs.get("path").map(|s| s.to_string()),
        pbk: query_pairs.get("pbk").map(|s| s.to_string()), // Reality public key
        sid: query_pairs.get("sid").map(|s| s.to_string()), // Reality short ID
        service_name: query_pairs.get("serviceName").map(|s| s.to_string()),
        group: None,
        allow_insecure: None,
    })
}

fn parse_trojan(link: &str) -> Result<ServerConfig> {
    let url = Url::parse(link).context("Invalid Trojan URL")?;
    let password = url.username();
    let address = url.host_str().ok_or(anyhow!("Missing host"))?.to_string();
    let port = url.port().ok_or(anyhow!("Missing port"))?;
    let query_pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
    let remarks = url.fragment().unwrap_or(&address).to_string();

    Ok(ServerConfig {
        id: Some(uuid::Uuid::new_v4().to_string()),
        remarks,
        protocol: Protocol::Trojan,
        address,
        port,
        uuid: None,
        password: Some(password.to_string()),

        method: None,
        network: query_pairs
            .get("type")
            .map(|s| s.to_string())
            .or(Some("tcp".to_string())), // usually tcp or grpc/ws
        security: query_pairs
            .get("security")
            .map(|s| s.to_string())
            .or(Some("tls".to_string())),
        flow: None,
        fingerprint: query_pairs.get("fp").map(|s| s.to_string()),
        sni: query_pairs.get("sni").map(|s| s.to_string()),
        host: query_pairs.get("host").map(|s| s.to_string()),
        path: query_pairs.get("path").map(|s| s.to_string()),
        pbk: None,
        sid: None,
        service_name: query_pairs.get("serviceName").map(|s| s.to_string()),
        group: None,
        allow_insecure: query_pairs.get("allowInsecure").map(|s| s == "1"),
    })
}

fn parse_shadowsocks(link: &str) -> Result<ServerConfig> {
    // SS format is diverse. Standard: ss://base64(method:password)@server:port#remarks
    // SIP002: ss://base64(method:password@server:port)#remarks

    let link_content = link.trim_start_matches("ss://");
    let (main_part, remarks): (&str, String) = match link_content.split_once('#') {
        Some((m, r)) => (
            m,
            percent_encoding::percent_decode_str(r)
                .decode_utf8()?
                .to_string(),
        ),
        None => (link_content, "Shadowsocks".to_string()),
    };

    if main_part.contains('@') {
        // user:pass@host:port format (user:pass might be base64)
        let (user_info, host_port): (&str, &str) = main_part
            .split_once('@')
            .ok_or(anyhow!("Invalid SS format"))?;

        // Split with type inference help
        let (method, password): (String, String) = if !user_info.contains(':') {
            // Probably base64 encoded "method:password"
            let decoded = decode_base64_flexible(user_info)?;
            let decoded_str = String::from_utf8(decoded)?;
            decoded_str
                .split_once(':')
                .map(|(m, p)| (m.to_string(), p.to_string()))
                .ok_or(anyhow!("Invalid SS credentials"))?
        } else {
            user_info
                .split_once(':')
                .map(|(m, p)| (m.to_string(), p.to_string()))
                .ok_or(anyhow!("Invalid SS credentials"))?
        };

        let (address, port_str): (&str, &str) = host_port
            .rsplit_once(':')
            .ok_or(anyhow!("Missing SS port"))?;
        let port = port_str.parse::<u16>()?;

        Ok(ServerConfig {
            id: Some(uuid::Uuid::new_v4().to_string()),
            remarks,
            protocol: Protocol::Shadowsocks,
            address: address.to_string(),
            port,
            uuid: None,
            password: Some(password),
            network: None,
            method: None,
            security: Some(method),
            flow: None,
            fingerprint: None,
            sni: None,
            host: None,
            path: None,
            pbk: None,
            sid: None,
            service_name: None,
            group: None,
            allow_insecure: None,
        })
    } else {
        // Everything might be base64? SIP002 logic
        // Try decoding the whole main_part
        let decoded = decode_base64_flexible(main_part)?;
        let decoded_str = String::from_utf8(decoded)?;
        // decoded format: method:password@server:port

        let (user_info, host_port): (&str, &str) = decoded_str
            .rsplit_once('@')
            .ok_or(anyhow!("Invalid SIP002 format"))?;
        let (method, password): (&str, &str) = user_info
            .split_once(':')
            .ok_or(anyhow!("Invalid SIP002 credentials"))?;
        let (address, port_str): (&str, &str) = host_port
            .rsplit_once(':')
            .ok_or(anyhow!("Invalid SIP002 hostport"))?;
        let port = port_str.parse::<u16>()?;

        Ok(ServerConfig {
            id: Some(uuid::Uuid::new_v4().to_string()),
            remarks,
            protocol: Protocol::Shadowsocks,
            address: address.to_string(),
            port,
            uuid: None,
            password: Some(password.to_string()),
            network: None,
            method: None,
            security: Some(method.to_string()),
            flow: None,
            fingerprint: None,
            sni: None,
            host: None,
            path: None,
            pbk: None,
            sid: None,
            service_name: None,
            group: None,
            allow_insecure: None,
        })
    }
}

fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // 1. Try standard
    if let Ok(d) = general_purpose::STANDARD.decode(input) {
        return Ok(d);
    }
    // 2. Try URL_SAFE
    if let Ok(d) = general_purpose::URL_SAFE.decode(input) {
        return Ok(d);
    }
    // 3. Try unpadded
    if let Ok(d) = general_purpose::STANDARD_NO_PAD.decode(input) {
        return Ok(d);
    }
    general_purpose::URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless() {
        let link = "vless://uuid@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=publickey&sid=shortid&type=tcp#Example";
        let config = parse_share_link(link).unwrap();
        assert_eq!(config.protocol, Protocol::Vless);
        assert_eq!(config.address, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.security, Some("reality".to_string()));
        assert_eq!(config.pbk, Some("publickey".to_string()));
        assert_eq!(config.remarks, "Example");
    }

    #[test]
    fn test_parse_vmess() {
        // vmess parsing relies on base64 json. Constructed manually for test.
        let json = r#"{"v":"2","ps":"Remarks","add":"127.0.0.1","port":"10086","id":"uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"example.com","path":"/","tls":"tls"}"#;
        let b64 = general_purpose::STANDARD.encode(json);
        let link = format!("vmess://{}", b64);

        let config = parse_share_link(&link).unwrap();
        assert_eq!(config.protocol, Protocol::Vmess);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.port, 10086);
        assert_eq!(config.network, Some("ws".to_string()));
    }

    #[test]
    fn test_parse_trojan() {
        let link = "trojan://password@example.com:443?security=tls&sni=example.com#Trojan";
        let config = parse_share_link(link).unwrap();
        assert_eq!(config.protocol, Protocol::Trojan);
        assert_eq!(config.address, "example.com");
        assert_eq!(config.password, Some("password".to_string()));
    }

    #[test]
    fn test_parse_ss() {
        // ss://method:pass@host:port#remarks (not base64) - not standard but common
        // SIP002: ss://base64(method:pass@host:port)#remarks

        let raw = "aes-256-gcm:password@1.1.1.1:8388";
        let b64 = general_purpose::URL_SAFE.encode(raw);
        let link = format!("ss://{}#Shadowsocks", b64);

        let config = parse_share_link(&link).unwrap();
        assert_eq!(config.protocol, Protocol::Shadowsocks);
        assert_eq!(config.address, "1.1.1.1");
        assert_eq!(config.port, 8388);
        assert_eq!(config.security, Some("aes-256-gcm".to_string()));
        assert_eq!(config.password, Some("password".to_string()));
    }

    #[test]
    fn test_high_density_link() {
        let config = ServerConfig {
            id: Some("1234".to_string()),
            protocol: Protocol::Vless,
            address: "example.com".to_string(),
            port: 443,
            ..Default::default()
        };
        let link = generate_high_density_link(&config).unwrap();
        assert!(link.starts_with("rr://"));
        let parsed = parse_high_density_link(&link).unwrap();
        assert_eq!(parsed.address, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.protocol, Protocol::Vless);
    }
}
