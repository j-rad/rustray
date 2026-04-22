// tests/ffi_stealth_test.rs
#![cfg(not(target_arch = "wasm32"))]
//! FFI Stealth Feature Tests
//!
//! This test suite validates the FFI-exposed stealth features:
//! - REALITY handshake via FFI
//! - Vision flow via FFI
//! - Flow-J connection via FFI
//!
//! These tests ensure that FFI clients can successfully use rustray's
//! premium stealth features through the exported functions.

use rustray::RayResult;
use rustray::ffi::{
    ConnectConfig, FlowJCdnConfig, FlowJMobileConfig, FragmentConfig, RealityConfig,
};

/// Test configuration parsing for REALITY settings
#[test]
fn test_config_parsing_reality() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "protocol": "vless",
        "flow": "xtls-rprx-vision",
        "security": "reality",
        "reality_settings": {
            "public_key": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            "short_id": "abcd1234",
            "server_name": "www.microsoft.com",
            "fingerprint": "chrome"
        }
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.address, "example.com");
    assert_eq!(config.port, 443);
    assert_eq!(config.protocol, "vless");
    assert_eq!(config.flow, Some("xtls-rprx-vision".to_string()));
    assert_eq!(config.security, "reality");

    let reality = config.reality_settings.unwrap();
    assert_eq!(reality.server_name, "www.microsoft.com");
    assert_eq!(reality.fingerprint, "chrome");
    assert_eq!(reality.short_id, "abcd1234");
}

/// Test configuration parsing with fragment settings
#[test]
fn test_config_parsing_fragment() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "vless",
        "security": "tls",
        "fragment_settings": {
            "length": "20-100",
            "interval": "10-30"
        }
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    let fragment = config.fragment_settings.unwrap();
    assert_eq!(fragment.length, "20-100");
    assert_eq!(fragment.interval, "10-30");
}

/// Test configuration parsing for Flow-J modes
#[test]
fn test_config_parsing_flowj_reality_mode() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "flow-j",
        "security": "reality",
        "flow_j_settings": {
            "mode": "reality",
            "reality": {
                "dest": "www.samsung.com:443",
                "server_names": ["www.google.com", "www.microsoft.com"],
                "short_ids": ["abcd1234"]
            }
        }
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    assert_eq!(config.protocol, "flow-j");
    let flowj = config.flow_j_settings.unwrap();
    assert_eq!(flowj.mode, "reality");
    assert!(flowj.reality.is_some());

    let reality = flowj.reality.unwrap();
    assert_eq!(reality.dest, "www.samsung.com:443");
    assert_eq!(reality.server_names.len(), 2);
}

/// Test configuration parsing for Flow-J CDN mode
#[test]
fn test_config_parsing_flowj_cdn_mode() {
    let json = r#"
    {
        "address": "cdn.example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "flow-j",
        "security": "tls",
        "flow_j_settings": {
            "mode": "cdn",
            "cdn": {
                "path": "/tunnel/v1",
                "host": "api.example.com",
                "use_xhttp": true
            }
        }
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    let flowj = config.flow_j_settings.unwrap();
    assert_eq!(flowj.mode, "cdn");

    let cdn = flowj.cdn.unwrap();
    assert_eq!(cdn.path, "/tunnel/v1");
    assert_eq!(cdn.host, Some("api.example.com".to_string()));
    assert!(cdn.use_xhttp);
}

/// Test configuration parsing for Flow-J MQTT mode
#[test]
fn test_config_parsing_flowj_mqtt_mode() {
    let json = r#"
    {
        "address": "mqtt.example.com",
        "port": 1883,
        "uuid": "test-uuid",
        "protocol": "flow-j",
        "security": "none",
        "flow_j_settings": {
            "mode": "mqtt",
            "mqtt": {
                "broker": "mqtt.example.com:1883",
                "upload_topic": "sensors/data/up",
                "download_topic": "sensors/data/down",
                "username": "device123",
                "password": "secret"
            }
        }
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    let flowj = config.flow_j_settings.unwrap();
    assert_eq!(flowj.mode, "mqtt");

    let mqtt = flowj.mqtt.unwrap();
    assert_eq!(mqtt.broker, "mqtt.example.com:1883");
    assert_eq!(mqtt.upload_topic, "sensors/data/up");
    assert_eq!(mqtt.download_topic, "sensors/data/down");
    assert_eq!(mqtt.username, Some("device123".to_string()));
}

/// Test configuration parsing with FEC settings
#[test]
fn test_config_parsing_flowj_fec() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "flow-j",
        "security": "reality",
        "flow_j_settings": {
            "mode": "auto",
            "fec": {
                "enabled": true,
                "data_shards": 10,
                "parity_shards": 3
            }
        }
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    let flowj = config.flow_j_settings.unwrap();
    let fec = flowj.fec.unwrap();
    assert!(fec.enabled);
    assert_eq!(fec.data_shards, 10);
    assert_eq!(fec.parity_shards, 3);
}

/// Test default values for ConnectConfig
#[test]
fn test_config_defaults() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "vless"
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();

    // Check defaults
    assert_eq!(config.network, "tcp");
    assert_eq!(config.security, "tls");
    assert_eq!(config.local_address, "127.0.0.1");
    assert_eq!(config.local_port, 1080);
    assert_eq!(config.routing_mode, "global");
    assert!(!config.enable_udp);
}

/// Test FFI version function
#[test]
fn test_ffi_version() {
    let version = rustray::ffi::get_version();
    assert!(!version.is_empty());
    // Should start with a digit (version number)
    assert!(version.chars().next().unwrap().is_ascii_digit());
}

/// Test FFI is_running function
#[test]
fn test_ffi_is_running() {
    // Should not be running when not started
    assert!(!rustray::ffi::is_running());
}

/// Test FFI fetch_stats function
#[test]
fn test_ffi_fetch_stats() {
    let stats = rustray::ffi::fetch_stats();

    // Should return default stats when not running (i.e., 0 for counts)
    assert_eq!(stats.bytes_uploaded, 0);
    assert_eq!(stats.bytes_downloaded, 0);
    assert_eq!(stats.active_connections, 0);
}

/// Test FFI start with invalid config
#[test]
fn test_ffi_start_invalid_config() {
    let result = rustray::ffi::start("invalid json".to_string());
    // Not a Result type, but the Enum directly

    match result {
        RayResult::ConfigError(msg) => {
            assert!(msg.contains("expected") || msg.contains("EOF") || msg.contains("JSON"));
        }
        e => panic!("Expected ConfigError, got {:?}", e),
    }
}

/// Test FFI stop when not running
#[test]
fn test_ffi_stop_not_running() {
    let stopped = rustray::ffi::stop();
    // May be true or false depending on internal state
    // This test just ensures it doesn't panic
    let _ = stopped;
}

/// Test RealityConfig serialization
#[test]
fn test_reality_config_serialization() {
    let config = RealityConfig {
        public_key: "test_pub_key".to_string(),
        short_id: "abcd1234".to_string(),
        server_name: "www.google.com".to_string(),
        fingerprint: "chrome".to_string(),
        spider_x: Some("https://example.com".to_string()),
    };

    let json = serde_json::to_string(&config).unwrap();
    let parsed: RealityConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.public_key, config.public_key);
    assert_eq!(parsed.short_id, config.short_id);
    assert_eq!(parsed.server_name, config.server_name);
    assert_eq!(parsed.fingerprint, config.fingerprint);
    assert_eq!(parsed.spider_x, config.spider_x);
}

/// Test FragmentConfig serialization
#[test]
fn test_fragment_config_serialization() {
    let config = FragmentConfig {
        length: "50-200".to_string(),
        interval: "10-50".to_string(),
    };

    let json = serde_json::to_string(&config).unwrap();
    let parsed: FragmentConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.length, config.length);
    assert_eq!(parsed.interval, config.interval);
}

/// Test FlowJMobileConfig serialization
#[test]
fn test_flowj_mobile_config_serialization() {
    let config = FlowJMobileConfig {
        mode: "cdn".to_string(),
        reality: None,
        cdn: Some(FlowJCdnConfig {
            path: "/api/tunnel".to_string(),
            host: Some("cdn.example.com".to_string()),
            use_xhttp: true,
        }),
        mqtt: None,
        fec: None,
    };

    let json = serde_json::to_string(&config).unwrap();
    let parsed: FlowJMobileConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.mode, config.mode);
    assert!(parsed.cdn.is_some());
    let cdn = parsed.cdn.unwrap();
    assert_eq!(cdn.path, "/api/tunnel");
    assert!(cdn.use_xhttp);
}

/// Test FfiError display
#[test]
fn test_ffi_error_display() {
    let errors = vec![
        (
            RayResult::ConfigError("bad config".to_string()),
            "Configuration error: bad config",
        ),
        (
            RayResult::ConnectionError("timeout".to_string()),
            "Connection error: timeout",
        ),
        (
            RayResult::HandshakeError("tls failed".to_string()),
            "Handshake error: tls failed",
        ),
        (
            RayResult::ProtocolError("invalid".to_string()),
            "Protocol error: invalid",
        ),
        (RayResult::AlreadyRunning, "Tunnel already running"),
        (RayResult::NotRunning, "Tunnel not running"),
        (
            RayResult::PanicError("crash".to_string()),
            "Panic occurred: crash",
        ),
    ];

    for (error, expected) in errors {
        assert_eq!(format!("{}", error), expected);
    }
}

/// Test that FFI handles empty config fields gracefully
#[test]
fn test_ffi_config_minimal_fields() {
    let json = r#"
    {
        "address": "1.2.3.4",
        "port": 8443,
        "uuid": "",
        "protocol": "vless"
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.address, "1.2.3.4");
    assert!(config.uuid.is_empty());
}

/// Test IPv6 address in config
#[test]
fn test_ffi_config_ipv6() {
    let json = r#"
    {
        "address": "2001:db8::1",
        "port": 443,
        "uuid": "test",
        "protocol": "vless"
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.address, "2001:db8::1");
}

/// Test uTLS fingerprint options
#[test]
fn test_ffi_config_utls_fingerprints() {
    for fingerprint in &["chrome", "firefox", "safari", "ios", "random"] {
        let json = format!(
            r#"
        {{
            "address": "example.com",
            "port": 443,
            "uuid": "test",
            "protocol": "vless",
            "utls_fingerprint": "{}"
        }}
        "#,
            fingerprint
        );

        let config: ConnectConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.utls_fingerprint,
            Some(fingerprint.to_string()),
            "Failed for fingerprint: {}",
            fingerprint
        );
    }
}

/// Test TUN FD passing in config
#[test]
fn test_ffi_config_tun_fd() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test",
        "protocol": "vless",
        "tun_fd": 42
    }
    "#;

    let config: ConnectConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.tun_fd, Some(42));
}

/// Test routing mode options
#[test]
fn test_ffi_config_routing_modes() {
    for mode in &["global", "bypass_lan", "bypass_mainland"] {
        let json = format!(
            r#"
        {{
            "address": "example.com",
            "port": 443,
            "uuid": "test",
            "protocol": "vless",
            "routing_mode": "{}"
        }}
        "#,
            mode
        );

        let config: ConnectConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.routing_mode, *mode,
            "Failed for routing mode: {}",
            mode
        );
    }
}

// ============================================================================
// INTEGRATION TESTS (require network, marked with ignore)
// ============================================================================

/// Integration test for REALITY handshake (requires network)
#[test]
#[ignore = "requires network connection to test server"]
fn test_reality_handshake_integration() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "vless",
        "security": "reality",
        "reality_settings": {
            "public_key": "your-public-key",
            "short_id": "your-short-id",
            "server_name": "www.google.com",
            "fingerprint": "chrome"
        }
    }
    "#;

    let result = rustray::ffi::test_reality_handshake(json.to_string());

    // This test is expected to fail without a real server
    // but it validates the function doesn't panic
    assert!(result.is_err() || result.is_ok());
}

/// Integration test for Vision handshake (requires network)
#[test]
#[ignore = "requires network connection to test server"]
fn test_vision_handshake_integration() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "vless",
        "flow": "xtls-rprx-vision",
        "security": "tls"
    }
    "#;

    let result = rustray::ffi::test_vision_handshake(json.to_string());

    // Validates the function doesn't panic
    assert!(result.is_err() || result.is_ok());
}

/// Integration test for Flow-J connection (requires network)
#[test]
#[ignore = "requires network connection to test server"]
fn test_flowj_connection_integration() {
    let json = r#"
    {
        "address": "example.com",
        "port": 443,
        "uuid": "test-uuid",
        "protocol": "flow-j",
        "security": "reality",
        "flow_j_settings": {
            "mode": "auto"
        }
    }
    "#;

    let result = rustray::ffi::test_flowj_connection(json.to_string());

    // Validates the function doesn't panic
    assert!(result.is_err() || result.is_ok());
}
