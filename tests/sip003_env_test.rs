// tests/sip003_env_test.rs
//! Integration tests for SIP003 plugin interoperability.

use rustray::plugin::sip003::Sip003Config;

#[test]
fn test_sip003_parse_options() {
    let config = Sip003Config::new(
        "10.0.0.1".to_string(),
        443,
        "127.0.0.1".to_string(),
        1080,
        "obfs=tls;obfs-host=www.example.com;mux=4",
    );

    assert_eq!(config.option("obfs"), Some("tls"));
    assert_eq!(config.option("obfs-host"), Some("www.example.com"));
    assert_eq!(config.option("mux"), Some("4"));
    assert_eq!(config.option("nonexistent"), None);
}

#[test]
fn test_sip003_boolean_flags() {
    let config = Sip003Config::new(
        "10.0.0.1".to_string(),
        443,
        "127.0.0.1".to_string(),
        1080,
        "fast-open;no-delay;obfs=http",
    );

    assert!(config.has_flag("fast-open"));
    assert!(config.has_flag("no-delay"));
    assert!(config.has_flag("obfs"));
    assert!(!config.has_flag("missing"));
}

#[test]
fn test_sip003_empty_options() {
    let config = Sip003Config::new(
        "10.0.0.1".to_string(),
        443,
        "127.0.0.1".to_string(),
        1080,
        "",
    );

    assert!(config.plugin_options.is_empty());
}

#[test]
fn test_sip003_addr_parsing() {
    let config = Sip003Config::new(
        "192.168.1.1".to_string(),
        8443,
        "127.0.0.1".to_string(),
        1080,
        "",
    );

    let remote = config.remote_addr().unwrap();
    assert_eq!(remote.ip().to_string(), "192.168.1.1");
    assert_eq!(remote.port(), 8443);

    let local = config.local_addr().unwrap();
    assert_eq!(local.ip().to_string(), "127.0.0.1");
    assert_eq!(local.port(), 1080);
}

#[test]
fn test_sip003_env_vars_map() {
    let config = Sip003Config::new(
        "10.0.0.1".to_string(),
        443,
        "127.0.0.1".to_string(),
        1080,
        "obfs=tls;fast-open",
    );

    let env_vars = config.build_env_vars();
    assert_eq!(env_vars.get("SS_REMOTE_HOST").unwrap(), "10.0.0.1");
    assert_eq!(env_vars.get("SS_REMOTE_PORT").unwrap(), "443");
    assert_eq!(env_vars.get("SS_LOCAL_HOST").unwrap(), "127.0.0.1");
    assert_eq!(env_vars.get("SS_LOCAL_PORT").unwrap(), "1080");
    
    let options = env_vars.get("SS_PLUGIN_OPTIONS").unwrap();
    // Options may be in any order due to HashMap iteration
    assert!(options.contains("obfs=tls") || options.contains("fast-open"));
}
