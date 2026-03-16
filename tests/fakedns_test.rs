use rustray::app::dns::fakedns::FakeDns;
use rustray::config::FakeDnsConfig;
use std::net::IpAddr;

#[test]
fn test_fakedns_lru_eviction() {
    let config = FakeDnsConfig {
        ip_pool: "198.18.0.0/16".to_string(),
        pool_size: 65536,
        max_entries: 10, // Small for testing
        persist_path: None,
        save_interval_secs: 300,
    };

    let fakedns = FakeDns::new(config).unwrap();

    // Insert 15 domains
    for i in 0..15 {
        fakedns.get_fake_ip(&format!("domain{}.com", i));
    }

    // Check stats: should have max 10 entries
    let (current, max) = fakedns.stats();
    assert_eq!(current, 10);
    assert_eq!(max, 10);

    // First 5 should be evicted
    let ip0: IpAddr = "198.18.0.0".parse().unwrap();
    assert!(fakedns.get_domain_from_ip(ip0).is_none());

    // Last entry should still exist
    let ip14: IpAddr = "198.18.0.14".parse().unwrap();
    assert_eq!(
        fakedns.get_domain_from_ip(ip14),
        Some("domain14.com".to_string())
    );
}

#[test]
fn test_fakedns_persistence() {
    let temp_file = "/tmp/fakedns_test.json";

    let config = FakeDnsConfig {
        ip_pool: "198.18.0.0/16".to_string(),
        pool_size: 65536,
        max_entries: 100,
        persist_path: Some(temp_file.to_string()),
        save_interval_secs: 300,
    };

    // Create and populate
    let fakedns1 = FakeDns::new(config.clone()).unwrap();
    let ip1 = fakedns1.get_fake_ip("test.com");
    let ip2 = fakedns1.get_fake_ip("example.com");
    fakedns1.save_state(temp_file).unwrap();

    // Load in new instance
    let fakedns2 = FakeDns::new(config).unwrap();
    assert_eq!(
        fakedns2.get_domain_from_ip(IpAddr::V4(ip1)),
        Some("test.com".to_string())
    );
    assert_eq!(
        fakedns2.get_domain_from_ip(IpAddr::V4(ip2)),
        Some("example.com".to_string())
    );

    // Cleanup
    std::fs::remove_file(temp_file).ok();
}

#[test]
fn test_fakedns_is_fake_ip() {
    let config = FakeDnsConfig::default();
    let fakedns = FakeDns::new(config).unwrap();

    let fake_ip: IpAddr = "198.18.0.1".parse().unwrap();
    let real_ip: IpAddr = "8.8.8.8".parse().unwrap();

    assert!(fakedns.is_fake_ip(fake_ip));
    assert!(!fakedns.is_fake_ip(real_ip));
}

#[test]
fn test_fakedns_ip_allocation() {
    let config = FakeDnsConfig::default();
    let fakedns = FakeDns::new(config).unwrap();

    let ip1 = fakedns.get_fake_ip("google.com");
    let ip2 = fakedns.get_fake_ip("google.com"); // Same domain
    let ip3 = fakedns.get_fake_ip("example.com"); // Different domain

    // Same domain should return same IP
    assert_eq!(ip1, ip2);

    // Different domain should get different IP
    assert_ne!(ip1, ip3);

    // Reverse lookup should work
    assert_eq!(
        fakedns.get_domain_from_ip(IpAddr::V4(ip1)),
        Some("google.com".to_string())
    );
}
