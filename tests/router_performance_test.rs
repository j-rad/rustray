// tests/router_performance_test.rs
//! Router Performance Tests
//!
//! This test suite validates routing performance:
//! - GeoIP matching with 10,000+ rules
//! - Iranian IP fast-path performance
//! - Domain matching performance
//! - Target: <1ms decision time

use rustray::app::router::geo_loader::GeoManager;
use std::net::IpAddr;
use std::time::Instant;

/// Test Iranian IP fast-path performance
#[test]
fn test_iranian_ip_fast_path_performance() {
    let manager = GeoManager::new();

    // Generate test IPs from Iranian ranges
    let test_ips: Vec<IpAddr> = vec![
        "2.176.1.1".parse().unwrap(),   // MCI
        "2.144.1.1".parse().unwrap(),   // Shatel
        "5.52.1.1".parse().unwrap(),    // Irancell
        "5.160.1.1".parse().unwrap(),   // ITC
        "37.32.1.1".parse().unwrap(),   // Various
        "46.100.1.1".parse().unwrap(),  // Shatel
        "78.38.1.1".parse().unwrap(),   // Shatel
        "151.232.1.1".parse().unwrap(), // MCI
        "217.218.1.1".parse().unwrap(), // TCI
        "188.208.1.1".parse().unwrap(), // TCI
    ];

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for ip in &test_ips {
            let _ = manager.is_iranian_ip(*ip);
        }
    }

    let elapsed = start.elapsed();
    let total_ops = iterations * test_ips.len();
    let avg_ns = elapsed.as_nanos() / total_ops as u128;

    println!(
        "Iranian IP fast-path: {} ops in {:?} ({} ns/op, {:.3} µs/op)",
        total_ops,
        elapsed,
        avg_ns,
        avg_ns as f64 / 1000.0
    );

    // Should be < 1ms average
    assert!(
        avg_ns < 1_000_000,
        "Iranian IP lookup too slow: {} ns/op (target: <1ms)",
        avg_ns
    );
}

/// Test Iranian domain fast-path performance
#[test]
fn test_iranian_domain_fast_path_performance() {
    let manager = GeoManager::new();

    let test_domains = vec![
        "example.ir",
        "www.shatel.ir",
        "api.mci.ir",
        "portal.irancell.ir",
        "service.mobinnet.ir",
        "digikala.com", // Non-Iranian
        "shaparak.ir",
        "snapp.ir",
        "banking.ir",
        "google.com", // Non-Iranian
    ];

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for domain in &test_domains {
            let _ = manager.is_iranian_domain(domain);
        }
    }

    let elapsed = start.elapsed();
    let total_ops = iterations * test_domains.len();
    let avg_ns = elapsed.as_nanos() / total_ops as u128;

    println!(
        "Iranian domain fast-path: {} ops in {:?} ({} ns/op, {:.3} µs/op)",
        total_ops,
        elapsed,
        avg_ns,
        avg_ns as f64 / 1000.0
    );

    // Should be < 1ms average
    assert!(
        avg_ns < 1_000_000,
        "Iranian domain lookup too slow: {} ns/op (target: <1ms)",
        avg_ns
    );
}

/// Test GeoIP match performance with multiple countries
#[test]
fn test_geoip_match_performance() {
    let manager = GeoManager::new();

    // Mix of IPs
    let test_cases: Vec<(IpAddr, &str)> = vec![
        ("2.176.1.1".parse().unwrap(), "ir"),
        ("8.8.8.8".parse().unwrap(), "us"),
        ("1.1.1.1".parse().unwrap(), "au"),
        ("151.232.1.1".parse().unwrap(), "ir"),
        ("223.5.5.5".parse().unwrap(), "cn"),
    ];

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for (ip, country) in &test_cases {
            let _ = manager.match_geoip(*ip, country);
        }
    }

    let elapsed = start.elapsed();
    let total_ops = iterations * test_cases.len();
    let avg_ns = elapsed.as_nanos() / total_ops as u128;

    println!(
        "GeoIP match: {} ops in {:?} ({} ns/op, {:.3} µs/op)",
        total_ops,
        elapsed,
        avg_ns,
        avg_ns as f64 / 1000.0
    );

    // Should be < 1ms average
    assert!(
        avg_ns < 1_000_000,
        "GeoIP match too slow: {} ns/op (target: <1ms)",
        avg_ns
    );
}

/// Test GeoSite match performance
#[test]
fn test_geosite_match_performance() {
    let manager = GeoManager::new();

    let test_cases: Vec<(&str, &str)> = vec![
        ("example.ir", "ir"),
        ("google.com", "google"),
        ("facebook.com", "facebook"),
        ("digikala.ir", "ir"),
        ("youtube.com", "youtube"),
        ("snapp.ir", "ir"),
        ("twitter.com", "twitter"),
        ("shaparak.ir", "ir"),
    ];

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for (domain, category) in &test_cases {
            let _ = manager.match_geosite(domain, category);
        }
    }

    let elapsed = start.elapsed();
    let total_ops = iterations * test_cases.len();
    let avg_ns = elapsed.as_nanos() / total_ops as u128;

    println!(
        "GeoSite match: {} ops in {:?} ({} ns/op, {:.3} µs/op)",
        total_ops,
        elapsed,
        avg_ns,
        avg_ns as f64 / 1000.0
    );

    // Should be < 1ms average
    assert!(
        avg_ns < 1_000_000,
        "GeoSite match too slow: {} ns/op (target: <1ms)",
        avg_ns
    );
}

/// Test get_country performance
#[test]
fn test_get_country_performance() {
    let manager = GeoManager::new();

    let test_ips: Vec<IpAddr> = vec![
        "2.176.1.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        "151.232.1.1".parse().unwrap(),
        "1.1.1.1".parse().unwrap(),
        "46.100.1.1".parse().unwrap(),
    ];

    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for ip in &test_ips {
            let _ = manager.get_country(*ip);
        }
    }

    let elapsed = start.elapsed();
    let total_ops = iterations * test_ips.len();
    let avg_ns = elapsed.as_nanos() / total_ops as u128;

    println!(
        "Get country: {} ops in {:?} ({} ns/op, {:.3} µs/op)",
        total_ops,
        elapsed,
        avg_ns,
        avg_ns as f64 / 1000.0
    );

    // Should be < 1ms average
    assert!(
        avg_ns < 1_000_000,
        "Get country too slow: {} ns/op (target: <1ms)",
        avg_ns
    );
}

/// Test stats collection overhead
#[test]
fn test_stats_overhead() {
    let manager = GeoManager::new();

    let ip: IpAddr = "2.176.1.1".parse().unwrap();

    // Warm up
    for _ in 0..1000 {
        let _ = manager.is_iranian_ip(ip);
    }

    let iterations = 100_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = manager.is_iranian_ip(ip);
    }

    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iterations as u128;

    println!(
        "With stats: {} ops in {:?} ({} ns/op)",
        iterations, elapsed, avg_ns
    );

    let (lookups, _, iranian_hits, _, _) = manager.get_stats();
    println!(
        "Stats after test: lookups={}, iranian_hits={}",
        lookups, iranian_hits
    );

    // Stats collection should add minimal overhead
    assert!(avg_ns < 10_000, "Stats overhead too high: {} ns/op", avg_ns);
}

/// Test mixed workload (realistic scenario)
#[test]
fn test_mixed_workload_performance() {
    let manager = GeoManager::new();

    let iterations = 5_000;
    let mut total_duration_ns: u128 = 0;
    let mut max_duration_ns: u128 = 0;
    let mut operations = 0;

    // Simulate realistic routing decisions
    for i in 0..iterations {
        // Alternate between different operation types
        match i % 5 {
            0 => {
                // Iranian IP check
                let ip: IpAddr = "2.176.1.1".parse().unwrap();
                let start = Instant::now();
                let _ = manager.is_iranian_ip(ip);
                let d = start.elapsed().as_nanos();
                total_duration_ns += d;
                max_duration_ns = max_duration_ns.max(d);
                operations += 1;
            }
            1 => {
                // Iranian domain check
                let start = Instant::now();
                let _ = manager.is_iranian_domain("example.ir");
                let d = start.elapsed().as_nanos();
                total_duration_ns += d;
                max_duration_ns = max_duration_ns.max(d);
                operations += 1;
            }
            2 => {
                // GeoIP match
                let ip: IpAddr = "8.8.8.8".parse().unwrap();
                let start = Instant::now();
                let _ = manager.match_geoip(ip, "us");
                let d = start.elapsed().as_nanos();
                total_duration_ns += d;
                max_duration_ns = max_duration_ns.max(d);
                operations += 1;
            }
            3 => {
                // GeoSite match
                let start = Instant::now();
                let _ = manager.match_geosite("google.com", "google");
                let d = start.elapsed().as_nanos();
                total_duration_ns += d;
                max_duration_ns = max_duration_ns.max(d);
                operations += 1;
            }
            _ => {
                // Get country
                let ip: IpAddr = "151.232.1.1".parse().unwrap();
                let start = Instant::now();
                let _ = manager.get_country(ip);
                let d = start.elapsed().as_nanos();
                total_duration_ns += d;
                max_duration_ns = max_duration_ns.max(d);
                operations += 1;
            }
        }
    }

    let avg_ns = total_duration_ns / operations as u128;

    println!(
        "Mixed workload: {} ops, avg={} ns, max={} ns ({:.3} µs max)",
        operations,
        avg_ns,
        max_duration_ns,
        max_duration_ns as f64 / 1000.0
    );

    // All operations should complete < 1ms
    assert!(
        max_duration_ns < 1_000_000,
        "Max operation time exceeded 1ms: {} ns",
        max_duration_ns
    );
}

/// Test correctness of Iranian IP detection
#[test]
fn test_iranian_ip_correctness() {
    let manager = GeoManager::new();

    // Known Iranian IPs
    let iranian_ips = vec![
        ("2.176.1.1", true),   // MCI
        ("2.144.1.1", true),   // Shatel
        ("5.52.1.1", true),    // Irancell
        ("151.232.1.1", true), // MCI
        ("217.218.1.1", true), // TCI
        ("46.100.1.1", true),  // Shatel
        // Non-Iranian IPs
        ("8.8.8.8", false),   // Google DNS
        ("1.1.1.1", false),   // Cloudflare
        ("223.5.5.5", false), // Alibaba
        ("9.9.9.9", false),   // Quad9
    ];

    for (ip_str, expected) in iranian_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let result = manager.is_iranian_ip(ip);
        assert_eq!(
            result,
            expected,
            "IP {} should be {} Iranian",
            ip_str,
            if expected { "" } else { "NOT" }
        );
    }
}

/// Test correctness of Iranian domain detection
#[test]
fn test_iranian_domain_correctness() {
    let manager = GeoManager::new();

    let test_cases = vec![
        ("example.ir", true),
        ("www.shatel.ir", true),
        ("api.mci.ir", true),
        ("ir", true),
        ("portal.irancell.ir", true),
        // Non-Iranian domains
        ("google.com", false),
        ("example.com", false),
        ("amazon.com", false),
        ("facebook.com", false),
    ];

    for (domain, expected) in test_cases {
        let result = manager.is_iranian_domain(domain);
        assert_eq!(
            result,
            expected,
            "Domain {} should be {} Iranian",
            domain,
            if expected { "" } else { "NOT" }
        );
    }
}

/// Test GeoManager statistics accuracy
#[test]
fn test_stats_accuracy() {
    let manager = GeoManager::new();

    // Perform known number of operations
    let ip: IpAddr = "2.176.1.1".parse().unwrap();
    let non_ir_ip: IpAddr = "8.8.8.8".parse().unwrap();

    for _ in 0..100 {
        manager.is_iranian_ip(ip);
    }

    for _ in 0..50 {
        manager.is_iranian_ip(non_ir_ip);
    }

    let (lookups, _, iranian_hits, _, _) = manager.get_stats();

    assert_eq!(lookups, 150, "Expected 150 lookups, got {}", lookups);
    assert_eq!(
        iranian_hits, 100,
        "Expected 100 Iranian hits, got {}",
        iranian_hits
    );
}
