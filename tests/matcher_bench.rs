use rustray::app::router::matcher::{DomainMatcher, IpMatcher};

#[test]
fn test_ip_priority() {
    let mut matcher = IpMatcher::new();

    // Rule 1: Catch-all (Index 1)
    matcher.insert("0.0.0.0/0".parse().unwrap(), 1, "block".to_string());

    // Rule 2: Specific (Index 100)
    matcher.insert("192.168.1.1/32".parse().unwrap(), 100, "allow".to_string());

    // Traffic: 192.168.1.1
    // Matches both. Should return min index (1).
    let (idx, tag) = matcher.match_ip("192.168.1.1".parse().unwrap()).unwrap();
    assert_eq!(idx, 1);
    assert_eq!(tag, "block");
}

#[test]
fn test_domain_priority() {
    let mut matcher = DomainMatcher::new();

    // Rule 1: suffix com (Index 1)
    matcher.add_domain_rule("domain:com", 1);

    // Rule 2: suffix google.com (Index 100)
    matcher.add_domain_rule("domain:google.com", 100);

    // Traffic: google.com
    // Trie has entries for "moc" and "moc.elgoog".
    // "moc.elgoog" node has index 100.
    // "moc" node has index 1.
    // Logic should check both and return min(1, 100) = 1.

    let idx = matcher.match_domain("google.com").unwrap();
    assert_eq!(
        idx, 1,
        "Should match 'com' (Index 1) over 'google.com' (Index 100)"
    );
}

#[test]
fn test_domain_priority_reverse() {
    let mut matcher = DomainMatcher::new();

    // Rule 1: suffix google.com (Index 1)
    matcher.add_domain_rule("domain:google.com", 1);

    // Rule 2: suffix com (Index 100)
    matcher.add_domain_rule("domain:com", 100);

    // Traffic: google.com
    // Should match Rule 1 (Index 1).
    let idx = matcher.match_domain("google.com").unwrap();
    assert_eq!(idx, 1);

    // Traffic: apple.com
    // Should match Rule 2 (Index 100).
    let idx = matcher.match_domain("apple.com").unwrap();
    assert_eq!(idx, 100);
}
