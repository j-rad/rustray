// src/security/pii_filter.rs
//! PII (Personally Identifiable Information) filtering for logs
//!
//! Ensures sensitive data is not leaked in production logs.

use regex::Regex;
use std::sync::OnceLock;

static UUID_REGEX: OnceLock<Regex> = OnceLock::new();
#[cfg(not(debug_assertions))]
static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
#[cfg(not(debug_assertions))]
static IPV6_REGEX: OnceLock<Regex> = OnceLock::new();

/// Sanitize a log message by removing PII
pub fn sanitize_log_message(msg: &str) -> String {
    let mut sanitized = msg.to_string();

    // Remove UUIDs
    let uuid_re = UUID_REGEX.get_or_init(|| {
        Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap()
    });
    sanitized = uuid_re
        .replace_all(&sanitized, "[UUID_REDACTED]")
        .to_string();

    // Remove IPv4 addresses (except localhost and private ranges in debug mode)
    #[cfg(not(debug_assertions))]
    {
        let ipv4_re =
            IPV4_REGEX.get_or_init(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap());
        sanitized = ipv4_re.replace_all(&sanitized, "[IP_REDACTED]").to_string();
    }

    // Remove IPv6 addresses
    #[cfg(not(debug_assertions))]
    {
        let ipv6_re = IPV6_REGEX
            .get_or_init(|| Regex::new(r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}").unwrap());
        sanitized = ipv6_re
            .replace_all(&sanitized, "[IPV6_REDACTED]")
            .to_string();
    }

    // Remove SNI (Server Name Indication) - common domain patterns
    // Only in production to avoid breaking debug logs
    #[cfg(not(debug_assertions))]
    {
        // Redact anything that looks like a domain after "sni=" or "host="
        let sni_re = Regex::new(r"(sni|host|server)=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})").unwrap();
        sanitized = sni_re
            .replace_all(&sanitized, "$1=[DOMAIN_REDACTED]")
            .to_string();
    }

    sanitized
}

/// Macro to log with PII filtering in production
#[macro_export]
macro_rules! safe_info {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            tracing::info!($($arg)*);
        }
        #[cfg(not(debug_assertions))]
        {
            let msg = format!($($arg)*);
            let sanitized = $crate::security::pii_filter::sanitize_log_message(&msg);
            tracing::info!("{}", sanitized);
        }
    };
}

#[macro_export]
macro_rules! safe_debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            tracing::debug!($($arg)*);
        }
        #[cfg(not(debug_assertions))]
        {
            let msg = format!($($arg)*);
            let sanitized = $crate::security::pii_filter::sanitize_log_message(&msg);
            tracing::debug!("{}", sanitized);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_redaction() {
        let msg = "User 550e8400-e29b-41d4-a716-446655440000 connected";
        let sanitized = sanitize_log_message(msg);
        assert!(sanitized.contains("[UUID_REDACTED]"));
        assert!(!sanitized.contains("550e8400"));
    }

    #[test]
    fn test_ip_redaction() {
        let msg = "Connection from 192.168.1.100";
        let sanitized = sanitize_log_message(msg);

        #[cfg(not(debug_assertions))]
        {
            assert!(sanitized.contains("[IP_REDACTED]"));
            assert!(!sanitized.contains("192.168.1.100"));
        }

        #[cfg(debug_assertions)]
        {
            // In debug mode, IPs are preserved
            assert!(sanitized.contains("192.168.1.100"));
        }
    }

    #[test]
    fn test_sni_redaction() {
        let msg = "Connecting to sni=example.com";
        let sanitized = sanitize_log_message(msg);

        #[cfg(not(debug_assertions))]
        {
            assert!(sanitized.contains("[DOMAIN_REDACTED]"));
            assert!(!sanitized.contains("example.com"));
        }

        #[cfg(debug_assertions)]
        {
            assert!(sanitized.contains("example.com"));
        }
    }
}
