//! TLS connection forensics collector
//!
//! Tracks active TLS connections with SNI, fingerprints, and handshake metrics

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct TlsConnectionInfo {
    pub id: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub sni: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub utls_fingerprint: String,
    pub state: ConnectionState,
    pub handshake_duration_ms: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub established_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshaking,
    Established,
    Closing,
    Closed,
}

pub struct TlsForensicsCollector {
    connections: Arc<RwLock<HashMap<String, TlsConnectionInfo>>>,
}

impl TlsForensicsCollector {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new TLS connection
    pub fn register_connection(
        &self,
        id: String,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
        sni: String,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let conn = TlsConnectionInfo {
            id: id.clone(),
            local_port,
            remote_host,
            remote_port,
            sni,
            tls_version: "Unknown".to_string(),
            cipher_suite: "Unknown".to_string(),
            utls_fingerprint: "".to_string(),
            state: ConnectionState::Handshaking,
            handshake_duration_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
            established_at: now,
        };

        let mut connections = self.connections.write().unwrap();
        connections.insert(id, conn);
    }

    /// Update connection after handshake completion
    pub fn update_handshake(
        &self,
        id: &str,
        tls_version: String,
        cipher_suite: String,
        utls_fingerprint: String,
        handshake_duration_ms: u32,
    ) {
        let mut connections = self.connections.write().unwrap();

        if let Some(conn) = connections.get_mut(id) {
            conn.tls_version = tls_version;
            conn.cipher_suite = cipher_suite;
            conn.utls_fingerprint = utls_fingerprint;
            conn.handshake_duration_ms = handshake_duration_ms;
            conn.state = ConnectionState::Established;
        }
    }

    /// Update connection traffic stats
    pub fn update_traffic(&self, id: &str, bytes_sent: u64, bytes_received: u64) {
        let mut connections = self.connections.write().unwrap();

        if let Some(conn) = connections.get_mut(id) {
            conn.bytes_sent = bytes_sent;
            conn.bytes_received = bytes_received;
        }
    }

    /// Mark connection as closing
    pub fn mark_closing(&self, id: &str) {
        let mut connections = self.connections.write().unwrap();

        if let Some(conn) = connections.get_mut(id) {
            conn.state = ConnectionState::Closing;
        }
    }

    /// Remove connection (closed)
    pub fn remove_connection(&self, id: &str) {
        let mut connections = self.connections.write().unwrap();

        if let Some(mut conn) = connections.get_mut(id) {
            conn.state = ConnectionState::Closed;
        }

        // Keep closed connections for a short time for forensics
        // They will be cleaned up by cleanup_old_connections()
    }

    /// Get all active connections
    pub fn get_active_connections(&self) -> Vec<TlsConnectionInfo> {
        let connections = self.connections.read().unwrap();
        connections
            .values()
            .filter(|c| {
                matches!(
                    c.state,
                    ConnectionState::Handshaking | ConnectionState::Established
                )
            })
            .cloned()
            .collect()
    }

    /// Get all connections (including closed)
    pub fn get_all_connections(&self) -> Vec<TlsConnectionInfo> {
        let connections = self.connections.read().unwrap();
        connections.values().cloned().collect()
    }

    /// Get connection by ID
    pub fn get_connection(&self, id: &str) -> Option<TlsConnectionInfo> {
        let connections = self.connections.read().unwrap();
        connections.get(id).cloned()
    }

    /// Clean up old closed connections (older than 1 hour)
    pub fn cleanup_old_connections(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff = now - 3600; // 1 hour ago

        let mut connections = self.connections.write().unwrap();
        connections.retain(|_, conn| {
            // Keep if not closed, or if closed recently
            !matches!(conn.state, ConnectionState::Closed) || conn.established_at > cutoff
        });
    }

    /// Get connection count by state
    pub fn get_connection_count_by_state(&self, state: ConnectionState) -> usize {
        let connections = self.connections.read().unwrap();
        connections.values().filter(|c| c.state == state).count()
    }

    /// Generate uTLS fingerprint (JA3-style)
    pub fn generate_utls_fingerprint(
        tls_version: u16,
        cipher_suites: &[u16],
        extensions: &[u16],
    ) -> String {
        let cipher_str = cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ext_str = extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!("{},{},{}", tls_version, cipher_str, ext_str)
    }
}

impl Default for TlsForensicsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_lifecycle() {
        let collector = TlsForensicsCollector::new();

        // Register connection
        collector.register_connection(
            "conn1".to_string(),
            54321,
            "example.com".to_string(),
            443,
            "example.com".to_string(),
        );

        // Update handshake
        collector.update_handshake(
            "conn1",
            "TLS 1.3".to_string(),
            "TLS_AES_256_GCM_SHA384".to_string(),
            "771,4865-4866-4867,0-23-65281".to_string(),
            45,
        );

        // Update traffic
        collector.update_traffic("conn1", 1024, 2048);

        let conn = collector.get_connection("conn1").unwrap();
        assert_eq!(conn.state, ConnectionState::Established);
        assert_eq!(conn.bytes_sent, 1024);
        assert_eq!(conn.bytes_received, 2048);

        // Close connection
        collector.remove_connection("conn1");

        let conn = collector.get_connection("conn1").unwrap();
        assert_eq!(conn.state, ConnectionState::Closed);
    }

    #[test]
    fn test_utls_fingerprint() {
        let fingerprint = TlsForensicsCollector::generate_utls_fingerprint(
            771,
            &[4865, 4866, 4867],
            &[0, 23, 65281],
        );

        assert_eq!(fingerprint, "771,4865-4866-4867,0-23-65281");
    }

    #[test]
    fn test_active_connections_filter() {
        let collector = TlsForensicsCollector::new();

        collector.register_connection(
            "conn1".to_string(),
            54321,
            "example.com".to_string(),
            443,
            "example.com".to_string(),
        );

        collector.register_connection(
            "conn2".to_string(),
            54322,
            "test.com".to_string(),
            443,
            "test.com".to_string(),
        );

        collector.update_handshake(
            "conn1",
            "TLS 1.3".to_string(),
            "TLS_AES_256_GCM_SHA384".to_string(),
            "771,4865-4866-4867,0-23-65281".to_string(),
            45,
        );

        collector.remove_connection("conn2");

        let active = collector.get_active_connections();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "conn1");
    }
}
