// src/app/connection_tracker.rs
//! Real-Time Connection State Tracking
//!
//! Provides granular tracking of active connections, traffic statistics,
//! and connection state for FFI exposure.

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Connection state enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

/// Granular Active Session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub id: String, // UUID
    pub source: String,
    pub dest: String,
    pub protocol: String,
    pub start_time: u64,
    pub sniffed_header: Option<String>,
    // We use Arc<Atomic> here to allow cheap updating from Router without locking the map
    #[serde(skip)]
    pub uploaded_ref: Arc<AtomicU64>,
    #[serde(skip)]
    pub downloaded_ref: Arc<AtomicU64>,
    // Snapshot values for serialization
    pub uploaded: u64,
    pub downloaded: u64,
}

impl ActiveSession {
    pub fn new(id: String, source: String, dest: String, protocol: String) -> Self {
        Self {
            id,
            source,
            dest,
            protocol,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            sniffed_header: None,
            uploaded_ref: Arc::new(AtomicU64::new(0)),
            downloaded_ref: Arc::new(AtomicU64::new(0)),
            uploaded: 0,
            downloaded: 0,
        }
    }
}

/// Real-time connection statistics (Aggregate)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub state: ConnectionState,
    pub active_connections: u32,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub connection_start_time: u64,
    pub current_protocol: String,
    pub current_server: String,
    pub last_error: Option<String>,
    pub last_error_time: Option<u64>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            active_connections: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
            connection_start_time: 0,
            current_protocol: String::new(),
            current_server: String::new(),
            last_error: None,
            last_error_time: None,
        }
    }
}

/// Thread-safe connection tracker
pub struct ConnectionTracker {
    state: Arc<RwLock<ConnectionState>>,
    // Granular Sessions: SessionID -> ActiveSession
    pub sessions: Arc<DashMap<String, ActiveSession>>,

    // Aggregate Global Counters
    active_count: Arc<AtomicU64>,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
    connection_start: Arc<AtomicU64>,
    protocol: Arc<RwLock<String>>,
    server: Arc<RwLock<String>>,
    last_error: Arc<RwLock<Option<(String, u64)>>>,
    is_running: Arc<AtomicBool>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            sessions: Arc::new(DashMap::new()),
            active_count: Arc::new(AtomicU64::new(0)),
            bytes_up: Arc::new(AtomicU64::new(0)),
            bytes_down: Arc::new(AtomicU64::new(0)),
            connection_start: Arc::new(AtomicU64::new(0)),
            protocol: Arc::new(RwLock::new(String::new())),
            server: Arc::new(RwLock::new(String::new())),
            last_error: Arc::new(RwLock::new(None)),
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Register a new active session
    pub fn register_session(&self, session: ActiveSession) {
        self.active_count.fetch_add(1, Ordering::Relaxed);
        self.sessions.insert(session.id.clone(), session);
    }

    /// Remove a session
    pub fn end_session(&self, id: &str) {
        if self.sessions.remove(id).is_some() {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get a live snapshot of all active sessions
    pub fn get_active_sessions(&self) -> Vec<ActiveSession> {
        self.sessions
            .iter()
            .map(|r| {
                let mut session = r.value().clone();
                // Sync atomic values to snapshot fields
                session.uploaded = session.uploaded_ref.load(Ordering::Relaxed);
                session.downloaded = session.downloaded_ref.load(Ordering::Relaxed);
                session
            })
            .collect()
    }

    /// Update traffic for specific session (and global)
    pub fn add_traffic(&self, session_id: &str, up: u64, down: u64) {
        if up > 0 {
            self.bytes_up.fetch_add(up, Ordering::Relaxed);
            if let Some(sess) = self.sessions.get(session_id) {
                sess.uploaded_ref.fetch_add(up, Ordering::Relaxed);
            }
        }
        if down > 0 {
            self.bytes_down.fetch_add(down, Ordering::Relaxed);
            if let Some(sess) = self.sessions.get(session_id) {
                sess.downloaded_ref.fetch_add(down, Ordering::Relaxed);
            }
        }
    }

    // --- Legacy / Aggregate API ---

    pub fn set_state(&self, state: ConnectionState) {
        *self.state.write() = state;
        if state == ConnectionState::Connected && !self.is_running.load(Ordering::Relaxed) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.connection_start.store(now, Ordering::Relaxed);
            self.is_running.store(true, Ordering::Relaxed);
        } else if state == ConnectionState::Disconnected {
            self.is_running.store(false, Ordering::Relaxed);
            self.sessions.clear(); // Clear all sessions on disconnect
            self.active_count.store(0, Ordering::Relaxed);
        }
    }

    pub fn get_state(&self) -> ConnectionState {
        *self.state.read()
    }

    // Kept for backward compat, but sessions should be preferred
    pub fn add_connection(&self) {
        self.active_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remove_connection(&self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_upload(&self, bytes: u64) {
        self.bytes_up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.bytes_down.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn set_protocol(&self, protocol: String) {
        *self.protocol.write() = protocol;
    }

    pub fn set_server(&self, server: String) {
        *self.server.write() = server;
    }

    pub fn set_error(&self, error: String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        *self.last_error.write() = Some((error, now));
        self.set_state(ConnectionState::Error);
    }

    pub fn get_stats(&self) -> ConnectionStats {
        let error = self.last_error.read();
        let (last_error, last_error_time) = error
            .as_ref()
            .map(|(msg, time)| (Some(msg.clone()), Some(*time)))
            .unwrap_or((None, None));

        ConnectionStats {
            state: self.get_state(),
            active_connections: self.active_count.load(Ordering::Relaxed) as u32,
            bytes_uploaded: self.bytes_up.load(Ordering::Relaxed),
            bytes_downloaded: self.bytes_down.load(Ordering::Relaxed),
            connection_start_time: self.connection_start.load(Ordering::Relaxed),
            current_protocol: self.protocol.read().clone(),
            current_server: self.server.read().clone(),
            last_error,
            last_error_time,
        }
    }

    pub fn reset(&self) {
        self.bytes_up.store(0, Ordering::Relaxed);
        self.bytes_down.store(0, Ordering::Relaxed);
        self.connection_start.store(0, Ordering::Relaxed);
        *self.last_error.write() = None;
        self.set_state(ConnectionState::Disconnected);
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

static GLOBAL_TRACKER: OnceLock<ConnectionTracker> = OnceLock::new();

pub fn global_tracker() -> &'static ConnectionTracker {
    GLOBAL_TRACKER.get_or_init(ConnectionTracker::new)
}

// --- Tracked Stream Wrapper ---

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// A wrapper around any AsyncStream that updates traffic counters on r/w
pub struct TrackedStream<S> {
    inner: S,
    session_id: String,
    uploaded_ref: Arc<AtomicU64>,
    downloaded_ref: Arc<AtomicU64>,
}

impl<S> TrackedStream<S> {
    pub fn new(
        inner: S,
        session_id: String,
        uploaded_ref: Arc<AtomicU64>,
        downloaded_ref: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            session_id,
            uploaded_ref,
            downloaded_ref,
        }
    }
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        global_tracker().end_session(&self.session_id);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                if after > before {
                    let diff = (after - before) as u64;
                    // Read = Upload from client perspective (Inbound -> Proxy)
                    self.uploaded_ref.fetch_add(diff, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                // Write = Download to client perspective
                self.downloaded_ref.fetch_add(n as u64, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_state_transitions() {
        let tracker = ConnectionTracker::new();
        assert_eq!(tracker.get_state(), ConnectionState::Disconnected);
        tracker.set_state(ConnectionState::Connecting);
        assert_eq!(tracker.get_state(), ConnectionState::Connecting);
    }

    #[test]
    fn test_session_tracking() {
        let tracker = ConnectionTracker::new();
        let session = ActiveSession::new(
            "uuid-1".into(),
            "127.0.0.1:1234".into(),
            "google.com:443".into(),
            "tcp".into(),
        );

        tracker.register_session(session);
        assert_eq!(tracker.get_stats().active_connections, 1);

        tracker.add_traffic("uuid-1", 100, 200);

        let sessions = tracker.get_active_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].uploaded, 100);
        assert_eq!(sessions[0].downloaded, 200);

        // Check global aggregation
        let stats = tracker.get_stats();
        assert_eq!(stats.bytes_uploaded, 100);
        assert_eq!(stats.bytes_downloaded, 200);

        tracker.end_session("uuid-1");
        assert_eq!(tracker.get_stats().active_connections, 0);
    }
}
