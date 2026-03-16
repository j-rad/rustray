// src/app/diagnostics.rs
//! Advanced Diagnostics Module
//!
//! This module provides production-grade diagnostic capabilities:
//!
//! - Thread-safe circular log buffer (LogCollector)
//! - Real-time log streaming via FFI callbacks
//! - Performance metrics collection
//! - Connection tracing
//! - Error aggregation

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::Level;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default log buffer size
const DEFAULT_BUFFER_SIZE: usize = 500;

/// Maximum log message length before truncation
const MAX_MESSAGE_LEN: usize = 4096;

/// Batch size for FFI callbacks
#[allow(dead_code)]
const FFI_BATCH_SIZE: usize = 50;

// ============================================================================
// LOG ENTRY
// ============================================================================

/// A single log entry
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Timestamp (unix epoch micros)
    pub timestamp: u64,
    /// Log level
    pub level: LogLevel,
    /// Target module
    pub target: String,
    /// Log message
    pub message: String,
    /// Optional connection ID
    pub connection_id: Option<u64>,
    /// Optional span/trace ID
    pub span_id: Option<u64>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(level: LogLevel, target: &str, message: String) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
            level,
            target: target.to_string(),
            message: if message.len() > MAX_MESSAGE_LEN {
                format!("{}...", &message[..MAX_MESSAGE_LEN - 3])
            } else {
                message
            },
            connection_id: None,
            span_id: None,
        }
    }

    /// Create with connection ID
    pub fn with_connection(mut self, conn_id: u64) -> Self {
        self.connection_id = Some(conn_id);
        self
    }

    /// Format timestamp as ISO 8601
    pub fn timestamp_str(&self) -> String {
        let secs = self.timestamp / 1_000_000;
        let micros = self.timestamp % 1_000_000;
        format!("{}.{:06}", secs, micros)
    }

    /// Convert to FFI-friendly format
    pub fn to_ffi_string(&self) -> String {
        format!(
            "[{}] {} {}: {}",
            self.level.as_str(),
            self.timestamp_str(),
            self.target,
            self.message
        )
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}: {}",
            self.level.as_str(),
            self.timestamp_str(),
            self.target,
            self.message
        )
    }
}

/// Log level enum (FFI-compatible)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    pub fn from_tracing(level: Level) -> Self {
        match level {
            Level::TRACE => LogLevel::Trace,
            Level::DEBUG => LogLevel::Debug,
            Level::INFO => LogLevel::Info,
            Level::WARN => LogLevel::Warn,
            Level::ERROR => LogLevel::Error,
        }
    }
}

impl From<u8> for LogLevel {
    fn from(v: u8) -> Self {
        match v {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Info,
            3 => LogLevel::Warn,
            _ => LogLevel::Error,
        }
    }
}

// ============================================================================
// LOG COLLECTOR
// ============================================================================

/// Thread-safe circular log buffer
pub struct LogCollector {
    /// Circular buffer of log entries
    buffer: RwLock<VecDeque<LogEntry>>,
    /// Maximum buffer size
    capacity: usize,
    /// Total entries processed
    total_entries: AtomicU64,
    /// Entries dropped due to overflow
    dropped_entries: AtomicU64,
    /// Is streaming enabled
    streaming_enabled: AtomicBool,
    /// Minimum log level for collection
    min_level: RwLock<LogLevel>,
    /// FFI callback function pointer
    ffi_callback: RwLock<Option<Box<dyn Fn(&str) + Send + Sync>>>,
    /// Subscribers for real-time streaming
    subscribers: RwLock<Vec<tokio::sync::mpsc::UnboundedSender<LogEntry>>>,
}

impl LogCollector {
    /// Create a new LogCollector with default capacity
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUFFER_SIZE)
    }

    /// Create a new LogCollector with custom capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
            total_entries: AtomicU64::new(0),
            dropped_entries: AtomicU64::new(0),
            streaming_enabled: AtomicBool::new(false),
            min_level: RwLock::new(LogLevel::Debug),
            ffi_callback: RwLock::new(None),
            subscribers: RwLock::new(Vec::new()),
        }
    }

    /// Add a log entry
    pub fn push(&self, entry: LogEntry) {
        // Check minimum level
        if let Ok(min_level) = self.min_level.read() {
            if entry.level < *min_level {
                return;
            }
        }

        self.total_entries.fetch_add(1, Ordering::Relaxed);

        // Add to buffer
        if let Ok(mut buffer) = self.buffer.write() {
            while buffer.len() >= self.capacity {
                buffer.pop_front();
                self.dropped_entries.fetch_add(1, Ordering::Relaxed);
            }
            buffer.push_back(entry.clone());
        }

        // Send to FFI callback if enabled
        if self.streaming_enabled.load(Ordering::Relaxed) {
            if let Ok(callback) = self.ffi_callback.read() {
                if let Some(cb) = callback.as_ref() {
                    cb(&entry.to_ffi_string());
                }
            }
        }

        // Send to async subscribers
        if let Ok(subs) = self.subscribers.read() {
            for sub in subs.iter() {
                let _ = sub.send(entry.clone());
            }
        }
    }

    /// Log a message at the specified level
    pub fn log(&self, level: LogLevel, target: &str, message: impl Into<String>) {
        self.push(LogEntry::new(level, target, message.into()));
    }

    /// Log info level
    pub fn info(&self, target: &str, message: impl Into<String>) {
        self.log(LogLevel::Info, target, message);
    }

    /// Log warn level
    pub fn warn(&self, target: &str, message: impl Into<String>) {
        self.log(LogLevel::Warn, target, message);
    }

    /// Log error level
    pub fn error(&self, target: &str, message: impl Into<String>) {
        self.log(LogLevel::Error, target, message);
    }

    /// Log debug level
    pub fn debug(&self, target: &str, message: impl Into<String>) {
        self.log(LogLevel::Debug, target, message);
    }

    /// Get the last N entries
    pub fn get_last(&self, count: usize) -> Vec<LogEntry> {
        if let Ok(buffer) = self.buffer.read() {
            let skip = if buffer.len() > count {
                buffer.len() - count
            } else {
                0
            };
            buffer.iter().skip(skip).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Get all entries
    pub fn get_all(&self) -> Vec<LogEntry> {
        if let Ok(buffer) = self.buffer.read() {
            buffer.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Get entries since timestamp (unix epoch micros)
    pub fn get_since(&self, since_timestamp: u64) -> Vec<LogEntry> {
        if let Ok(buffer) = self.buffer.read() {
            buffer
                .iter()
                .filter(|e| e.timestamp > since_timestamp)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get entries by level
    pub fn get_by_level(&self, level: LogLevel) -> Vec<LogEntry> {
        if let Ok(buffer) = self.buffer.read() {
            buffer
                .iter()
                .filter(|e| e.level == level)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get entries for a connection
    pub fn get_by_connection(&self, conn_id: u64) -> Vec<LogEntry> {
        if let Ok(buffer) = self.buffer.read() {
            buffer
                .iter()
                .filter(|e| e.connection_id == Some(conn_id))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Clear all entries
    pub fn clear(&self) {
        if let Ok(mut buffer) = self.buffer.write() {
            buffer.clear();
        }
    }

    /// Get statistics
    pub fn stats(&self) -> LogCollectorStats {
        let current_size = self.buffer.read().map(|b| b.len()).unwrap_or(0);

        LogCollectorStats {
            capacity: self.capacity,
            current_size,
            total_entries: self.total_entries.load(Ordering::Relaxed),
            dropped_entries: self.dropped_entries.load(Ordering::Relaxed),
            streaming_enabled: self.streaming_enabled.load(Ordering::Relaxed),
        }
    }

    /// Set minimum log level
    pub fn set_min_level(&self, level: LogLevel) {
        if let Ok(mut min) = self.min_level.write() {
            *min = level;
        }
    }

    /// Enable FFI log streaming
    pub fn enable_streaming(&self) {
        self.streaming_enabled.store(true, Ordering::SeqCst);
    }

    /// Disable FFI log streaming
    pub fn disable_streaming(&self) {
        self.streaming_enabled.store(false, Ordering::SeqCst);
    }

    /// Set FFI callback for log streaming
    pub fn set_ffi_callback<F>(&self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        if let Ok(mut cb) = self.ffi_callback.write() {
            *cb = Some(Box::new(callback));
        }
        self.enable_streaming();
    }

    /// Clear FFI callback
    pub fn clear_ffi_callback(&self) {
        if let Ok(mut cb) = self.ffi_callback.write() {
            *cb = None;
        }
        self.disable_streaming();
    }

    /// Subscribe to real-time log stream (async)
    pub fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<LogEntry> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        if let Ok(mut subs) = self.subscribers.write() {
            subs.push(tx);
        }
        rx
    }

    /// Get formatted log output for FFI
    pub fn get_formatted_logs(&self, count: usize) -> Vec<String> {
        self.get_last(count)
            .iter()
            .map(|e| e.to_ffi_string())
            .collect()
    }

    /// Export logs as JSON
    pub fn export_json(&self) -> String {
        let entries: Vec<_> = self
            .get_all()
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "level": e.level.as_str(),
                    "target": e.target,
                    "message": e.message,
                    "connection_id": e.connection_id,
                })
            })
            .collect();

        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Log collector statistics
#[derive(Clone, Debug)]
pub struct LogCollectorStats {
    pub capacity: usize,
    pub current_size: usize,
    pub total_entries: u64,
    pub dropped_entries: u64,
    pub streaming_enabled: bool,
}

// ============================================================================
// TRACING LAYER
// ============================================================================

use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Tracing layer that forwards logs to LogCollector
pub struct LogCollectorLayer {
    collector: Arc<LogCollector>,
}

impl LogCollectorLayer {
    pub fn new(collector: Arc<LogCollector>) -> Self {
        Self { collector }
    }
}

impl<S> Layer<S> for LogCollectorLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let level = LogLevel::from_tracing(*event.metadata().level());
        let target = event.metadata().target();

        // Extract message from event fields
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let entry = LogEntry::new(level, target, visitor.message);
        self.collector.push(entry);
    }
}

/// Visitor to extract message from tracing event
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else if self.message.is_empty() {
            self.message = format!("{:?}", value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" || self.message.is_empty() {
            self.message = value.to_string();
        }
    }
}

// ============================================================================
// CONNECTION TRACER
// ============================================================================

/// Connection-level tracing
pub struct ConnectionTracer {
    /// Connection ID
    pub id: u64,
    /// Start time
    pub start: Instant,
    /// Log collector reference
    collector: Arc<LogCollector>,
    /// Protocol
    pub protocol: String,
    /// Target address
    pub target: String,
}

impl ConnectionTracer {
    /// Create a new connection tracer
    pub fn new(id: u64, protocol: &str, target: &str, collector: Arc<LogCollector>) -> Self {
        let tracer = Self {
            id,
            start: Instant::now(),
            collector,
            protocol: protocol.to_string(),
            target: target.to_string(),
        };

        tracer.log(
            LogLevel::Debug,
            &format!("Connection started: {} -> {}", protocol, target),
        );
        tracer
    }

    /// Log with connection context
    pub fn log(&self, level: LogLevel, message: &str) {
        let entry = LogEntry::new(level, &format!("conn:{}", self.id), message.to_string())
            .with_connection(self.id);

        self.collector.push(entry);
    }

    /// Log info
    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    /// Log error
    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for ConnectionTracer {
    fn drop(&mut self) {
        let elapsed = self.elapsed();
        self.log(
            LogLevel::Debug,
            &format!(
                "Connection closed after {:?}: {} -> {}",
                elapsed, self.protocol, self.target
            ),
        );
    }
}

// ============================================================================
// PERFORMANCE METRICS
// ============================================================================

/// Performance metrics collector
pub struct PerformanceMetrics {
    /// Total requests
    pub total_requests: AtomicU64,
    /// Successful requests
    pub successful_requests: AtomicU64,
    /// Failed requests
    pub failed_requests: AtomicU64,
    /// Total bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Average latency (microseconds)
    pub avg_latency_us: AtomicU64,
    /// Max latency (microseconds)
    pub max_latency_us: AtomicU64,
    /// Active connections
    pub active_connections: AtomicUsize,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            avg_latency_us: AtomicU64::new(0),
            max_latency_us: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }

    pub fn record_request(&self, success: bool, bytes: u64, latency_us: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }

        self.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);

        // Update max latency
        let current_max = self.max_latency_us.load(Ordering::Relaxed);
        if latency_us > current_max {
            self.max_latency_us.store(latency_us, Ordering::Relaxed);
        }

        // Update average (simple moving average)
        let total = self.total_requests.load(Ordering::Relaxed);
        let avg = self.avg_latency_us.load(Ordering::Relaxed);
        let new_avg = (avg * (total - 1) + latency_us) / total;
        self.avg_latency_us.store(new_avg, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

use std::sync::OnceLock;

/// Global log collector instance
static GLOBAL_COLLECTOR: OnceLock<Arc<LogCollector>> = OnceLock::new();

/// Get or initialize global log collector
pub fn global_collector() -> Arc<LogCollector> {
    GLOBAL_COLLECTOR
        .get_or_init(|| Arc::new(LogCollector::new()))
        .clone()
}

/// Initialize global log collector with custom capacity
pub fn init_global_collector(capacity: usize) -> Arc<LogCollector> {
    let collector = Arc::new(LogCollector::with_capacity(capacity));
    let _ = GLOBAL_COLLECTOR.set(collector.clone());
    collector
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "test", "Hello World".to_string());
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.target, "test");
        assert_eq!(entry.message, "Hello World");
    }

    #[test]
    fn test_log_collector_push() {
        let collector = LogCollector::new();

        for i in 0..10 {
            collector.info("test", format!("Message {}", i));
        }

        assert_eq!(collector.get_all().len(), 10);
    }

    #[test]
    fn test_log_collector_overflow() {
        let collector = LogCollector::with_capacity(5);

        for i in 0..10 {
            collector.info("test", format!("Message {}", i));
        }

        let entries = collector.get_all();
        assert_eq!(entries.len(), 5);
        // Should contain last 5 messages
        assert!(entries[0].message.contains("5"));
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
        assert!(LogLevel::Debug > LogLevel::Trace);
    }

    #[test]
    fn test_log_collector_stats() {
        let collector = LogCollector::with_capacity(100);

        for i in 0..50 {
            collector.info("test", format!("Message {}", i));
        }

        let stats = collector.stats();
        assert_eq!(stats.capacity, 100);
        assert_eq!(stats.current_size, 50);
        assert_eq!(stats.total_entries, 50);
        assert_eq!(stats.dropped_entries, 0);
    }

    #[test]
    fn test_get_by_level() {
        let collector = LogCollector::new();

        collector.info("test", "Info message");
        collector.error("test", "Error message");
        collector.warn("test", "Warn message");

        let errors = collector.get_by_level(LogLevel::Error);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("Error"));
    }

    #[test]
    fn test_ffi_format() {
        let entry = LogEntry::new(LogLevel::Info, "test", "Hello".to_string());
        let ffi_str = entry.to_ffi_string();
        assert!(ffi_str.contains("[INFO]"));
        assert!(ffi_str.contains("test"));
        assert!(ffi_str.contains("Hello"));
    }

    #[test]
    fn test_min_level_filtering() {
        let collector = LogCollector::new();
        collector.set_min_level(LogLevel::Warn);

        collector.debug("test", "Debug - should be filtered");
        collector.info("test", "Info - should be filtered");
        collector.warn("test", "Warn - should appear");
        collector.error("test", "Error - should appear");

        let entries = collector.get_all();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_subscribe() {
        let collector = Arc::new(LogCollector::new());
        let mut rx = collector.subscribe();

        collector.info("test", "Test message");

        let entry = rx.recv().await.unwrap();
        assert!(entry.message.contains("Test message"));
    }
}
