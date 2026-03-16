// src/app/log_collector.rs
//! Thread-Safe Circular Log Buffer for FFI Integration
//!
//! Provides a production-grade log collection system that can be accessed
//! from FFI (UniFFI) for real-time log streaming to mobile/desktop UIs.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

/// Maximum number of log entries to keep in memory
const DEFAULT_LOG_CAPACITY: usize = 10000;

/// A single log entry with metadata
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: i64,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Thread-safe circular log buffer
#[derive(Clone)]
pub struct LogCollector {
    entries: Arc<RwLock<VecDeque<LogEntry>>>,
    capacity: usize,
}

impl LogCollector {
    /// Create a new log collector with default capacity
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_LOG_CAPACITY)
    }

    /// Create a new log collector with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Add a log entry to the buffer
    pub fn push(&self, entry: LogEntry) {
        let mut entries = self.entries.write().unwrap();

        // If at capacity, remove oldest entry
        if entries.len() >= self.capacity {
            entries.pop_front();
        }

        entries.push_back(entry);
    }

    /// Get the most recent N log entries
    pub fn get_recent(&self, count: usize) -> Vec<LogEntry> {
        let entries = self.entries.read().unwrap();
        let start = entries.len().saturating_sub(count);
        entries.iter().skip(start).cloned().collect()
    }

    /// Get all log entries
    pub fn get_all(&self) -> Vec<LogEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().cloned().collect()
    }

    /// Clear all log entries
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
    }

    /// Get current number of stored entries
    pub fn len(&self) -> usize {
        let entries = self.entries.read().unwrap();
        entries.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracing layer that forwards logs to the LogCollector
pub struct LogCollectorLayer {
    collector: LogCollector,
}

impl LogCollectorLayer {
    pub fn new(collector: LogCollector) -> Self {
        Self { collector }
    }
}

impl<S> Layer<S> for LogCollectorLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();

        // Extract message
        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));

        // Create log entry
        let entry = LogEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            level: format!("{:?}", metadata.level()),
            target: metadata.target().to_string(),
            message,
        };

        self.collector.push(entry);
    }
}

/// Visitor to extract message from tracing event
struct MessageVisitor<'a>(&'a mut String);

impl<'a> tracing::field::Visit for MessageVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            *self.0 = format!("{:?}", value);
            // Remove surrounding quotes if present
            if self.0.starts_with('"') && self.0.ends_with('"') {
                *self.0 = self.0[1..self.0.len() - 1].to_string();
            }
        }
    }
}

/// Global log collector instance
static GLOBAL_COLLECTOR: std::sync::OnceLock<LogCollector> = std::sync::OnceLock::new();

/// Initialize the global log collector
pub fn init_log_collector() -> LogCollector {
    GLOBAL_COLLECTOR.get_or_init(|| LogCollector::new()).clone()
}

/// Get the global log collector
pub fn get_log_collector() -> Option<LogCollector> {
    GLOBAL_COLLECTOR.get().cloned()
}

/// Setup tracing with log collector integration
pub fn setup_tracing_with_collector() -> LogCollector {
    let collector = init_log_collector();

    let collector_layer = LogCollectorLayer::new(collector.clone());

    let subscriber = Registry::default()
        .with(collector_layer)
        .with(tracing_subscriber::fmt::layer());

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    collector
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_collector_basic() {
        let collector = LogCollector::new();

        let entry = LogEntry {
            timestamp: 1234567890,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: "Test message".to_string(),
        };

        collector.push(entry.clone());
        assert_eq!(collector.len(), 1);

        let recent = collector.get_recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].message, "Test message");
    }

    #[test]
    fn test_log_collector_capacity() {
        let collector = LogCollector::with_capacity(5);

        // Add 10 entries
        for i in 0..10 {
            collector.push(LogEntry {
                timestamp: i,
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: format!("Message {}", i),
            });
        }

        // Should only keep last 5
        assert_eq!(collector.len(), 5);

        let all = collector.get_all();
        assert_eq!(all[0].message, "Message 5");
        assert_eq!(all[4].message, "Message 9");
    }

    #[test]
    fn test_log_collector_clear() {
        let collector = LogCollector::new();

        collector.push(LogEntry {
            timestamp: 0,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: "Test".to_string(),
        });

        assert_eq!(collector.len(), 1);
        collector.clear();
        assert_eq!(collector.len(), 0);
        assert!(collector.is_empty());
    }
}
