// rustray/src/app/logging.rs
//! Production Logging System with Rolling Files
//!
//! Features:
//! - Daily rolling log files via tracing-appender
//! - Configurable retention (default 30 days)
//! - JSON structured logging option
//! - Log streaming endpoint for remote access

use std::path::PathBuf;
use std::sync::Arc;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Logging configuration
#[derive(Clone, Debug)]
pub struct LogConfig {
    /// Directory for log files
    pub log_dir: PathBuf,
    /// Log file prefix
    pub file_prefix: String,
    /// Rotation policy: Daily, Hourly, or Never
    pub rotation: LogRotation,
    /// Maximum days to keep logs
    pub max_days: u32,
    /// Enable JSON structured output
    pub json_format: bool,
    /// Log level filter (e.g., "info", "debug", "rustray=debug,actix=info")
    pub level_filter: String,
    /// Also log to stdout
    pub stdout: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("/var/log/rustray"),
            file_prefix: "rustray".to_string(),
            rotation: LogRotation::Daily,
            max_days: 30,
            json_format: false,
            level_filter: "info".to_string(),
            stdout: true,
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub enum LogRotation {
    Daily,
    Hourly,
    Never,
}

impl From<LogRotation> for Rotation {
    fn from(r: LogRotation) -> Rotation {
        match r {
            LogRotation::Daily => Rotation::DAILY,
            LogRotation::Hourly => Rotation::HOURLY,
            LogRotation::Never => Rotation::NEVER,
        }
    }
}

/// Initialize the logging system
/// Returns a guard that must be kept alive for the lifetime of the application
pub fn init_logging(config: &LogConfig) -> Result<LogGuard, LogError> {
    // Ensure log directory exists
    std::fs::create_dir_all(&config.log_dir)
        .map_err(|e| LogError::DirectoryCreation(e.to_string()))?;

    let file_appender =
        RollingFileAppender::new(config.rotation.into(), &config.log_dir, &config.file_prefix);

    let (non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.level_filter))
        .map_err(|e| LogError::FilterParse(e.to_string()))?;

    let subscriber = tracing_subscriber::registry().with(env_filter);

    // Note: JSON format requires tracing-subscriber "json" feature
    // Using human-readable format for now
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_ansi(false);

    if config.stdout {
        let stdout_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stdout)
            .with_target(true)
            .with_ansi(true);

        subscriber.with(file_layer).with(stdout_layer).init();
    } else {
        subscriber.with(file_layer).init();
    }

    Ok(LogGuard {
        _file_guard: file_guard,
        config: config.clone(),
    })
}

/// Guard that keeps the logging system alive
pub struct LogGuard {
    _file_guard: WorkerGuard,
    config: LogConfig,
}

impl LogGuard {
    /// Get the log directory path
    pub fn log_dir(&self) -> &PathBuf {
        &self.config.log_dir
    }

    /// List available log files
    pub fn list_log_files(&self) -> Vec<LogFileInfo> {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.config.log_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata()
                    && metadata.is_file() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with(&self.config.file_prefix) {
                            files.push(LogFileInfo {
                                name,
                                path: entry.path(),
                                size: metadata.len(),
                                modified: metadata.modified().ok(),
                            });
                        }
                    }
            }
        }
        files.sort_by(|a, b| b.modified.cmp(&a.modified));
        files
    }

    /// Read lines from the most recent log file
    pub fn read_recent_logs(&self, max_lines: usize) -> Vec<String> {
        let files = self.list_log_files();
        if files.is_empty() {
            return Vec::new();
        }

        // Read from most recent file
        if let Ok(content) = std::fs::read_to_string(&files[0].path) {
            content
                .lines()
                .rev()
                .take(max_lines)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Clean up old log files
    pub fn cleanup_old_logs(&self) -> Result<u32, LogError> {
        let cutoff = std::time::SystemTime::now()
            - std::time::Duration::from_secs(self.config.max_days as u64 * 86400);

        let mut deleted = 0u32;
        for file in self.list_log_files() {
            if let Some(modified) = file.modified
                && modified < cutoff
                    && std::fs::remove_file(&file.path).is_ok() {
                        deleted += 1;
                        tracing::info!("Deleted old log file: {}", file.name);
                    }
        }
        Ok(deleted)
    }
}

#[derive(Debug, Clone)]
pub struct LogFileInfo {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

#[derive(Debug)]
pub enum LogError {
    DirectoryCreation(String),
    FilterParse(String),
    FileRead(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::DirectoryCreation(e) => write!(f, "Failed to create log directory: {}", e),
            LogError::FilterParse(e) => write!(f, "Failed to parse log filter: {}", e),
            LogError::FileRead(e) => write!(f, "Failed to read log file: {}", e),
        }
    }
}

impl std::error::Error for LogError {}

// ============================================================================
// Log Streaming for API
// ============================================================================

/// In-memory log buffer for streaming
pub struct LogBuffer {
    buffer: Arc<parking_lot::RwLock<Vec<String>>>,
    max_entries: usize,
}

impl LogBuffer {
    pub fn new(max_entries: usize) -> Self {
        Self {
            buffer: Arc::new(parking_lot::RwLock::new(Vec::with_capacity(max_entries))),
            max_entries,
        }
    }

    pub fn push(&self, entry: String) {
        let mut buf = self.buffer.write();
        if buf.len() >= self.max_entries {
            buf.remove(0);
        }
        buf.push(entry);
    }

    pub fn get_recent(&self, count: usize) -> Vec<String> {
        let buf = self.buffer.read();
        buf.iter()
            .rev()
            .take(count)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    pub fn get_since(&self, since_index: usize) -> Vec<String> {
        let buf = self.buffer.read();
        if since_index >= buf.len() {
            Vec::new()
        } else {
            buf[since_index..].to_vec()
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.max_days, 30);
        assert!(!config.json_format);
        assert!(config.stdout);
    }

    #[test]
    fn test_log_buffer() {
        let buffer = LogBuffer::new(5);
        for i in 0..7 {
            buffer.push(format!("Line {}", i));
        }
        assert_eq!(buffer.len(), 5);
        let recent = buffer.get_recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[2], "Line 6");
    }
}
