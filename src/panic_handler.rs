// src/panic_handler.rs
//! Global Panic Supervisor
//!
//! Captures thread panics, logs them securely (PII scrubbed),
//! and attempts to keep the process alive if possible (or fail gracefully).

use crate::security::pii_filter::sanitize_log_message;
use std::panic;
use std::thread;
use tracing::error;

/// Initialize the global panic hook
pub fn init() {
    panic::set_hook(Box::new(|info| {
        let thread = thread::current();
        let name = thread.name().unwrap_or("<unnamed>");

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<Any>",
            },
        };

        let location = match info.location() {
            Some(location) => format!("{}:{}:{}", location.file(), location.line(), location.column()),
            None => "unknown location".to_string(),
        };

        // Scrub sensitive data from panic message
        let scrubbed_msg = sanitize_log_message(msg);

        error!(
            target: "panic",
            "CRITICAL PANIC in thread '{}' at {}: {}",
            name,
            location,
            scrubbed_msg
        );

        // Optional: Trigger a self-healing restart signal here if we had a supervisor channel
        // For now, we log and abort to let systemd restart us, or let the thread die if it's non-critical.
        // But the prompt says "restart proxy tasks instantly" -> implies we shouldn't abort entire process?
        // std::panic::set_hook doesn't stop the unwinding. The thread will still die.
        // If the main thread dies, the process dies.
        // If a worker thread dies, we need a supervisor to restart it.
        // Rust's tokio runtime handles task panics by catching them at the task boundary usually.
        // If this hook is called, it means a panic happened.

        // Strategy: We log. If it's the main thread, we might want to abort to ensure clean restart.
        if name == "main" {
            error!("Main thread panicked. Aborting for restart.");
            std::process::abort();
        }
    }));
}
