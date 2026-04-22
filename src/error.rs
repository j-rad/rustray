// src/error.rs
use thiserror::Error;

/// A specific set of errors that can occur within our application.
///
/// While we use `anyhow::Result` for most function signatures to simplify
/// error propagation, this enum allows us to define specific, typed
/// errors if needed.
#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("Configuration parsing error")]
    Config(#[from] serde_json::Error),

    #[error("An underlying component reported failure: {0}")]
    Component(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// A type alias for the standard `Result` type, using `anyhow::Error`
/// as the error variant. This is the primary result type that should
/// be used throughout the application.
pub type Result<T> = std::result::Result<T, anyhow::Error>;
