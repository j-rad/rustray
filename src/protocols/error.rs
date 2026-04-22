// src/protocols/error.rs
//! Protocol-specific error types for better error handling and debugging
//! Enhanced with Iranian network censorship diagnostics

use thiserror::Error;

/// VLESS Protocol Errors
#[derive(Debug, Error)]
pub enum VlessError {
    #[error("Invalid protocol version: {0}, expected 0")]
    InvalidVersion(u8),

    #[error("Unknown client UUID")]
    UnknownClient,

    #[error("Replay attack detected for nonce")]
    ReplayDetected,

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    #[error("REALITY handshake failed: {0}")]
    RealityHandshakeFailed(String),

    #[error("REALITY authentication failed: {0}")]
    RealityAuthFailed(String),

    #[error("REALITY probe detected and blocked")]
    RealityProbeDetected,

    #[error("Handshake timeout after {0}ms - possible DPI interference")]
    HandshakeTimeout(u64),

    #[error("SNI snooping detected - connection reset by ISP")]
    SnoopingDetected,

    #[error("Invalid addon type: {0}")]
    InvalidAddonType(u8),

    #[error("Addon data too large: {0} bytes")]
    AddonTooLarge(usize),

    #[error("Invalid UUID format: {0}")]
    InvalidUuid(String),

    #[error("Invalid domain encoding")]
    InvalidDomainEncoding,

    #[error("Fallback destination required but not configured")]
    FallbackNotConfigured,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("UUID parsing error: {0}")]
    UuidParse(#[from] uuid::Error),

    #[error("Network censorship: {0}")]
    Censorship(#[from] NetworkCensorshipError),
}

pub type VlessResult<T> = Result<T, VlessError>;

/// VMess Protocol Errors
#[derive(Debug, Error)]
pub enum VmessError {
    #[error("Invalid header length: {0}")]
    InvalidHeaderLength(usize),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UUID parsing error: {0}")]
    UuidParse(#[from] uuid::Error),
}

pub type VmessResult<T> = Result<T, VmessError>;

/// Trojan Protocol Errors
#[derive(Debug, Error)]
pub enum TrojanError {
    #[error("Invalid password hash")]
    InvalidPassword,

    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("CRLF validation failed")]
    InvalidCRLF,

    #[error("TLS required but not configured")]
    TlsRequired,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub type TrojanResult<T> = Result<T, TrojanError>;

/// Shadowsocks 2022 Protocol Errors
#[derive(Debug, Error)]
pub enum ShadowsocksError {
    #[error("Invalid salt length: {0}")]
    InvalidSaltLength(usize),

    #[error("Invalid header length: {0}")]
    InvalidHeaderLength(usize),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("AEAD tag mismatch")]
    AeadTagMismatch,

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("Replay attack detected")]
    ReplayDetected,

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type ShadowsocksResult<T> = Result<T, ShadowsocksError>;

/// Hysteria2 Protocol Errors
#[derive(Debug, Error)]
pub enum Hysteria2Error {
    #[error("QUIC connection error: {0}")]
    QuicError(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid stream type: {0}")]
    InvalidStreamType(u8),

    #[error("Congestion control error: {0}")]
    CongestionControl(String),

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Hysteria2Result<T> = Result<T, Hysteria2Error>;

// Implement conversion to crate::error::Error for all protocol errors
impl From<VlessError> for crate::error::Error {
    fn from(err: VlessError) -> Self {
        crate::error::Error::Protocol(err.to_string())
    }
}

impl From<VmessError> for crate::error::Error {
    fn from(err: VmessError) -> Self {
        crate::error::Error::Protocol(err.to_string())
    }
}

impl From<TrojanError> for crate::error::Error {
    fn from(err: TrojanError) -> Self {
        crate::error::Error::Protocol(err.to_string())
    }
}

impl From<ShadowsocksError> for crate::error::Error {
    fn from(err: ShadowsocksError) -> Self {
        crate::error::Error::Protocol(err.to_string())
    }
}

impl From<Hysteria2Error> for crate::error::Error {
    fn from(err: Hysteria2Error) -> Self {
        crate::error::Error::Protocol(err.to_string())
    }
}

/// Network Censorship Errors (Iranian ISP-specific diagnostics)
#[derive(Debug, Error)]
pub enum NetworkCensorshipError {
    #[error("Connection reset during TLS handshake - likely DPI block")]
    TlsHandshakeReset,

    #[error("SNI filtering detected for domain: {0}")]
    SniFiltered(String),

    #[error("TCP connection timeout to {0}:{1} - possible IP block")]
    TcpTimeout(String, u16),

    #[error("Suspicious connection pattern detected by GFW/DPI")]
    PatternDetected,

    #[error("Certificate validation failed - MITM attack suspected")]
    MitmSuspected,

    #[error("UDP packet dropped - QoS throttling by ISP")]
    UdpDropped,
}

impl From<NetworkCensorshipError> for crate::error::Error {
    fn from(err: NetworkCensorshipError) -> Self {
        crate::error::Error::Protocol(err.to_string())
    }
}
