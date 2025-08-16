//! Error handling for RustMapV3

use std::fmt;

/// Result type for RustMapV3 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for RustMapV3
#[derive(Debug)]
pub enum Error {
    /// I/O related errors
    Io(std::io::Error),
    /// Network resolution errors
    DnsResolution(String),
    /// Invalid target format
    InvalidTarget(String),
    /// Invalid port specification
    InvalidPort(String),
    /// Nmap execution error
    NmapError(String),
    /// RustScan execution error
    RustScanError(String),
    /// General error with message
    General(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "I/O error: {}", err),
            Error::DnsResolution(msg) => write!(f, "DNS resolution error: {}", msg),
            Error::InvalidTarget(msg) => write!(f, "Invalid target: {}", msg),
            Error::InvalidPort(msg) => write!(f, "Invalid port specification: {}", msg),
            Error::NmapError(msg) => write!(f, "Nmap error: {}", msg),
            Error::RustScanError(msg) => write!(f, "RustScan error: {}", msg),
            Error::General(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::General(err.to_string())
    }
}