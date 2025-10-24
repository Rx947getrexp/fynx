//! Error types for IPSec protocol operations
//!
//! This module defines a unified error type for all IPSec operations,
//! covering IKEv2 and ESP protocols.

use std::fmt;

/// Result type for IPSec operations
pub type Result<T> = std::result::Result<T, Error>;

/// IPSec protocol errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid IKEv2 message format
    InvalidMessage(String),

    /// Invalid IKEv2 payload
    InvalidPayload(String),

    /// Unsupported protocol version
    UnsupportedVersion(u8),

    /// Unsupported exchange type
    UnsupportedExchangeType(u8),

    /// No acceptable proposal found
    NoProposalChosen,

    /// Authentication failed
    AuthenticationFailed(String),

    /// Security Association not found
    SaNotFound(String),

    /// Cryptographic operation failed
    CryptoError(String),

    /// Replay attack detected
    ReplayDetected(u64),

    /// Invalid packet length
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Buffer too short for operation
    BufferTooShort {
        /// Required length
        required: usize,
        /// Available length
        available: usize,
    },

    /// Message too large
    MessageTooLarge(u32),

    /// Invalid Security Parameter Index
    InvalidSpi(u32),

    /// Invalid sequence number
    InvalidSequence(u64),

    /// State machine error
    InvalidState(String),

    /// I/O error
    Io(String),

    /// Internal error (should not happen)
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidMessage(msg) => write!(f, "Invalid IKE message: {}", msg),
            Error::InvalidPayload(msg) => write!(f, "Invalid IKE payload: {}", msg),
            Error::UnsupportedVersion(v) => {
                write!(f, "Unsupported IKE version: 0x{:02x}", v)
            }
            Error::UnsupportedExchangeType(t) => {
                write!(f, "Unsupported exchange type: {}", t)
            }
            Error::NoProposalChosen => {
                write!(f, "No acceptable proposal found in negotiation")
            }
            Error::AuthenticationFailed(msg) => {
                write!(f, "Authentication failed: {}", msg)
            }
            Error::SaNotFound(id) => write!(f, "Security Association not found: {}", id),
            Error::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Error::ReplayDetected(seq) => {
                write!(f, "Replay attack detected (sequence: {})", seq)
            }
            Error::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid length: expected {}, got {}",
                    expected, actual
                )
            }
            Error::BufferTooShort {
                required,
                available,
            } => {
                write!(
                    f,
                    "Buffer too short: need {} bytes, have {}",
                    required, available
                )
            }
            Error::MessageTooLarge(size) => {
                write!(f, "IKE message too large: {} bytes", size)
            }
            Error::InvalidSpi(spi) => write!(f, "Invalid SPI: 0x{:08x}", spi),
            Error::InvalidSequence(seq) => write!(f, "Invalid sequence number: {}", seq),
            Error::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

// Convert from std::io::Error
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidMessage("test".to_string());
        assert_eq!(err.to_string(), "Invalid IKE message: test");

        let err = Error::UnsupportedVersion(0x10);
        assert_eq!(err.to_string(), "Unsupported IKE version: 0x10");

        let err = Error::InvalidLength {
            expected: 10,
            actual: 5,
        };
        assert_eq!(err.to_string(), "Invalid length: expected 10, got 5");
    }

    #[test]
    fn test_error_clone() {
        let err1 = Error::NoProposalChosen;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        match err {
            Error::Io(msg) => assert!(msg.contains("file not found")),
            _ => panic!("Expected Io error"),
        }
    }

    #[test]
    fn test_buffer_too_short() {
        let err = Error::BufferTooShort {
            required: 100,
            available: 50,
        };
        assert!(err.to_string().contains("Buffer too short"));
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("50"));
    }
}
