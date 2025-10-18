//! Error types for Fynx

use std::fmt;

/// Unified error type for all Fynx operations
#[derive(Debug)]
pub enum FynxError {
    /// I/O error
    Io(std::io::Error),

    /// Configuration error
    Config(String),

    /// Protocol error
    Protocol(String),

    /// Security error (authentication, authorization, etc.)
    Security(String),

    /// Not implemented
    NotImplemented(String),

    /// Other error
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for FynxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FynxError::Io(e) => write!(f, "IO error: {}", e),
            FynxError::Config(msg) => write!(f, "Configuration error: {}", msg),
            FynxError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            FynxError::Security(msg) => write!(f, "Security error: {}", msg),
            FynxError::NotImplemented(msg) => write!(f, "Not implemented: {}", msg),
            FynxError::Other(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::error::Error for FynxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FynxError::Io(e) => Some(e),
            FynxError::Other(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FynxError {
    fn from(err: std::io::Error) -> Self {
        FynxError::Io(err)
    }
}

/// Result type for Fynx operations
pub type FynxResult<T> = Result<T, FynxError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = FynxError::Config("Invalid configuration".to_string());
        assert_eq!(
            err.to_string(),
            "Configuration error: Invalid configuration"
        );
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let fynx_err: FynxError = io_err.into();
        assert!(matches!(fynx_err, FynxError::Io(_)));
    }

    #[test]
    fn test_result_type() {
        fn example() -> FynxResult<i32> {
            Ok(42)
        }

        assert_eq!(example().unwrap(), 42);
    }
}
