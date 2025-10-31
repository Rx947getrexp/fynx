//! Error types for IPSec protocol operations
//!
//! This module defines a unified error type for all IPSec operations,
//! covering IKEv2 and ESP protocols.

use std::fmt;

/// Result type for IPSec operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error codes for programmatic handling
///
/// Provides stable error codes that can be used for programmatic error handling,
/// logging, and monitoring. Error codes are grouped by category (1000s = protocol,
/// 2000s = crypto, 3000s = state, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // Protocol errors (1000-1999)
    /// Invalid message format (1001)
    InvalidMessage = 1001,
    /// Invalid payload (1002)
    InvalidPayload = 1002,
    /// Unsupported version (1003)
    UnsupportedVersion = 1003,
    /// No proposal chosen (1004)
    NoProposalChosen = 1004,
    /// Invalid syntax (1005)
    InvalidSyntax = 1005,

    // Crypto errors (2000-2999)
    /// Authentication failed (2001)
    AuthenticationFailed = 2001,
    /// Cryptographic operation failed (2002)
    CryptoError = 2002,
    /// Invalid key length (2003)
    InvalidKeyLength = 2003,

    // State errors (3000-3999)
    /// Invalid state (3001)
    InvalidState = 3001,
    /// Invalid state transition (3002)
    InvalidStateTransition = 3002,
    /// Security Association not found (3003)
    SaNotFound = 3003,

    // Security errors (4000-4999)
    /// Replay attack detected (4001)
    ReplayDetected = 4001,

    // Network errors (5000-5999)
    /// Network I/O error (5001)
    NetworkError = 5001,
    /// Network timeout (5002)
    NetworkTimeout = 5002,

    // Internal errors (9000-9999)
    /// Internal error (9001)
    InternalError = 9001,
}

impl ErrorCode {
    /// Get error code as u32
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Get error code category name
    pub fn category(self) -> &'static str {
        match self {
            ErrorCode::InvalidMessage
            | ErrorCode::InvalidPayload
            | ErrorCode::UnsupportedVersion
            | ErrorCode::NoProposalChosen
            | ErrorCode::InvalidSyntax => "Protocol",

            ErrorCode::AuthenticationFailed
            | ErrorCode::CryptoError
            | ErrorCode::InvalidKeyLength => "Crypto",

            ErrorCode::InvalidState
            | ErrorCode::InvalidStateTransition
            | ErrorCode::SaNotFound => "State",

            ErrorCode::ReplayDetected => "Security",

            ErrorCode::NetworkError | ErrorCode::NetworkTimeout => "Network",

            ErrorCode::InternalError => "Internal",
        }
    }
}

/// IPSec protocol errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid IKEv2 message format
    InvalidMessage(String),

    /// Invalid IKEv2 payload
    InvalidPayload(String),

    /// Invalid parameter value
    InvalidParameter(String),

    /// Unsupported protocol version
    UnsupportedVersion(u8),

    /// Unsupported exchange type
    UnsupportedExchangeType(u8),

    /// No acceptable proposal found
    NoProposalChosen,

    /// Invalid proposal
    InvalidProposal(String),

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

    /// Invalid state transition
    InvalidStateTransition {
        /// Current state
        from: String,
        /// Target state
        to: String,
    },

    /// Missing required payload
    MissingPayload(String),

    /// Invalid exchange type
    InvalidExchangeType,

    /// Invalid message ID
    InvalidMessageId {
        /// Expected message ID
        expected: u32,
        /// Received message ID
        received: u32,
    },

    /// Invalid key length
    InvalidKeyLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Invalid IV length
    InvalidIvLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

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
            Error::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Error::UnsupportedVersion(v) => {
                write!(f, "Unsupported IKE version: 0x{:02x}", v)
            }
            Error::UnsupportedExchangeType(t) => {
                write!(f, "Unsupported exchange type: {}", t)
            }
            Error::NoProposalChosen => {
                write!(f, "No acceptable proposal found in negotiation")
            }
            Error::InvalidProposal(msg) => {
                write!(f, "Invalid proposal: {}", msg)
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
                write!(f, "Invalid length: expected {}, got {}", expected, actual)
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
            Error::InvalidStateTransition { from, to } => {
                write!(f, "Invalid state transition from {} to {}", from, to)
            }
            Error::MissingPayload(name) => write!(f, "Missing required payload: {}", name),
            Error::InvalidExchangeType => write!(f, "Invalid exchange type"),
            Error::InvalidMessageId { expected, received } => {
                write!(
                    f,
                    "Invalid message ID: expected {}, received {}",
                    expected, received
                )
            }
            Error::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Error::InvalidIvLength { expected, actual } => {
                write!(
                    f,
                    "Invalid IV length: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Get error code for programmatic handling
    ///
    /// Returns a stable error code that can be used for:
    /// - Programmatic error handling
    /// - Monitoring and alerting
    /// - Error categorization
    ///
    /// # Returns
    ///
    /// `Some(ErrorCode)` if this error has a defined code, `None` otherwise.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Error::InvalidMessage(_) => Some(ErrorCode::InvalidMessage),
            Error::InvalidPayload(_) => Some(ErrorCode::InvalidPayload),
            Error::InvalidParameter(_) => Some(ErrorCode::InvalidSyntax),
            Error::UnsupportedVersion(_) => Some(ErrorCode::UnsupportedVersion),
            Error::UnsupportedExchangeType(_) => Some(ErrorCode::InvalidSyntax),
            Error::NoProposalChosen => Some(ErrorCode::NoProposalChosen),
            Error::InvalidProposal(_) => Some(ErrorCode::InvalidSyntax),
            Error::AuthenticationFailed(_) => Some(ErrorCode::AuthenticationFailed),
            Error::SaNotFound(_) => Some(ErrorCode::SaNotFound),
            Error::CryptoError(_) => Some(ErrorCode::CryptoError),
            Error::ReplayDetected(_) => Some(ErrorCode::ReplayDetected),
            Error::InvalidState(_) => Some(ErrorCode::InvalidState),
            Error::InvalidStateTransition { .. } => Some(ErrorCode::InvalidStateTransition),
            Error::InvalidKeyLength { .. } => Some(ErrorCode::InvalidKeyLength),
            Error::Io(_) => Some(ErrorCode::NetworkError),
            Error::Internal(_) => Some(ErrorCode::InternalError),
            _ => None,
        }
    }

    /// Add context to error message
    ///
    /// Wraps the error with additional context information.
    /// Useful for adding operation context to errors propagated from lower layers.
    ///
    /// # Arguments
    ///
    /// * `context` - Context description
    ///
    /// # Returns
    ///
    /// New error with context prepended to the message.
    ///
    /// # Example
    ///
    /// ```
    /// use fynx_proto::ipsec::error::Error;
    ///
    /// let err = Error::CryptoError("invalid key".to_string());
    /// let err_with_context = err.with_context("ESP encryption");
    ///
    /// assert_eq!(
    ///     err_with_context.to_string(),
    ///     "Cryptographic error: ESP encryption: invalid key"
    /// );
    /// ```
    pub fn with_context(self, context: &str) -> Self {
        match self {
            Error::InvalidMessage(msg) => {
                Error::InvalidMessage(format!("{}: {}", context, msg))
            }
            Error::InvalidPayload(msg) => Error::InvalidPayload(format!("{}: {}", context, msg)),
            Error::InvalidParameter(msg) => {
                Error::InvalidParameter(format!("{}: {}", context, msg))
            }
            Error::InvalidProposal(msg) => {
                Error::InvalidProposal(format!("{}: {}", context, msg))
            }
            Error::AuthenticationFailed(msg) => {
                Error::AuthenticationFailed(format!("{}: {}", context, msg))
            }
            Error::SaNotFound(msg) => Error::SaNotFound(format!("{}: {}", context, msg)),
            Error::CryptoError(msg) => Error::CryptoError(format!("{}: {}", context, msg)),
            Error::InvalidState(msg) => Error::InvalidState(format!("{}: {}", context, msg)),
            Error::MissingPayload(msg) => Error::MissingPayload(format!("{}: {}", context, msg)),
            Error::Io(msg) => Error::Io(format!("{}: {}", context, msg)),
            Error::Internal(msg) => Error::Internal(format!("{}: {}", context, msg)),
            // For other variants, leave as-is (they have structured data, not just messages)
            other => other,
        }
    }

    /// Check if error is retryable
    ///
    /// Returns `true` if this error represents a transient condition
    /// that may succeed on retry.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Io(_) | Error::CryptoError(_))
    }

    /// Check if error is fatal
    ///
    /// Returns `true` if this error indicates an unrecoverable condition.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::AuthenticationFailed(_)
                | Error::InvalidState(_)
                | Error::InvalidStateTransition { .. }
        )
    }
}

// Convert from std::io::Error
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

/// Error Recovery Action
///
/// Defines what action to take when an error occurs.
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryAction {
    /// Retry the operation with specified policy
    Retry {
        /// Maximum retry attempts
        max_attempts: u32,
        /// Base delay between retries
        base_delay: std::time::Duration,
    },

    /// Send NOTIFY error to peer
    NotifyPeer {
        /// Notify message type
        notify_type: u16,
    },

    /// Delete the Security Association
    DeleteSa,

    /// Reset connection (restart IKE_SA_INIT)
    Reset,

    /// Ignore the error (log and continue)
    Ignore,

    /// Fail immediately (propagate error)
    Fail,
}

/// Retry Policy
///
/// Configures automatic retry behavior with exponential backoff.
///
/// # Example
///
/// ```rust,ignore
/// use fynx_proto::ipsec::error::RetryPolicy;
/// use std::time::Duration;
///
/// let policy = RetryPolicy::new(3, Duration::from_secs(1), 2.0, Duration::from_secs(60));
///
/// // Check if should retry
/// assert!(policy.should_retry(0));
/// assert!(policy.should_retry(1));
/// assert!(policy.should_retry(2));
/// assert!(!policy.should_retry(3)); // Max attempts reached
///
/// // Get retry delay (exponential backoff)
/// assert_eq!(policy.get_delay(0), Duration::from_secs(1));  // 1s
/// assert_eq!(policy.get_delay(1), Duration::from_secs(2));  // 2s
/// assert_eq!(policy.get_delay(2), Duration::from_secs(4));  // 4s
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicy {
    /// Maximum retry attempts (0 = no retries)
    max_attempts: u32,

    /// Base delay between retries
    base_delay: std::time::Duration,

    /// Exponential backoff multiplier
    ///
    /// Each retry delay = base_delay * (multiplier ^ attempt)
    /// Typical values: 2.0 (exponential doubling)
    backoff_multiplier: f32,

    /// Maximum delay cap
    ///
    /// Prevents delays from growing too large
    max_delay: std::time::Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base_delay: std::time::Duration::from_secs(1),
            backoff_multiplier: 2.0,
            max_delay: std::time::Duration::from_secs(60),
        }
    }
}

impl RetryPolicy {
    /// Create new retry policy
    ///
    /// # Arguments
    ///
    /// * `max_attempts` - Maximum retry attempts
    /// * `base_delay` - Initial delay between retries
    /// * `backoff_multiplier` - Exponential backoff multiplier (e.g., 2.0)
    /// * `max_delay` - Maximum delay cap
    pub fn new(
        max_attempts: u32,
        base_delay: std::time::Duration,
        backoff_multiplier: f32,
        max_delay: std::time::Duration,
    ) -> Self {
        RetryPolicy {
            max_attempts,
            base_delay,
            backoff_multiplier,
            max_delay,
        }
    }

    /// Create no-retry policy
    pub fn no_retry() -> Self {
        RetryPolicy {
            max_attempts: 0,
            base_delay: std::time::Duration::from_secs(0),
            backoff_multiplier: 1.0,
            max_delay: std::time::Duration::from_secs(0),
        }
    }

    /// Check if should retry given attempt number
    ///
    /// # Arguments
    ///
    /// * `attempt` - Current attempt number (0-based)
    ///
    /// # Returns
    ///
    /// `true` if attempt < max_attempts
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }

    /// Get retry delay for given attempt
    ///
    /// Uses exponential backoff: `delay = base_delay * (multiplier ^ attempt)`
    ///
    /// # Arguments
    ///
    /// * `attempt` - Current attempt number (0-based)
    ///
    /// # Returns
    ///
    /// Delay duration, capped at max_delay
    pub fn get_delay(&self, attempt: u32) -> std::time::Duration {
        if self.max_attempts == 0 {
            return std::time::Duration::from_secs(0);
        }

        // Calculate exponential backoff: base * (multiplier ^ attempt)
        let multiplier_pow = self.backoff_multiplier.powi(attempt as i32);
        let delay_secs = self.base_delay.as_secs_f32() * multiplier_pow;

        let delay = std::time::Duration::from_secs_f32(delay_secs);

        // Cap at max_delay
        if delay > self.max_delay {
            self.max_delay
        } else {
            delay
        }
    }

    /// Get maximum attempts
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Get base delay
    pub fn base_delay(&self) -> std::time::Duration {
        self.base_delay
    }

    /// Get backoff multiplier
    pub fn backoff_multiplier(&self) -> f32 {
        self.backoff_multiplier
    }

    /// Get maximum delay
    pub fn max_delay(&self) -> std::time::Duration {
        self.max_delay
    }
}

/// Error Handler
///
/// Maps error types to recovery actions.
#[derive(Debug, Clone)]
pub struct ErrorHandler {
    /// Default recovery action
    default_action: RecoveryAction,

    /// Default retry policy
    default_retry: RetryPolicy,
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorHandler {
    /// Create new error handler with default policies
    pub fn new() -> Self {
        ErrorHandler {
            default_action: RecoveryAction::Fail,
            default_retry: RetryPolicy::default(),
        }
    }

    /// Create error handler with custom default action
    pub fn with_default_action(action: RecoveryAction) -> Self {
        ErrorHandler {
            default_action: action,
            default_retry: RetryPolicy::default(),
        }
    }

    /// Handle error and determine recovery action
    ///
    /// # Arguments
    ///
    /// * `error` - The error to handle
    ///
    /// # Returns
    ///
    /// Appropriate recovery action for the error type
    pub fn handle_error(&self, error: &Error) -> RecoveryAction {
        match error {
            // Transient errors - retry
            Error::Io(_) | Error::CryptoError(_) => RecoveryAction::Retry {
                max_attempts: self.default_retry.max_attempts(),
                base_delay: self.default_retry.base_delay(),
            },

            // Protocol errors - notify peer
            Error::InvalidMessage(_)
            | Error::InvalidPayload(_)
            | Error::InvalidParameter(_)
            | Error::UnsupportedVersion(_)
            | Error::UnsupportedExchangeType(_) => RecoveryAction::NotifyPeer { notify_type: 7 }, // INVALID_SYNTAX

            // Authentication errors - delete SA
            Error::AuthenticationFailed(_) => RecoveryAction::DeleteSa,

            // Replay attacks - ignore (already handled)
            Error::ReplayDetected(_) => RecoveryAction::Ignore,

            // State errors - depends on severity
            Error::InvalidState(_) | Error::InvalidStateTransition { .. } => {
                RecoveryAction::DeleteSa
            }

            // Missing SA - ignore (may be already deleted)
            Error::SaNotFound(_) => RecoveryAction::Ignore,

            // No proposal chosen - notify peer
            Error::NoProposalChosen => RecoveryAction::NotifyPeer { notify_type: 14 }, // NO_PROPOSAL_CHOSEN

            // All other errors - use default
            _ => self.default_action.clone(),
        }
    }

    /// Get default retry policy
    pub fn default_retry_policy(&self) -> &RetryPolicy {
        &self.default_retry
    }

    /// Set default retry policy
    pub fn set_default_retry_policy(&mut self, policy: RetryPolicy) {
        self.default_retry = policy;
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

    // Recovery Action tests

    #[test]
    fn test_recovery_action_retry() {
        let action = RecoveryAction::Retry {
            max_attempts: 3,
            base_delay: std::time::Duration::from_secs(1),
        };
        assert!(matches!(action, RecoveryAction::Retry { .. }));
    }

    #[test]
    fn test_recovery_action_notify_peer() {
        let action = RecoveryAction::NotifyPeer { notify_type: 7 };
        assert!(matches!(action, RecoveryAction::NotifyPeer { .. }));
    }

    // RetryPolicy tests

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts(), 3);
        assert_eq!(policy.base_delay(), std::time::Duration::from_secs(1));
        assert_eq!(policy.backoff_multiplier(), 2.0);
        assert_eq!(policy.max_delay(), std::time::Duration::from_secs(60));
    }

    #[test]
    fn test_retry_policy_new() {
        let policy = RetryPolicy::new(
            5,
            std::time::Duration::from_secs(2),
            1.5,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(policy.max_attempts(), 5);
        assert_eq!(policy.base_delay(), std::time::Duration::from_secs(2));
        assert_eq!(policy.backoff_multiplier(), 1.5);
        assert_eq!(policy.max_delay(), std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_retry_policy_no_retry() {
        let policy = RetryPolicy::no_retry();
        assert_eq!(policy.max_attempts(), 0);
        assert!(!policy.should_retry(0));
    }

    #[test]
    fn test_retry_policy_should_retry() {
        let policy = RetryPolicy::new(
            3,
            std::time::Duration::from_secs(1),
            2.0,
            std::time::Duration::from_secs(60),
        );

        assert!(policy.should_retry(0));
        assert!(policy.should_retry(1));
        assert!(policy.should_retry(2));
        assert!(!policy.should_retry(3)); // Max attempts reached
        assert!(!policy.should_retry(4));
    }

    #[test]
    fn test_retry_policy_get_delay_exponential() {
        let policy = RetryPolicy::new(
            5,
            std::time::Duration::from_secs(1),
            2.0,
            std::time::Duration::from_secs(100),
        );

        // Exponential backoff: 1, 2, 4, 8, 16 seconds
        assert_eq!(policy.get_delay(0), std::time::Duration::from_secs(1));
        assert_eq!(policy.get_delay(1), std::time::Duration::from_secs(2));
        assert_eq!(policy.get_delay(2), std::time::Duration::from_secs(4));
        assert_eq!(policy.get_delay(3), std::time::Duration::from_secs(8));
        assert_eq!(policy.get_delay(4), std::time::Duration::from_secs(16));
    }

    #[test]
    fn test_retry_policy_get_delay_capped() {
        let policy = RetryPolicy::new(
            10,
            std::time::Duration::from_secs(1),
            2.0,
            std::time::Duration::from_secs(10),
        );

        // Should cap at max_delay (10 seconds)
        assert_eq!(policy.get_delay(0), std::time::Duration::from_secs(1));
        assert_eq!(policy.get_delay(1), std::time::Duration::from_secs(2));
        assert_eq!(policy.get_delay(2), std::time::Duration::from_secs(4));
        assert_eq!(policy.get_delay(3), std::time::Duration::from_secs(8));
        assert_eq!(policy.get_delay(4), std::time::Duration::from_secs(10)); // Capped
        assert_eq!(policy.get_delay(5), std::time::Duration::from_secs(10)); // Capped
    }

    #[test]
    fn test_retry_policy_get_delay_no_retry() {
        let policy = RetryPolicy::no_retry();
        assert_eq!(policy.get_delay(0), std::time::Duration::from_secs(0));
        assert_eq!(policy.get_delay(1), std::time::Duration::from_secs(0));
    }

    // ErrorHandler tests

    #[test]
    fn test_error_handler_new() {
        let handler = ErrorHandler::new();
        assert!(matches!(
            handler.handle_error(&Error::Internal("test".into())),
            RecoveryAction::Fail
        ));
    }

    #[test]
    fn test_error_handler_with_default_action() {
        let handler = ErrorHandler::with_default_action(RecoveryAction::Ignore);
        assert!(matches!(
            handler.handle_error(&Error::Internal("test".into())),
            RecoveryAction::Ignore
        ));
    }

    #[test]
    fn test_error_handler_transient_errors() {
        let handler = ErrorHandler::new();

        // I/O errors should retry
        let action = handler.handle_error(&Error::Io("network error".into()));
        assert!(matches!(action, RecoveryAction::Retry { .. }));

        // Crypto errors should retry
        let action = handler.handle_error(&Error::CryptoError("hash failed".into()));
        assert!(matches!(action, RecoveryAction::Retry { .. }));
    }

    #[test]
    fn test_error_handler_protocol_errors() {
        let handler = ErrorHandler::new();

        // Protocol errors should notify peer
        let action = handler.handle_error(&Error::InvalidMessage("bad format".into()));
        assert!(matches!(
            action,
            RecoveryAction::NotifyPeer { notify_type: 7 }
        ));

        let action = handler.handle_error(&Error::UnsupportedVersion(99));
        assert!(matches!(action, RecoveryAction::NotifyPeer { .. }));
    }

    #[test]
    fn test_error_handler_authentication_errors() {
        let handler = ErrorHandler::new();

        let action = handler.handle_error(&Error::AuthenticationFailed("bad sig".into()));
        assert!(matches!(action, RecoveryAction::DeleteSa));
    }

    #[test]
    fn test_error_handler_replay_attacks() {
        let handler = ErrorHandler::new();

        let action = handler.handle_error(&Error::ReplayDetected(12345));
        assert!(matches!(action, RecoveryAction::Ignore));
    }

    #[test]
    fn test_error_handler_state_errors() {
        let handler = ErrorHandler::new();

        let action = handler.handle_error(&Error::InvalidState("bad state".into()));
        assert!(matches!(action, RecoveryAction::DeleteSa));

        let action = handler.handle_error(&Error::InvalidStateTransition {
            from: "Idle".into(),
            to: "Established".into(),
        });
        assert!(matches!(action, RecoveryAction::DeleteSa));
    }

    #[test]
    fn test_error_handler_sa_not_found() {
        let handler = ErrorHandler::new();

        let action = handler.handle_error(&Error::SaNotFound("SA-123".into()));
        assert!(matches!(action, RecoveryAction::Ignore));
    }

    #[test]
    fn test_error_handler_no_proposal_chosen() {
        let handler = ErrorHandler::new();

        let action = handler.handle_error(&Error::NoProposalChosen);
        assert!(matches!(
            action,
            RecoveryAction::NotifyPeer { notify_type: 14 }
        ));
    }

    #[test]
    fn test_error_handler_set_retry_policy() {
        let mut handler = ErrorHandler::new();

        let custom_policy = RetryPolicy::new(
            5,
            std::time::Duration::from_secs(2),
            1.5,
            std::time::Duration::from_secs(30),
        );

        handler.set_default_retry_policy(custom_policy.clone());
        assert_eq!(handler.default_retry_policy(), &custom_policy);
    }

    // ErrorCode tests

    #[test]
    fn test_error_code_values() {
        assert_eq!(ErrorCode::InvalidMessage as u32, 1001);
        assert_eq!(ErrorCode::AuthenticationFailed as u32, 2001);
        assert_eq!(ErrorCode::InvalidState as u32, 3001);
        assert_eq!(ErrorCode::ReplayDetected as u32, 4001);
        assert_eq!(ErrorCode::NetworkError as u32, 5001);
        assert_eq!(ErrorCode::InternalError as u32, 9001);
    }

    #[test]
    fn test_error_code_as_u32() {
        assert_eq!(ErrorCode::InvalidMessage.as_u32(), 1001);
        assert_eq!(ErrorCode::NoProposalChosen.as_u32(), 1004);
    }

    #[test]
    fn test_error_code_category() {
        assert_eq!(ErrorCode::InvalidMessage.category(), "Protocol");
        assert_eq!(ErrorCode::AuthenticationFailed.category(), "Crypto");
        assert_eq!(ErrorCode::InvalidState.category(), "State");
        assert_eq!(ErrorCode::ReplayDetected.category(), "Security");
        assert_eq!(ErrorCode::NetworkError.category(), "Network");
        assert_eq!(ErrorCode::InternalError.category(), "Internal");
    }

    // Error::code() tests

    #[test]
    fn test_error_code_mapping() {
        assert_eq!(
            Error::InvalidMessage("test".into()).code(),
            Some(ErrorCode::InvalidMessage)
        );
        assert_eq!(
            Error::AuthenticationFailed("bad auth".into()).code(),
            Some(ErrorCode::AuthenticationFailed)
        );
        assert_eq!(
            Error::NoProposalChosen.code(),
            Some(ErrorCode::NoProposalChosen)
        );
        assert_eq!(
            Error::ReplayDetected(123).code(),
            Some(ErrorCode::ReplayDetected)
        );
        assert_eq!(
            Error::Io("timeout".into()).code(),
            Some(ErrorCode::NetworkError)
        );
    }

    #[test]
    fn test_error_code_none_for_some_variants() {
        // Some error variants don't have codes
        assert!(Error::MessageTooLarge(1000).code().is_some() == false);
        assert!(Error::InvalidSpi(123).code().is_some() == false);
    }

    // Error::with_context() tests

    #[test]
    fn test_error_with_context() {
        let err = Error::CryptoError("invalid key".to_string());
        let err_with_context = err.with_context("ESP encryption");

        assert_eq!(
            err_with_context.to_string(),
            "Cryptographic error: ESP encryption: invalid key"
        );
    }

    #[test]
    fn test_error_with_context_multiple() {
        let err = Error::InvalidMessage("bad format".to_string());
        let err1 = err.with_context("IKE_SA_INIT");
        let err2 = err1.with_context("handshake");

        assert!(err2
            .to_string()
            .contains("handshake: IKE_SA_INIT: bad format"));
    }

    #[test]
    fn test_error_with_context_structured() {
        // Structured errors (non-string) should return unchanged
        let err = Error::InvalidLength {
            expected: 10,
            actual: 5,
        };
        let err_with_context = err.clone().with_context("test");

        assert_eq!(err, err_with_context);
    }

    // Error::is_retryable() tests

    #[test]
    fn test_error_is_retryable() {
        assert!(Error::Io("timeout".into()).is_retryable());
        assert!(Error::CryptoError("hash failed".into()).is_retryable());

        assert!(!Error::AuthenticationFailed("bad sig".into()).is_retryable());
        assert!(!Error::InvalidState("bad state".into()).is_retryable());
        assert!(!Error::NoProposalChosen.is_retryable());
    }

    // Error::is_fatal() tests

    #[test]
    fn test_error_is_fatal() {
        assert!(Error::AuthenticationFailed("bad auth".into()).is_fatal());
        assert!(Error::InvalidState("bad state".into()).is_fatal());
        assert!(Error::InvalidStateTransition {
            from: "A".into(),
            to: "B".into()
        }
        .is_fatal());

        assert!(!Error::Io("timeout".into()).is_fatal());
        assert!(!Error::NoProposalChosen.is_fatal());
        assert!(!Error::ReplayDetected(123).is_fatal());
    }
}
