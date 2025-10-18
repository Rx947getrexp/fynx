//! SSH protocol version exchange (RFC 4253 Section 4.2).
//!
//! The SSH protocol begins with a version exchange where both client and server
//! send an identification string:
//!
//! ```text
//! SSH-protoversion-softwareversion SP comments CR LF
//! ```
//!
//! Example: `SSH-2.0-Fynx_0.1.0 OpenSSF compliant SSH implementation`
//!
//! # Security
//!
//! - Maximum line length: 255 characters (DoS prevention)
//! - Must start with "SSH-2.0-" or "SSH-1.99-"
//! - No null bytes allowed in version string
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::version::Version;
//!
//! // Create version string
//! let version = Version::new("Fynx_0.1.0", Some("OpenSSF compliant"));
//! assert_eq!(version.to_string(), "SSH-2.0-Fynx_0.1.0 OpenSSF compliant");
//!
//! // Parse version string
//! let parsed = Version::parse("SSH-2.0-OpenSSH_8.9").unwrap();
//! assert_eq!(parsed.software(), "OpenSSH_8.9");
//! ```

use fynx_platform::{FynxError, FynxResult};

/// Maximum length of SSH version string (RFC 4253 Section 4.2).
pub const MAX_VERSION_LENGTH: usize = 255;

/// SSH protocol version string.
///
/// Represents the SSH identification string exchanged at connection start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Protocol version (e.g., "2.0")
    proto_version: String,
    /// Software version (e.g., "Fynx_0.1.0")
    software_version: String,
    /// Optional comments
    comments: Option<String>,
}

impl Version {
    /// Creates a new SSH version string.
    ///
    /// # Arguments
    ///
    /// * `software` - Software version string (e.g., "Fynx_0.1.0")
    /// * `comments` - Optional comments
    ///
    /// # Returns
    ///
    /// A new `Version` with protocol version "2.0".
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::version::Version;
    ///
    /// let version = Version::new("Fynx_0.1.0", None);
    /// assert_eq!(version.to_string(), "SSH-2.0-Fynx_0.1.0");
    /// ```
    pub fn new(software: &str, comments: Option<&str>) -> Self {
        Self {
            proto_version: "2.0".to_string(),
            software_version: software.to_string(),
            comments: comments.map(String::from),
        }
    }

    /// Returns the default Fynx version string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::version::Version;
    ///
    /// let version = Version::default_fynx();
    /// assert!(version.to_string().starts_with("SSH-2.0-Fynx_"));
    /// ```
    pub fn default_fynx() -> Self {
        Self::new(
            &format!("Fynx_{}", env!("CARGO_PKG_VERSION")),
            Some("OpenSSF compliant SSH implementation"),
        )
    }

    /// Parses an SSH version string.
    ///
    /// # Arguments
    ///
    /// * `line` - The version string line (with or without CR LF)
    ///
    /// # Returns
    ///
    /// A parsed `Version` or an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if:
    /// - Line is too long (> 255 characters)
    /// - Line doesn't start with "SSH-"
    /// - Protocol version is not "2.0" or "1.99"
    /// - Line contains null bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::version::Version;
    ///
    /// let version = Version::parse("SSH-2.0-OpenSSH_8.9\r\n").unwrap();
    /// assert_eq!(version.software(), "OpenSSH_8.9");
    /// ```
    pub fn parse(line: &str) -> FynxResult<Self> {
        // Strip CR LF if present
        let line = line.trim_end_matches("\r\n").trim_end_matches('\n');

        // Check length
        if line.len() > MAX_VERSION_LENGTH {
            return Err(FynxError::Protocol(format!(
                "Version string too long: {} bytes (max {})",
                line.len(),
                MAX_VERSION_LENGTH
            )));
        }

        // Check for null bytes
        if line.contains('\0') {
            return Err(FynxError::Protocol(
                "Version string contains null byte".to_string(),
            ));
        }

        // Must start with "SSH-"
        if !line.starts_with("SSH-") {
            return Err(FynxError::Protocol(format!(
                "Invalid version string: must start with 'SSH-', got '{}'",
                line
            )));
        }

        // Parse: SSH-protoversion-softwareversion[ comments]
        let parts: Vec<&str> = line.splitn(3, '-').collect();
        if parts.len() < 3 {
            return Err(FynxError::Protocol(format!(
                "Invalid version string format: '{}'",
                line
            )));
        }

        let proto_version = parts[1];
        let rest = parts[2];

        // Validate protocol version
        if proto_version != "2.0" && proto_version != "1.99" {
            return Err(FynxError::Protocol(format!(
                "Unsupported protocol version: '{}' (expected '2.0' or '1.99')",
                proto_version
            )));
        }

        // Split software version and comments (space-separated)
        let (software_version, comments) = if let Some(space_pos) = rest.find(' ') {
            let software = rest[..space_pos].to_string();
            let comments = rest[space_pos + 1..].trim().to_string();
            (software, Some(comments))
        } else {
            (rest.to_string(), None)
        };

        Ok(Self {
            proto_version: proto_version.to_string(),
            software_version,
            comments,
        })
    }

    /// Returns the protocol version (e.g., "2.0").
    pub fn proto_version(&self) -> &str {
        &self.proto_version
    }

    /// Returns the software version (e.g., "Fynx_0.1.0").
    pub fn software(&self) -> &str {
        &self.software_version
    }

    /// Returns the comments, if any.
    pub fn comments(&self) -> Option<&str> {
        self.comments.as_deref()
    }

    /// Converts to wire format (with CR LF).
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::version::Version;
    ///
    /// let version = Version::new("Fynx_0.1.0", None);
    /// assert_eq!(version.to_wire_format(), b"SSH-2.0-Fynx_0.1.0\r\n");
    /// ```
    pub fn to_wire_format(&self) -> Vec<u8> {
        format!("{}\r\n", self).into_bytes()
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSH-{}-{}", self.proto_version, self.software_version)?;
        if let Some(comments) = &self.comments {
            write!(f, " {}", comments)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_new() {
        let version = Version::new("Fynx_0.1.0", None);
        assert_eq!(version.proto_version(), "2.0");
        assert_eq!(version.software(), "Fynx_0.1.0");
        assert_eq!(version.comments(), None);
    }

    #[test]
    fn test_version_with_comments() {
        let version = Version::new("Fynx_0.1.0", Some("test comment"));
        assert_eq!(version.comments(), Some("test comment"));
    }

    #[test]
    fn test_version_display() {
        let version = Version::new("Fynx_0.1.0", None);
        assert_eq!(version.to_string(), "SSH-2.0-Fynx_0.1.0");

        let version_with_comments = Version::new("Fynx_0.1.0", Some("OpenSSF compliant"));
        assert_eq!(
            version_with_comments.to_string(),
            "SSH-2.0-Fynx_0.1.0 OpenSSF compliant"
        );
    }

    #[test]
    fn test_version_parse() {
        let version = Version::parse("SSH-2.0-OpenSSH_8.9").unwrap();
        assert_eq!(version.proto_version(), "2.0");
        assert_eq!(version.software(), "OpenSSH_8.9");
        assert_eq!(version.comments(), None);
    }

    #[test]
    fn test_version_parse_with_comments() {
        let version = Version::parse("SSH-2.0-OpenSSH_8.9 Ubuntu-3ubuntu0.1").unwrap();
        assert_eq!(version.software(), "OpenSSH_8.9");
        assert_eq!(version.comments(), Some("Ubuntu-3ubuntu0.1"));
    }

    #[test]
    fn test_version_parse_with_crlf() {
        let version = Version::parse("SSH-2.0-OpenSSH_8.9\r\n").unwrap();
        assert_eq!(version.software(), "OpenSSH_8.9");
    }

    #[test]
    fn test_version_parse_invalid_prefix() {
        let result = Version::parse("INVALID-2.0-Test");
        assert!(result.is_err());
        assert!(matches!(result, Err(FynxError::Protocol(_))));
    }

    #[test]
    fn test_version_parse_unsupported_protocol() {
        let result = Version::parse("SSH-1.0-OldClient");
        assert!(result.is_err());
        match result {
            Err(FynxError::Protocol(msg)) => {
                assert!(msg.contains("Unsupported protocol version"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_version_parse_too_long() {
        let long_string = format!("SSH-2.0-{}", "A".repeat(300));
        let result = Version::parse(&long_string);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_parse_null_byte() {
        let result = Version::parse("SSH-2.0-Test\0Bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_version_wire_format() {
        let version = Version::new("Fynx_0.1.0", None);
        assert_eq!(version.to_wire_format(), b"SSH-2.0-Fynx_0.1.0\r\n");
    }

    #[test]
    fn test_version_round_trip() {
        let original = Version::new("Fynx_0.1.0", Some("test"));
        let wire = original.to_string();
        let parsed = Version::parse(&wire).unwrap();
        assert_eq!(parsed.software(), original.software());
        assert_eq!(parsed.comments(), original.comments());
    }
}
