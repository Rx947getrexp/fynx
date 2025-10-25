//! SSH authorized_keys file parsing (OpenSSH format).
//!
//! This module provides parsing for OpenSSH authorized_keys files used
//! for public key authentication.
//!
//! # Format
//!
//! Each line in an authorized_keys file has the format:
//! ```text
//! [options] keytype base64-key [comment]
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use fynx_proto::ssh::authorized_keys::AuthorizedKeysFile;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let file = AuthorizedKeysFile::from_file("~/.ssh/authorized_keys")?;
//!
//! for key in file.keys() {
//!     println!("Algorithm: {}", key.algorithm());
//!     println!("Comment: {}", key.comment());
//! }
//! # Ok(())
//! # }
//! ```

use base64::Engine;
use fynx_platform::{FynxError, FynxResult};
use std::path::Path;

/// A single authorized key entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKey {
    /// Key options (e.g., "no-port-forwarding", "command=\"...\"")
    options: Vec<String>,
    /// Algorithm name (e.g., "ssh-ed25519", "ssh-rsa")
    algorithm: String,
    /// Base64-encoded public key data
    key_data: Vec<u8>,
    /// Optional comment
    comment: String,
}

impl AuthorizedKey {
    /// Creates a new authorized key entry.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Key algorithm name
    /// * `key_data` - Base64-decoded key data
    /// * `comment` - Optional comment
    pub fn new(algorithm: String, key_data: Vec<u8>, comment: String) -> Self {
        Self {
            options: Vec::new(),
            algorithm,
            key_data,
            comment,
        }
    }

    /// Creates a new authorized key entry with options.
    pub fn with_options(
        options: Vec<String>,
        algorithm: String,
        key_data: Vec<u8>,
        comment: String,
    ) -> Self {
        Self {
            options,
            algorithm,
            key_data,
            comment,
        }
    }

    /// Returns the key options.
    pub fn options(&self) -> &[String] {
        &self.options
    }

    /// Returns the algorithm name.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the key data (SSH wire format).
    pub fn key_data(&self) -> &[u8] {
        &self.key_data
    }

    /// Returns the comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Checks if this key has a specific option.
    pub fn has_option(&self, option: &str) -> bool {
        self.options.iter().any(|opt| opt == option)
    }

    /// Parses a single line from an authorized_keys file.
    ///
    /// # Format
    ///
    /// ```text
    /// [options] algorithm base64-key [comment]
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fynx_proto::ssh::authorized_keys::AuthorizedKey;
    ///
    /// let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host";
    /// let key = AuthorizedKey::parse_line(line).unwrap();
    /// assert_eq!(key.algorithm(), "ssh-ed25519");
    /// ```
    pub fn parse_line(line: &str) -> FynxResult<Self> {
        // Skip empty lines and comments
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(FynxError::Protocol("Empty or comment line".to_string()));
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(FynxError::Protocol(format!(
                "Invalid authorized_keys line: too few fields"
            )));
        }

        // Check if first field is an option or algorithm
        let (options, algorithm_idx) = if Self::is_key_type(parts[0]) {
            // No options, first field is algorithm
            (Vec::new(), 0)
        } else {
            // First field(s) are options
            let mut opts = Vec::new();
            let mut idx = 0;

            // Collect options until we find a key type
            while idx < parts.len() && !Self::is_key_type(parts[idx]) {
                opts.push(parts[idx].to_string());
                idx += 1;
            }

            if idx >= parts.len() {
                return Err(FynxError::Protocol(
                    "No key type found in authorized_keys line".to_string(),
                ));
            }

            (opts, idx)
        };

        if algorithm_idx + 1 >= parts.len() {
            return Err(FynxError::Protocol(
                "Missing key data in authorized_keys line".to_string(),
            ));
        }

        let algorithm = parts[algorithm_idx].to_string();
        let base64_key = parts[algorithm_idx + 1];

        // Decode base64 key data
        let key_data = base64::engine::general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| FynxError::Protocol(format!("Invalid base64 key data: {}", e)))?;

        // Remaining parts are comment
        let comment = if algorithm_idx + 2 < parts.len() {
            parts[algorithm_idx + 2..].join(" ")
        } else {
            String::new()
        };

        Ok(Self {
            options,
            algorithm,
            key_data,
            comment,
        })
    }

    /// Checks if a string is a recognized SSH key type.
    fn is_key_type(s: &str) -> bool {
        matches!(
            s,
            "ssh-rsa"
                | "rsa-sha2-256"
                | "rsa-sha2-512"
                | "ssh-ed25519"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
                | "ssh-dss"
        )
    }
}

/// Collection of authorized keys.
#[derive(Debug, Clone)]
pub struct AuthorizedKeysFile {
    /// List of authorized keys
    keys: Vec<AuthorizedKey>,
}

impl AuthorizedKeysFile {
    /// Creates a new empty authorized keys file.
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Loads authorized keys from a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to authorized_keys file
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use fynx_proto::ssh::authorized_keys::AuthorizedKeysFile;
    ///
    /// let file = AuthorizedKeysFile::from_file("~/.ssh/authorized_keys")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> FynxResult<Self> {
        let content = std::fs::read_to_string(path).map_err(FynxError::Io)?;
        Self::from_string(&content)
    }

    /// Parses authorized keys from a string.
    ///
    /// # Arguments
    ///
    /// * `content` - File content as string
    pub fn from_string(content: &str) -> FynxResult<Self> {
        let mut keys = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match AuthorizedKey::parse_line(line) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    // Log warning but continue parsing
                    eprintln!("Warning: Failed to parse line {}: {}", line_num + 1, e);
                }
            }
        }

        Ok(Self { keys })
    }

    /// Returns the list of authorized keys.
    pub fn keys(&self) -> &[AuthorizedKey] {
        &self.keys
    }

    /// Adds a key to the collection.
    pub fn add_key(&mut self, key: AuthorizedKey) {
        self.keys.push(key);
    }

    /// Finds a key matching the given algorithm and key data.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Key algorithm name
    /// * `key_data` - Key data to match
    ///
    /// # Returns
    ///
    /// The first matching key, or None if not found.
    pub fn find_key(&self, algorithm: &str, key_data: &[u8]) -> Option<&AuthorizedKey> {
        self.keys
            .iter()
            .find(|key| key.algorithm() == algorithm && key.key_data() == key_data)
    }
}

impl Default for AuthorizedKeysFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_key() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD user@host";
        let key = AuthorizedKey::parse_line(line).unwrap();

        assert_eq!(key.algorithm(), "ssh-ed25519");
        assert_eq!(key.comment(), "user@host");
        assert!(key.options().is_empty());
    }

    #[test]
    fn test_parse_key_without_comment() {
        let line = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/";
        let key = AuthorizedKey::parse_line(line).unwrap();

        assert_eq!(key.algorithm(), "ssh-rsa");
        assert_eq!(key.comment(), "");
    }

    #[test]
    fn test_parse_key_with_options() {
        let line = "no-port-forwarding,command=\"/usr/bin/ls\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD";
        let key = AuthorizedKey::parse_line(line).unwrap();

        assert_eq!(key.algorithm(), "ssh-ed25519");
        assert_eq!(key.options().len(), 1);
        assert!(key.has_option("no-port-forwarding,command=\"/usr/bin/ls\""));
    }

    #[test]
    fn test_parse_comment_line() {
        let line = "# This is a comment";
        let result = AuthorizedKey::parse_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_line() {
        let line = "   ";
        let result = AuthorizedKey::parse_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorized_keys_file() {
        let content = r#"
# Comment line
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD user@host1
        "#;

        let file = AuthorizedKeysFile::from_string(content).unwrap();
        assert_eq!(file.keys().len(), 1);
        assert_eq!(file.keys()[0].algorithm(), "ssh-ed25519");
        assert_eq!(file.keys()[0].comment(), "user@host1");
    }

    #[test]
    fn test_find_key() {
        let content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD user@host";
        let file = AuthorizedKeysFile::from_string(content).unwrap();

        let key_data = base64::engine::general_purpose::STANDARD
            .decode("AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD")
            .unwrap();

        let found = file.find_key("ssh-ed25519", &key_data);
        assert!(found.is_some());
        assert_eq!(found.unwrap().comment(), "user@host");
    }

    #[test]
    fn test_find_key_not_found() {
        let content = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD user@host";
        let file = AuthorizedKeysFile::from_string(content).unwrap();

        let wrong_data = vec![1, 2, 3, 4];
        let found = file.find_key("ssh-ed25519", &wrong_data);
        assert!(found.is_none());
    }
}
