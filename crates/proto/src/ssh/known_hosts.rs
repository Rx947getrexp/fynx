//! SSH known_hosts file support (OpenSSH format).
//!
//! This module provides parsing and verification for OpenSSH known_hosts files
//! used for host key verification and MITM attack prevention.
//!
//! # Format
//!
//! Each line in a known_hosts file has the format:
//! ```text
//! [hostnames] keytype base64-key [comment]
//! ```
//!
//! Hostnames can be:
//! - Standard: `example.com` or `[example.com]:2222`
//! - Hashed: `|1|salt|hash` (HMAC-SHA1 hashed hostname)
//! - Wildcard: `*.example.com`
//! - Multiple: `host1,host2,host3`
//! - Negated: `*.example.com,!bad.example.com`
//!
//! # Example
//!
//! ```rust,no_run
//! use fynx_proto::ssh::known_hosts::{KnownHostsFile, StrictHostKeyChecking};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load known_hosts file
//! let known_hosts = KnownHostsFile::from_file("~/.ssh/known_hosts")?;
//!
//! // Verify a host key
//! let status = known_hosts.verify_host_key(
//!     "example.com",
//!     22,
//!     "ssh-ed25519",
//!     &key_data,
//! );
//!
//! match status {
//!     HostKeyStatus::Known => println!("Host key verified"),
//!     HostKeyStatus::Changed { .. } => println!("WARNING: Host key changed!"),
//!     HostKeyStatus::Unknown => println!("Unknown host"),
//! }
//! # Ok(())
//! # }
//! ```

use base64::Engine;
use fynx_platform::{FynxError, FynxResult};
use std::path::{Path, PathBuf};

/// A single known_hosts entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    /// Hostname pattern (standard, hashed, or wildcard)
    hostname_pattern: String,
    /// Key type (e.g., "ssh-ed25519", "ssh-rsa")
    key_type: String,
    /// Public key data (SSH wire format)
    key_data: Vec<u8>,
    /// Optional comment
    comment: String,
}

impl KnownHost {
    /// Creates a new known host entry.
    ///
    /// # Arguments
    ///
    /// * `hostname_pattern` - Hostname pattern
    /// * `key_type` - Key algorithm name
    /// * `key_data` - Public key data
    pub fn new(hostname_pattern: String, key_type: String, key_data: Vec<u8>) -> Self {
        Self {
            hostname_pattern,
            key_type,
            key_data,
            comment: String::new(),
        }
    }

    /// Creates a new known host entry with a comment.
    pub fn with_comment(
        hostname_pattern: String,
        key_type: String,
        key_data: Vec<u8>,
        comment: String,
    ) -> Self {
        Self {
            hostname_pattern,
            key_type,
            key_data,
            comment,
        }
    }

    /// Returns the hostname pattern.
    pub fn hostname_pattern(&self) -> &str {
        &self.hostname_pattern
    }

    /// Returns the key type.
    pub fn key_type(&self) -> &str {
        &self.key_type
    }

    /// Returns the key data.
    pub fn key_data(&self) -> &[u8] {
        &self.key_data
    }

    /// Returns the comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Checks if this entry matches a hostname and port.
    ///
    /// Supports:
    /// - Standard matching: `example.com`
    /// - Hashed matching: `|1|salt|hash`
    /// - Wildcard matching: `*.example.com`
    /// - Port matching: `[example.com]:2222`
    pub fn matches(&self, hostname: &str, port: u16) -> FynxResult<bool> {
        // Build full hostname with port if not default
        let full_host = if port == 22 {
            hostname.to_string()
        } else {
            format!("[{}]:{}", hostname, port)
        };

        // Split multiple hostnames (comma-separated)
        for pattern in self.hostname_pattern.split(',') {
            let pattern = pattern.trim();

            // Handle negation (!host)
            if pattern.starts_with('!') {
                let neg_pattern = &pattern[1..];
                if Self::matches_pattern(neg_pattern, &full_host)? {
                    return Ok(false); // Negation matched, this entry doesn't apply
                }
                continue;
            }

            // Try to match this pattern
            if Self::matches_pattern(pattern, &full_host)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Matches a single pattern against a hostname.
    fn matches_pattern(pattern: &str, hostname: &str) -> FynxResult<bool> {
        // Hashed hostname format: |1|salt|hash
        if pattern.starts_with("|1|") {
            return Self::verify_hashed_hostname(pattern, hostname);
        }

        // Wildcard matching
        if pattern.contains('*') || pattern.contains('?') {
            return Ok(Self::wildcard_match(pattern, hostname));
        }

        // Standard exact match
        Ok(pattern == hostname)
    }

    /// Verifies a hashed hostname using HMAC-SHA1.
    ///
    /// Format: |1|salt|hash
    /// Where hash = Base64(HMAC-SHA1(salt, hostname))
    fn verify_hashed_hostname(hashed: &str, hostname: &str) -> FynxResult<bool> {
        let parts: Vec<&str> = hashed.split('|').collect();

        // Validate format: |1|salt|hash
        if parts.len() != 4 || !parts[0].is_empty() || parts[1] != "1" {
            return Ok(false);
        }

        // Decode salt and expected hash
        let salt = base64::engine::general_purpose::STANDARD
            .decode(parts[2])
            .map_err(|e| FynxError::Protocol(format!("Invalid base64 salt: {}", e)))?;

        let expected_hash = base64::engine::general_purpose::STANDARD
            .decode(parts[3])
            .map_err(|e| FynxError::Protocol(format!("Invalid base64 hash: {}", e)))?;

        // Compute HMAC-SHA1(salt, hostname)
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let mut hmac = HmacSha1::new_from_slice(&salt)
            .map_err(|e| FynxError::Protocol(format!("HMAC creation failed: {}", e)))?;

        hmac.update(hostname.as_bytes());
        let computed_hash = hmac.finalize().into_bytes();

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        Ok(computed_hash.ct_eq(&expected_hash[..]).into())
    }

    /// Simple wildcard matching (* and ?).
    ///
    /// - `*` matches any number of characters
    /// - `?` matches exactly one character
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let text_chars: Vec<char> = text.chars().collect();

        Self::wildcard_match_impl(&pattern_chars, &text_chars, 0, 0)
    }

    /// Recursive wildcard matching implementation.
    fn wildcard_match_impl(
        pattern: &[char],
        text: &[char],
        p_idx: usize,
        t_idx: usize,
    ) -> bool {
        // Both exhausted - match
        if p_idx == pattern.len() && t_idx == text.len() {
            return true;
        }

        // Pattern exhausted but text remains - no match
        if p_idx == pattern.len() {
            return false;
        }

        // Handle wildcard '*'
        if pattern[p_idx] == '*' {
            // Try matching zero characters
            if Self::wildcard_match_impl(pattern, text, p_idx + 1, t_idx) {
                return true;
            }

            // Try matching one or more characters
            if t_idx < text.len() {
                return Self::wildcard_match_impl(pattern, text, p_idx, t_idx + 1);
            }

            return false;
        }

        // Text exhausted - no match
        if t_idx == text.len() {
            return false;
        }

        // Handle single character wildcard '?'
        if pattern[p_idx] == '?' {
            return Self::wildcard_match_impl(pattern, text, p_idx + 1, t_idx + 1);
        }

        // Exact character match
        if pattern[p_idx] == text[t_idx] {
            return Self::wildcard_match_impl(pattern, text, p_idx + 1, t_idx + 1);
        }

        false
    }

    /// Parses a single line from a known_hosts file.
    ///
    /// Format: `hostname keytype base64-key [comment]`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use fynx_proto::ssh::known_hosts::KnownHost;
    ///
    /// let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host";
    /// let entry = KnownHost::parse_line(line).unwrap();
    /// assert_eq!(entry.hostname_pattern(), "example.com");
    /// assert_eq!(entry.key_type(), "ssh-ed25519");
    /// ```
    pub fn parse_line(line: &str) -> FynxResult<Self> {
        // Skip empty lines and comments
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(FynxError::Protocol("Empty or comment line".to_string()));
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(FynxError::Protocol(format!(
                "Invalid known_hosts line: too few fields (need at least 3)"
            )));
        }

        let hostname_pattern = parts[0].to_string();
        let key_type = parts[1].to_string();
        let base64_key = parts[2];

        // Decode base64 key data
        let key_data = base64::engine::general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| FynxError::Protocol(format!("Invalid base64 key data: {}", e)))?;

        // Remaining parts are comment
        let comment = if parts.len() > 3 {
            parts[3..].join(" ")
        } else {
            String::new()
        };

        Ok(Self {
            hostname_pattern,
            key_type,
            key_data,
            comment,
        })
    }
}

/// Collection of known hosts.
#[derive(Debug, Clone)]
pub struct KnownHostsFile {
    /// List of known host entries
    entries: Vec<KnownHost>,
    /// File path (for saving)
    path: PathBuf,
}

impl KnownHostsFile {
    /// Creates a new empty known_hosts file.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            entries: Vec::new(),
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Loads known_hosts from a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to known_hosts file
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use fynx_proto::ssh::known_hosts::KnownHostsFile;
    ///
    /// let known_hosts = KnownHostsFile::from_file("~/.ssh/known_hosts")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> FynxResult<Self> {
        let path_ref = path.as_ref();

        // If file doesn't exist, return empty file
        if !path_ref.exists() {
            return Ok(Self::new(path_ref));
        }

        let content = std::fs::read_to_string(path_ref).map_err(FynxError::Io)?;
        let mut file = Self::from_string(&content)?;
        file.path = path_ref.to_path_buf();

        Ok(file)
    }

    /// Parses known_hosts from a string.
    ///
    /// # Arguments
    ///
    /// * `content` - File content as string
    pub fn from_string(content: &str) -> FynxResult<Self> {
        let mut entries = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match KnownHost::parse_line(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    // Log warning but continue parsing
                    eprintln!("Warning: Failed to parse line {}: {}", line_num + 1, e);
                }
            }
        }

        Ok(Self {
            entries,
            path: PathBuf::new(),
        })
    }

    /// Returns the list of known host entries.
    pub fn entries(&self) -> &[KnownHost] {
        &self.entries
    }

    /// Adds a known host entry.
    pub fn add_entry(&mut self, entry: KnownHost) {
        self.entries.push(entry);
    }

    /// Verifies a host key against known hosts.
    ///
    /// # Arguments
    ///
    /// * `hostname` - Hostname to verify
    /// * `port` - Port number
    /// * `key_type` - Key algorithm name
    /// * `key_data` - Public key data
    ///
    /// # Returns
    ///
    /// Host key verification status.
    pub fn verify_host_key(
        &self,
        hostname: &str,
        port: u16,
        key_type: &str,
        key_data: &[u8],
    ) -> HostKeyStatus {
        for entry in &self.entries {
            // Check if hostname/port matches
            if let Ok(matches) = entry.matches(hostname, port) {
                if !matches {
                    continue;
                }

                // Hostname matches, check key type and data
                if entry.key_type() == key_type && entry.key_data() == key_data {
                    return HostKeyStatus::Known;
                }

                // Hostname matches but key is different
                return HostKeyStatus::Changed {
                    old_key_type: entry.key_type().to_string(),
                    old_key_data: entry.key_data().to_vec(),
                };
            }
        }

        // No matching entry found
        HostKeyStatus::Unknown
    }

    /// Adds a new host with its public key to the known_hosts file.
    ///
    /// # Arguments
    ///
    /// * `hostname` - Hostname (will be formatted with port if not 22)
    /// * `port` - Port number (default 22)
    /// * `key_type` - Key algorithm name (e.g., "ssh-ed25519")
    /// * `key_data` - Public key data in SSH wire format
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::known_hosts::KnownHostsFile;
    ///
    /// let mut known_hosts = KnownHostsFile::new("/tmp/known_hosts");
    /// let key_data = vec![0u8; 32]; // Example key data
    /// known_hosts.add_host("example.com", 22, "ssh-ed25519", &key_data).unwrap();
    /// ```
    pub fn add_host(
        &mut self,
        hostname: &str,
        port: u16,
        key_type: &str,
        key_data: &[u8],
    ) -> FynxResult<()> {
        // Format hostname with port if non-standard
        let hostname_pattern = if port == 22 {
            hostname.to_string()
        } else {
            format!("[{}]:{}", hostname, port)
        };

        // Create KnownHost entry manually (since parse_line expects a full line)
        let entry = KnownHost {
            hostname_pattern: hostname_pattern.clone(),
            key_type: key_type.to_string(),
            key_data: key_data.to_vec(),
            comment: String::new(),
        };

        self.entries.push(entry);
        Ok(())
    }

    /// Removes a host from the known_hosts file.
    ///
    /// Removes all entries matching the given hostname and port.
    ///
    /// # Returns
    ///
    /// Number of entries removed.
    pub fn remove_host(&mut self, hostname: &str, port: u16) -> FynxResult<usize> {
        let initial_count = self.entries.len();

        self.entries.retain(|entry| {
            if let Ok(matches) = entry.matches(hostname, port) {
                !matches
            } else {
                true // Keep entries with errors
            }
        });

        Ok(initial_count - self.entries.len())
    }

    /// Updates the host key for a given hostname/port.
    ///
    /// Removes all existing entries for the host and adds a new one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::known_hosts::KnownHostsFile;
    ///
    /// let mut known_hosts = KnownHostsFile::new("/tmp/known_hosts");
    /// let new_key_data = vec![0u8; 32];
    /// known_hosts.update_host("example.com", 22, "ssh-ed25519", &new_key_data).unwrap();
    /// ```
    pub fn update_host(
        &mut self,
        hostname: &str,
        port: u16,
        key_type: &str,
        key_data: &[u8],
    ) -> FynxResult<()> {
        // Remove old entries
        self.remove_host(hostname, port)?;

        // Add new entry
        self.add_host(hostname, port, key_type, key_data)?;

        Ok(())
    }

    /// Saves the known_hosts file to disk.
    ///
    /// Writes all entries in standard OpenSSH known_hosts format.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use fynx_proto::ssh::known_hosts::KnownHostsFile;
    ///
    /// let mut known_hosts = KnownHostsFile::new("/home/user/.ssh/known_hosts");
    /// known_hosts.add_host("example.com", 22, "ssh-ed25519", &vec![0u8; 32]).unwrap();
    /// known_hosts.save().unwrap();
    /// ```
    pub fn save(&self) -> FynxResult<()> {
        use std::fs;
        use std::io::Write;

        // Create parent directory if it doesn't exist
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(FynxError::Io)?;
            }
        }

        // Build the file content
        let mut content = String::new();
        for entry in &self.entries {
            let base64_key = base64::engine::general_purpose::STANDARD.encode(entry.key_data());
            let line = if entry.comment().is_empty() {
                format!(
                    "{} {} {}\n",
                    entry.hostname_pattern(),
                    entry.key_type(),
                    base64_key
                )
            } else {
                format!(
                    "{} {} {} {}\n",
                    entry.hostname_pattern(),
                    entry.key_type(),
                    base64_key,
                    entry.comment()
                )
            };
            content.push_str(&line);
        }

        // Write to file (atomic write via temp file)
        let temp_path = self.path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).map_err(FynxError::Io)?;
        file.write_all(content.as_bytes()).map_err(FynxError::Io)?;
        file.sync_all().map_err(FynxError::Io)?;
        drop(file);

        // Atomic rename
        fs::rename(&temp_path, &self.path).map_err(FynxError::Io)?;

        Ok(())
    }
}

/// Host key verification status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// Host key is known and matches.
    Known,
    /// Host key is known but has changed.
    Changed {
        /// Old key type
        old_key_type: String,
        /// Old key data
        old_key_data: Vec<u8>,
    },
    /// Host is unknown.
    Unknown,
}

/// Strict host key checking policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    /// Reject all unknown and changed keys.
    Strict,
    /// Prompt user for unknown and changed keys.
    Ask,
    /// Accept new hosts automatically, but reject changed keys.
    AcceptNew,
    /// Accept all hosts (insecure, testing only).
    No,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_format() {
        let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD user@host";
        let entry = KnownHost::parse_line(line).unwrap();

        assert_eq!(entry.hostname_pattern(), "example.com");
        assert_eq!(entry.key_type(), "ssh-ed25519");
        assert_eq!(entry.comment(), "user@host");
    }

    #[test]
    fn test_parse_with_port() {
        let line = "[example.com]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/";
        let entry = KnownHost::parse_line(line).unwrap();

        assert_eq!(entry.hostname_pattern(), "[example.com]:2222");
        assert_eq!(entry.key_type(), "ssh-rsa");
    }

    #[test]
    fn test_parse_comment_line() {
        let line = "# This is a comment";
        let result = KnownHost::parse_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_line() {
        let line = "   ";
        let result = KnownHost::parse_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_wildcard_match() {
        assert!(KnownHost::wildcard_match("*.example.com", "host.example.com"));
        assert!(KnownHost::wildcard_match("*.example.com", "sub.host.example.com"));
        assert!(!KnownHost::wildcard_match("*.example.com", "example.com"));
        assert!(!KnownHost::wildcard_match("*.example.com", "other.com"));

        assert!(KnownHost::wildcard_match("host?.example.com", "host1.example.com"));
        assert!(!KnownHost::wildcard_match("host?.example.com", "host12.example.com"));
    }

    #[test]
    fn test_known_hosts_file() {
        let content = r#"
# Comment line
example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD user@host
[example.com]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/ user@host2
        "#;

        let file = KnownHostsFile::from_string(content).unwrap();
        assert_eq!(file.entries().len(), 2);
    }

    #[test]
    fn test_verify_known_host() {
        let content = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD";
        let file = KnownHostsFile::from_string(content).unwrap();

        let key_data = base64::engine::general_purpose::STANDARD
            .decode("AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD")
            .unwrap();

        let status = file.verify_host_key("example.com", 22, "ssh-ed25519", &key_data);
        assert_eq!(status, HostKeyStatus::Known);
    }

    #[test]
    fn test_verify_unknown_host() {
        let content = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD";
        let file = KnownHostsFile::from_string(content).unwrap();

        let key_data = base64::engine::general_purpose::STANDARD
            .decode("AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD")
            .unwrap();

        let status = file.verify_host_key("other.com", 22, "ssh-ed25519", &key_data);
        assert_eq!(status, HostKeyStatus::Unknown);
    }

    #[test]
    fn test_detect_key_change() {
        let content = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRanDK33/M2A9M0Lc/TQ/pF5kfd8rplxF34cupZF1gD";
        let file = KnownHostsFile::from_string(content).unwrap();

        // Different key data
        let different_key = vec![1, 2, 3, 4];

        let status = file.verify_host_key("example.com", 22, "ssh-ed25519", &different_key);
        assert!(matches!(status, HostKeyStatus::Changed { .. }));
    }

    #[test]
    fn test_add_host() {
        let mut file = KnownHostsFile::new("/tmp/test_known_hosts");
        let key_data = vec![1, 2, 3, 4, 5];

        // Add a host on standard port
        file.add_host("example.com", 22, "ssh-ed25519", &key_data)
            .unwrap();
        assert_eq!(file.entries().len(), 1);
        assert_eq!(file.entries()[0].hostname_pattern(), "example.com");
        assert_eq!(file.entries()[0].key_type(), "ssh-ed25519");
        assert_eq!(file.entries()[0].key_data(), &key_data);

        // Add a host on non-standard port
        file.add_host("other.com", 2222, "ssh-rsa", &key_data)
            .unwrap();
        assert_eq!(file.entries().len(), 2);
        assert_eq!(file.entries()[1].hostname_pattern(), "[other.com]:2222");
    }

    #[test]
    fn test_remove_host() {
        let mut file = KnownHostsFile::new("/tmp/test_known_hosts");
        let key_data = vec![1, 2, 3, 4];

        // Add two hosts
        file.add_host("example.com", 22, "ssh-ed25519", &key_data)
            .unwrap();
        file.add_host("other.com", 22, "ssh-ed25519", &key_data)
            .unwrap();
        assert_eq!(file.entries().len(), 2);

        // Remove one host
        let removed = file.remove_host("example.com", 22).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(file.entries().len(), 1);
        assert_eq!(file.entries()[0].hostname_pattern(), "other.com");

        // Remove non-existent host
        let removed = file.remove_host("nonexistent.com", 22).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(file.entries().len(), 1);
    }

    #[test]
    fn test_update_host() {
        let mut file = KnownHostsFile::new("/tmp/test_known_hosts");
        let old_key = vec![1, 2, 3, 4];
        let new_key = vec![5, 6, 7, 8];

        // Add a host
        file.add_host("example.com", 22, "ssh-ed25519", &old_key)
            .unwrap();
        assert_eq!(file.entries().len(), 1);
        assert_eq!(file.entries()[0].key_data(), &old_key);

        // Update the host key
        file.update_host("example.com", 22, "ssh-ed25519", &new_key)
            .unwrap();
        assert_eq!(file.entries().len(), 1);
        assert_eq!(file.entries()[0].key_data(), &new_key);
    }

    #[test]
    fn test_save_and_load() {
        use std::fs;
        use std::io::Write;

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("fynx_test_known_hosts");
        fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("known_hosts_test");

        // Create and populate a known_hosts file
        let mut file = KnownHostsFile::new(&file_path);
        let key_data1 = vec![1, 2, 3, 4];
        let key_data2 = vec![5, 6, 7, 8];

        file.add_host("example.com", 22, "ssh-ed25519", &key_data1)
            .unwrap();
        file.add_host("other.com", 2222, "ssh-rsa", &key_data2)
            .unwrap();

        // Save to disk
        file.save().unwrap();

        // Load from disk
        let loaded = KnownHostsFile::from_file(&file_path).unwrap();
        assert_eq!(loaded.entries().len(), 2);
        assert_eq!(loaded.entries()[0].hostname_pattern(), "example.com");
        assert_eq!(loaded.entries()[0].key_data(), &key_data1);
        assert_eq!(loaded.entries()[1].hostname_pattern(), "[other.com]:2222");
        assert_eq!(loaded.entries()[1].key_data(), &key_data2);

        // Cleanup
        fs::remove_file(&file_path).ok();
        fs::remove_dir(&temp_dir).ok();
    }

    #[test]
    fn test_save_preserves_comments() {
        use std::fs;

        let temp_dir = std::env::temp_dir().join("fynx_test_known_hosts_comments");
        fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("known_hosts_comments");

        // Create a file with comments via manual entry construction
        let mut file = KnownHostsFile::new(&file_path);
        let key_data = vec![1, 2, 3, 4];

        // Add entry without comment
        file.add_host("example.com", 22, "ssh-ed25519", &key_data)
            .unwrap();

        // Add entry with comment (by parsing a line)
        let line_with_comment =
            "other.com ssh-ed25519 AQIDBA== user@host";
        if let Ok(entry) = KnownHost::parse_line(line_with_comment) {
            file.add_entry(entry);
        }

        file.save().unwrap();

        // Load and verify
        let loaded = KnownHostsFile::from_file(&file_path).unwrap();
        assert_eq!(loaded.entries().len(), 2);
        assert_eq!(loaded.entries()[0].comment(), "");
        assert_eq!(loaded.entries()[1].comment(), "user@host");

        // Cleanup
        fs::remove_file(&file_path).ok();
        fs::remove_dir(&temp_dir).ok();
    }
}
