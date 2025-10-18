//! SSH key exchange (KEX) implementation (RFC 4253 Section 7).
//!
//! This module implements SSH key exchange, including:
//! - SSH_MSG_KEXINIT message
//! - SSH_MSG_NEWKEYS message
//! - Algorithm negotiation
//! - Diffie-Hellman Group14-SHA256
//! - Curve25519-SHA256
//!
//! # Key Exchange Flow
//!
//! 1. Both sides send SSH_MSG_KEXINIT
//! 2. Algorithm negotiation (first match wins)
//! 3. Key exchange (DH or ECDH)
//! 4. Both sides send SSH_MSG_NEWKEYS
//! 5. Switch to encrypted communication
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::kex::{KexInit, NewKeys};
//!
//! // Create KEXINIT message
//! let kexinit = KexInit::new_default();
//! assert!(kexinit.kex_algorithms().contains(&"curve25519-sha256".to_string()));
//!
//! // Create NEWKEYS message
//! let newkeys = NewKeys::new();
//! let bytes = newkeys.to_bytes();
//! assert_eq!(bytes.len(), 1);
//! assert_eq!(bytes[0], 21);
//! ```

use bytes::{BufMut, BytesMut};
use fynx_platform::{FynxError, FynxResult};
use rand::RngCore;

/// SSH_MSG_KEXINIT message (RFC 4253 Section 7.1).
///
/// This message is used to negotiate algorithms for the SSH connection.
///
/// # Algorithm Lists
///
/// Each algorithm list is a comma-separated list of algorithm names,
/// ordered by preference (most preferred first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    /// Random cookie (16 bytes)
    cookie: [u8; 16],
    /// Key exchange algorithms
    kex_algorithms: Vec<String>,
    /// Server host key algorithms
    server_host_key_algorithms: Vec<String>,
    /// Encryption algorithms client to server
    encryption_algorithms_client_to_server: Vec<String>,
    /// Encryption algorithms server to client
    encryption_algorithms_server_to_client: Vec<String>,
    /// MAC algorithms client to server
    mac_algorithms_client_to_server: Vec<String>,
    /// MAC algorithms server to client
    mac_algorithms_server_to_client: Vec<String>,
    /// Compression algorithms client to server
    compression_algorithms_client_to_server: Vec<String>,
    /// Compression algorithms server to client
    compression_algorithms_server_to_client: Vec<String>,
    /// Languages client to server (usually empty)
    languages_client_to_server: Vec<String>,
    /// Languages server to client (usually empty)
    languages_server_to_client: Vec<String>,
    /// First KEX packet follows
    first_kex_packet_follows: bool,
}

impl KexInit {
    /// Creates a new KEXINIT message with default Fynx algorithms.
    ///
    /// Uses secure, modern algorithms recommended by current standards:
    /// - KEX: curve25519-sha256, diffie-hellman-group14-sha256
    /// - Host key: ssh-ed25519, rsa-sha2-512, rsa-sha2-256
    /// - Encryption: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes256-ctr, aes128-ctr
    /// - MAC: hmac-sha2-256, hmac-sha2-512 (for non-AEAD ciphers)
    /// - Compression: none
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex::KexInit;
    ///
    /// let kexinit = KexInit::new_default();
    /// assert_eq!(kexinit.cookie().len(), 16);
    /// ```
    pub fn new_default() -> Self {
        let mut cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut cookie);

        Self {
            cookie,
            kex_algorithms: vec![
                "curve25519-sha256".to_string(),
                "curve25519-sha256@libssh.org".to_string(),
                "diffie-hellman-group14-sha256".to_string(),
            ],
            server_host_key_algorithms: vec![
                "ssh-ed25519".to_string(),
                "rsa-sha2-512".to_string(),
                "rsa-sha2-256".to_string(),
            ],
            encryption_algorithms_client_to_server: vec![
                "chacha20-poly1305@openssh.com".to_string(),
                "aes256-gcm@openssh.com".to_string(),
                "aes128-gcm@openssh.com".to_string(),
                "aes256-ctr".to_string(),
                "aes128-ctr".to_string(),
            ],
            encryption_algorithms_server_to_client: vec![
                "chacha20-poly1305@openssh.com".to_string(),
                "aes256-gcm@openssh.com".to_string(),
                "aes128-gcm@openssh.com".to_string(),
                "aes256-ctr".to_string(),
                "aes128-ctr".to_string(),
            ],
            mac_algorithms_client_to_server: vec![
                "hmac-sha2-256".to_string(),
                "hmac-sha2-512".to_string(),
            ],
            mac_algorithms_server_to_client: vec![
                "hmac-sha2-256".to_string(),
                "hmac-sha2-512".to_string(),
            ],
            compression_algorithms_client_to_server: vec!["none".to_string()],
            compression_algorithms_server_to_client: vec!["none".to_string()],
            languages_client_to_server: vec![],
            languages_server_to_client: vec![],
            first_kex_packet_follows: false,
        }
    }

    /// Returns the cookie.
    pub fn cookie(&self) -> &[u8; 16] {
        &self.cookie
    }

    /// Returns the key exchange algorithms.
    pub fn kex_algorithms(&self) -> &[String] {
        &self.kex_algorithms
    }

    /// Returns the server host key algorithms.
    pub fn server_host_key_algorithms(&self) -> &[String] {
        &self.server_host_key_algorithms
    }

    /// Returns the encryption algorithms (client to server).
    pub fn encryption_algorithms_client_to_server(&self) -> &[String] {
        &self.encryption_algorithms_client_to_server
    }

    /// Returns the encryption algorithms (server to client).
    pub fn encryption_algorithms_server_to_client(&self) -> &[String] {
        &self.encryption_algorithms_server_to_client
    }

    /// Returns the MAC algorithms (client to server).
    pub fn mac_algorithms_client_to_server(&self) -> &[String] {
        &self.mac_algorithms_client_to_server
    }

    /// Returns the MAC algorithms (server to client).
    pub fn mac_algorithms_server_to_client(&self) -> &[String] {
        &self.mac_algorithms_server_to_client
    }

    /// Returns whether first KEX packet follows.
    pub fn first_kex_packet_follows(&self) -> bool {
        self.first_kex_packet_follows
    }

    /// Serializes the KEXINIT message to bytes (without packet framing).
    ///
    /// Format (RFC 4253 Section 7.1):
    /// ```text
    /// byte         SSH_MSG_KEXINIT (20)
    /// byte[16]     cookie (random bytes)
    /// name-list    kex_algorithms
    /// name-list    server_host_key_algorithms
    /// name-list    encryption_algorithms_client_to_server
    /// name-list    encryption_algorithms_server_to_client
    /// name-list    mac_algorithms_client_to_server
    /// name-list    mac_algorithms_server_to_client
    /// name-list    compression_algorithms_client_to_server
    /// name-list    compression_algorithms_server_to_client
    /// name-list    languages_client_to_server
    /// name-list    languages_server_to_client
    /// boolean      first_kex_packet_follows
    /// uint32       0 (reserved for future extension)
    /// ```
    ///
    /// # Returns
    ///
    /// Serialized message bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex::KexInit;
    ///
    /// let kexinit = KexInit::new_default();
    /// let bytes = kexinit.to_bytes();
    /// assert_eq!(bytes[0], 20); // SSH_MSG_KEXINIT
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_KEXINIT (20)
        buf.put_u8(20);

        // byte[16] cookie
        buf.put_slice(&self.cookie);

        // name-list fields
        write_name_list(&mut buf, &self.kex_algorithms);
        write_name_list(&mut buf, &self.server_host_key_algorithms);
        write_name_list(&mut buf, &self.encryption_algorithms_client_to_server);
        write_name_list(&mut buf, &self.encryption_algorithms_server_to_client);
        write_name_list(&mut buf, &self.mac_algorithms_client_to_server);
        write_name_list(&mut buf, &self.mac_algorithms_server_to_client);
        write_name_list(&mut buf, &self.compression_algorithms_client_to_server);
        write_name_list(&mut buf, &self.compression_algorithms_server_to_client);
        write_name_list(&mut buf, &self.languages_client_to_server);
        write_name_list(&mut buf, &self.languages_server_to_client);

        // boolean first_kex_packet_follows
        buf.put_u8(if self.first_kex_packet_follows { 1 } else { 0 });

        // uint32 reserved (always 0)
        buf.put_u32(0);

        buf.to_vec()
    }

    /// Parses a KEXINIT message from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - The message bytes (without packet framing)
    ///
    /// # Returns
    ///
    /// A parsed `KexInit` or an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if:
    /// - Message is too short
    /// - Message type is not SSH_MSG_KEXINIT (20)
    /// - Name list parsing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex::KexInit;
    ///
    /// let original = KexInit::new_default();
    /// let bytes = original.to_bytes();
    ///
    /// let parsed = KexInit::from_bytes(&bytes).unwrap();
    /// assert_eq!(parsed.kex_algorithms(), original.kex_algorithms());
    /// ```
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol("KEXINIT message is empty".to_string()));
        }

        // Check message type
        if data[0] != 20 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 20 (SSH_MSG_KEXINIT), got {}",
                data[0]
            )));
        }

        if data.len() < 17 {
            return Err(FynxError::Protocol(format!(
                "KEXINIT message too short: {} bytes (minimum 17)",
                data.len()
            )));
        }

        // Extract cookie
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&data[1..17]);

        let mut offset = 17;

        // Parse name lists
        let kex_algorithms = read_name_list(data, &mut offset)?;
        let server_host_key_algorithms = read_name_list(data, &mut offset)?;
        let encryption_algorithms_client_to_server = read_name_list(data, &mut offset)?;
        let encryption_algorithms_server_to_client = read_name_list(data, &mut offset)?;
        let mac_algorithms_client_to_server = read_name_list(data, &mut offset)?;
        let mac_algorithms_server_to_client = read_name_list(data, &mut offset)?;
        let compression_algorithms_client_to_server = read_name_list(data, &mut offset)?;
        let compression_algorithms_server_to_client = read_name_list(data, &mut offset)?;
        let languages_client_to_server = read_name_list(data, &mut offset)?;
        let languages_server_to_client = read_name_list(data, &mut offset)?;

        // Parse boolean
        if offset >= data.len() {
            return Err(FynxError::Protocol(
                "KEXINIT message truncated (missing first_kex_packet_follows)".to_string(),
            ));
        }
        let first_kex_packet_follows = data[offset] != 0;
        offset += 1;

        // Parse reserved (uint32, ignored)
        if offset + 4 > data.len() {
            return Err(FynxError::Protocol(
                "KEXINIT message truncated (missing reserved field)".to_string(),
            ));
        }

        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
        })
    }
}

/// SSH_MSG_NEWKEYS message (RFC 4253 Section 7.3).
///
/// This message is sent by both the client and server after the key exchange
/// is complete. It signals the intention to start using the newly negotiated
/// keys for encryption and integrity protection.
///
/// # Protocol
///
/// After both sides send and receive SSH_MSG_NEWKEYS:
/// - All subsequent packets MUST be encrypted using the negotiated cipher
/// - All subsequent packets MUST be authenticated using the negotiated MAC
/// - The packet sequence number is NOT reset (continues from current value)
///
/// # Wire Format
///
/// ```text
/// byte    SSH_MSG_NEWKEYS (21)
/// ```
///
/// This is the simplest SSH message - just a single byte with value 21.
///
/// # Example
///
/// ```rust
/// use fynx_proto::ssh::kex::NewKeys;
///
/// let newkeys = NewKeys::new();
/// let bytes = newkeys.to_bytes();
/// assert_eq!(bytes, vec![21]);
///
/// let parsed = NewKeys::from_bytes(&bytes).unwrap();
/// assert_eq!(parsed, newkeys);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewKeys;

impl NewKeys {
    /// Creates a new SSH_MSG_NEWKEYS message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex::NewKeys;
    ///
    /// let newkeys = NewKeys::new();
    /// ```
    pub const fn new() -> Self {
        Self
    }

    /// Serializes the NEWKEYS message to bytes.
    ///
    /// # Returns
    ///
    /// A single-byte vector containing the value 21 (SSH_MSG_NEWKEYS).
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex::NewKeys;
    ///
    /// let newkeys = NewKeys::new();
    /// let bytes = newkeys.to_bytes();
    /// assert_eq!(bytes, vec![21]);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![21]
    }

    /// Parses a NEWKEYS message from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - The message bytes (should be a single byte with value 21)
    ///
    /// # Returns
    ///
    /// A `NewKeys` instance or an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if:
    /// - Message is empty
    /// - Message type is not SSH_MSG_NEWKEYS (21)
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex::NewKeys;
    ///
    /// let bytes = vec![21];
    /// let newkeys = NewKeys::from_bytes(&bytes).unwrap();
    /// assert_eq!(newkeys, NewKeys::new());
    /// ```
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol("NEWKEYS message is empty".to_string()));
        }

        if data[0] != 21 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 21 (SSH_MSG_NEWKEYS), got {}",
                data[0]
            )));
        }

        Ok(Self)
    }
}

impl Default for NewKeys {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes a name-list to the buffer (RFC 4251 Section 5).
///
/// Format: uint32 length + comma-separated names
fn write_name_list(buf: &mut BytesMut, names: &[String]) {
    let list = names.join(",");
    let bytes = list.as_bytes();
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

/// Reads a name-list from the buffer (RFC 4251 Section 5).
///
/// Format: uint32 length + comma-separated names
fn read_name_list(data: &[u8], offset: &mut usize) -> FynxResult<Vec<String>> {
    if *offset + 4 > data.len() {
        return Err(FynxError::Protocol(format!(
            "Cannot read name-list length at offset {}",
            offset
        )));
    }

    let length = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]) as usize;
    *offset += 4;

    if *offset + length > data.len() {
        return Err(FynxError::Protocol(format!(
            "Name-list data truncated: expected {} bytes at offset {}",
            length, offset
        )));
    }

    let list_bytes = &data[*offset..*offset + length];
    *offset += length;

    let list_str = std::str::from_utf8(list_bytes)
        .map_err(|_| FynxError::Protocol("Name-list contains invalid UTF-8".to_string()))?;

    if list_str.is_empty() {
        Ok(vec![])
    } else {
        Ok(list_str.split(',').map(String::from).collect())
    }
}

/// Negotiates algorithms between client and server.
///
/// Uses the first matching algorithm from the client's list that also appears
/// in the server's list (RFC 4253 Section 7.1).
///
/// # Arguments
///
/// * `client_list` - Client's algorithm list (ordered by preference)
/// * `server_list` - Server's algorithm list (ordered by preference)
///
/// # Returns
///
/// The negotiated algorithm name, or an error if no match.
///
/// # Errors
///
/// Returns [`FynxError::Protocol`] if no common algorithm found.
///
/// # Example
///
/// ```rust
/// use fynx_proto::ssh::kex::negotiate_algorithm;
///
/// let client = vec!["aes256-ctr".to_string(), "aes128-ctr".to_string()];
/// let server = vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()];
///
/// let result = negotiate_algorithm(&client, &server).unwrap();
/// assert_eq!(result, "aes256-ctr"); // First client preference that server supports
/// ```
pub fn negotiate_algorithm(client_list: &[String], server_list: &[String]) -> FynxResult<String> {
    for client_alg in client_list {
        if server_list.contains(client_alg) {
            return Ok(client_alg.clone());
        }
    }

    Err(FynxError::Protocol(format!(
        "No common algorithm: client={:?}, server={:?}",
        client_list, server_list
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kexinit_new_default() {
        let kexinit = KexInit::new_default();
        assert_eq!(kexinit.cookie().len(), 16);
        assert!(kexinit
            .kex_algorithms()
            .contains(&"curve25519-sha256".to_string()));
        assert!(kexinit
            .server_host_key_algorithms()
            .contains(&"ssh-ed25519".to_string()));
        assert!(!kexinit.first_kex_packet_follows());
    }

    #[test]
    fn test_kexinit_serialization() {
        let kexinit = KexInit::new_default();
        let bytes = kexinit.to_bytes();

        assert_eq!(bytes[0], 20); // SSH_MSG_KEXINIT
        assert!(bytes.len() > 17); // At least message type + cookie
    }

    #[test]
    fn test_kexinit_round_trip() {
        let original = KexInit::new_default();
        let bytes = original.to_bytes();
        let parsed = KexInit::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.cookie(), original.cookie());
        assert_eq!(parsed.kex_algorithms(), original.kex_algorithms());
        assert_eq!(
            parsed.server_host_key_algorithms(),
            original.server_host_key_algorithms()
        );
        assert_eq!(
            parsed.encryption_algorithms_client_to_server(),
            original.encryption_algorithms_client_to_server()
        );
        assert_eq!(
            parsed.first_kex_packet_follows(),
            original.first_kex_packet_follows()
        );
    }

    #[test]
    fn test_kexinit_parse_invalid_type() {
        let mut data = vec![99]; // Wrong message type
        data.extend_from_slice(&[0u8; 20]);

        let result = KexInit::from_bytes(&data);
        assert!(result.is_err());
        match result {
            Err(FynxError::Protocol(msg)) => {
                assert!(msg.contains("Invalid message type"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_kexinit_parse_too_short() {
        let data = vec![20, 1, 2, 3]; // Only 4 bytes
        let result = KexInit::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_negotiate_algorithm_success() {
        let client = vec!["aes256-ctr".to_string(), "aes128-ctr".to_string()];
        let server = vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()];

        let result = negotiate_algorithm(&client, &server).unwrap();
        assert_eq!(result, "aes256-ctr"); // First match from client's perspective
    }

    #[test]
    fn test_negotiate_algorithm_no_match() {
        let client = vec!["aes256-ctr".to_string()];
        let server = vec!["aes128-ctr".to_string()];

        let result = negotiate_algorithm(&client, &server);
        assert!(result.is_err());
        match result {
            Err(FynxError::Protocol(msg)) => {
                assert!(msg.contains("No common algorithm"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_name_list_write_read() {
        let names = vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
        ];
        let mut buf = BytesMut::new();
        write_name_list(&mut buf, &names);

        let mut offset = 0;
        let parsed = read_name_list(&buf, &mut offset).unwrap();
        assert_eq!(parsed, names);
    }

    #[test]
    fn test_name_list_empty() {
        let names: Vec<String> = vec![];
        let mut buf = BytesMut::new();
        write_name_list(&mut buf, &names);

        let mut offset = 0;
        let parsed = read_name_list(&buf, &mut offset).unwrap();
        assert_eq!(parsed, names);
    }

    #[test]
    fn test_newkeys_new() {
        let newkeys = NewKeys::new();
        assert_eq!(newkeys, NewKeys);
    }

    #[test]
    fn test_newkeys_default() {
        let newkeys = NewKeys::default();
        assert_eq!(newkeys, NewKeys::new());
    }

    #[test]
    fn test_newkeys_to_bytes() {
        let newkeys = NewKeys::new();
        let bytes = newkeys.to_bytes();
        assert_eq!(bytes, vec![21]);
    }

    #[test]
    fn test_newkeys_from_bytes_valid() {
        let bytes = vec![21];
        let newkeys = NewKeys::from_bytes(&bytes).unwrap();
        assert_eq!(newkeys, NewKeys::new());
    }

    #[test]
    fn test_newkeys_from_bytes_empty() {
        let bytes = vec![];
        let result = NewKeys::from_bytes(&bytes);
        assert!(result.is_err());
        match result {
            Err(FynxError::Protocol(msg)) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_newkeys_from_bytes_invalid_type() {
        let bytes = vec![20]; // Wrong message type
        let result = NewKeys::from_bytes(&bytes);
        assert!(result.is_err());
        match result {
            Err(FynxError::Protocol(msg)) => {
                assert!(msg.contains("Invalid message type"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_newkeys_round_trip() {
        let original = NewKeys::new();
        let bytes = original.to_bytes();
        let parsed = NewKeys::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, original);
    }
}
