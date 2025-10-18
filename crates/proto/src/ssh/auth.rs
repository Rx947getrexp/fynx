//! SSH authentication protocol (RFC 4252).
//!
//! This module implements user authentication for SSH:
//! - "publickey" - Public key authentication (Ed25519, RSA)
//! - "password" - Password authentication
//! - "none" - Test authentication state
//!
//! # Security
//!
//! - **Constant-time password comparison** - Prevents timing attacks
//! - **Partial success handling** - Supports multi-factor authentication
//! - **Public key signature verification** - Uses cryptographically secure libraries
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::auth::{AuthRequest, AuthMethod};
//!
//! // Create password authentication request
//! let auth = AuthRequest::new(
//!     "user",
//!     "ssh-connection",
//!     AuthMethod::Password("secret".to_string()),
//! );
//! ```

use bytes::{BufMut, BytesMut};
use fynx_platform::{FynxError, FynxResult};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// SSH authentication method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// No authentication (test only).
    None,
    /// Password authentication.
    Password(String),
    /// Public key authentication.
    PublicKey {
        /// Algorithm name (e.g., "ssh-ed25519", "rsa-sha2-256")
        algorithm: String,
        /// Public key blob
        public_key: Vec<u8>,
        /// Signature (if present)
        signature: Option<Vec<u8>>,
    },
}

impl AuthMethod {
    /// Returns the method name.
    pub fn name(&self) -> &str {
        match self {
            AuthMethod::None => "none",
            AuthMethod::Password(_) => "password",
            AuthMethod::PublicKey { .. } => "publickey",
        }
    }
}

impl Drop for AuthMethod {
    fn drop(&mut self) {
        // Zeroize sensitive data
        if let AuthMethod::Password(ref mut password) = self {
            password.zeroize();
        }
    }
}

/// SSH_MSG_USERAUTH_REQUEST message (RFC 4252 Section 5).
///
/// This message is sent by the client to request authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// User name
    user_name: String,
    /// Service name (usually "ssh-connection")
    service_name: String,
    /// Authentication method
    method: AuthMethod,
}

impl AuthRequest {
    /// Creates a new authentication request.
    ///
    /// # Arguments
    ///
    /// * `user_name` - User name to authenticate as
    /// * `service_name` - Service to start after authentication (usually "ssh-connection")
    /// * `method` - Authentication method
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::auth::{AuthRequest, AuthMethod};
    ///
    /// let auth = AuthRequest::new(
    ///     "alice",
    ///     "ssh-connection",
    ///     AuthMethod::Password("secret".to_string()),
    /// );
    /// ```
    pub fn new(user_name: &str, service_name: &str, method: AuthMethod) -> Self {
        Self {
            user_name: user_name.to_string(),
            service_name: service_name.to_string(),
            method,
        }
    }

    /// Returns the user name.
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns the service name.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Returns the authentication method.
    pub fn method(&self) -> &AuthMethod {
        &self.method
    }

    /// Serializes the authentication request to bytes.
    ///
    /// Format (RFC 4252 Section 5):
    /// ```text
    /// byte      SSH_MSG_USERAUTH_REQUEST (50)
    /// string    user name
    /// string    service name
    /// string    method name
    /// ....      method specific fields
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_USERAUTH_REQUEST (50)
        buf.put_u8(50);

        // string user name
        write_string(&mut buf, &self.user_name);

        // string service name
        write_string(&mut buf, &self.service_name);

        // string method name
        write_string(&mut buf, self.method.name());

        // Method-specific fields
        match &self.method {
            AuthMethod::None => {
                // No additional fields
            }
            AuthMethod::Password(password) => {
                // boolean FALSE (not changing password)
                buf.put_u8(0);
                // string plaintext password
                write_string(&mut buf, password);
            }
            AuthMethod::PublicKey {
                algorithm,
                public_key,
                signature,
            } => {
                // boolean (TRUE if signature present)
                buf.put_u8(if signature.is_some() { 1 } else { 0 });
                // string public key algorithm name
                write_string(&mut buf, algorithm);
                // string public key blob
                write_bytes(&mut buf, public_key);
                // string signature (if present)
                if let Some(sig) = signature {
                    write_bytes(&mut buf, sig);
                }
            }
        }

        buf.to_vec()
    }

    /// Parses an authentication request from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if the data is invalid.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "USERAUTH_REQUEST message is empty".to_string(),
            ));
        }

        // Check message type
        if data[0] != 50 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 50 (SSH_MSG_USERAUTH_REQUEST), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        // Parse user name
        let user_name = read_string(data, &mut offset)?;

        // Parse service name
        let service_name = read_string(data, &mut offset)?;

        // Parse method name
        let method_name = read_string(data, &mut offset)?;

        // Parse method-specific fields
        let method = match method_name.as_str() {
            "none" => AuthMethod::None,
            "password" => {
                // boolean (changing password flag)
                if offset >= data.len() {
                    return Err(FynxError::Protocol(
                        "USERAUTH_REQUEST truncated (missing password change flag)".to_string(),
                    ));
                }
                let _changing = data[offset] != 0;
                offset += 1;

                // string password
                let password = read_string(data, &mut offset)?;
                AuthMethod::Password(password)
            }
            "publickey" => {
                // boolean (has signature)
                if offset >= data.len() {
                    return Err(FynxError::Protocol(
                        "USERAUTH_REQUEST truncated (missing publickey signature flag)".to_string(),
                    ));
                }
                let has_signature = data[offset] != 0;
                offset += 1;

                // string algorithm name
                let algorithm = read_string(data, &mut offset)?;

                // string public key blob
                let public_key = read_bytes(data, &mut offset)?;

                // string signature (if present)
                let signature = if has_signature {
                    Some(read_bytes(data, &mut offset)?)
                } else {
                    None
                };

                AuthMethod::PublicKey {
                    algorithm,
                    public_key,
                    signature,
                }
            }
            _ => {
                return Err(FynxError::Protocol(format!(
                    "Unsupported authentication method: '{}'",
                    method_name
                )))
            }
        };

        Ok(Self {
            user_name,
            service_name,
            method,
        })
    }
}

/// SSH_MSG_USERAUTH_FAILURE message (RFC 4252 Section 5.1).
///
/// Sent by the server when authentication fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailure {
    /// Authentications that can continue
    methods_can_continue: Vec<String>,
    /// Partial success flag
    partial_success: bool,
}

impl AuthFailure {
    /// Creates a new authentication failure message.
    ///
    /// # Arguments
    ///
    /// * `methods` - Methods that can continue
    /// * `partial_success` - Whether partial success was achieved
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::auth::AuthFailure;
    ///
    /// let failure = AuthFailure::new(
    ///     vec!["publickey".to_string(), "password".to_string()],
    ///     false,
    /// );
    /// ```
    pub fn new(methods: Vec<String>, partial_success: bool) -> Self {
        Self {
            methods_can_continue: methods,
            partial_success,
        }
    }

    /// Returns the methods that can continue.
    pub fn methods_can_continue(&self) -> &[String] {
        &self.methods_can_continue
    }

    /// Returns whether partial success was achieved.
    pub fn partial_success(&self) -> bool {
        self.partial_success
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_USERAUTH_FAILURE (51)
        buf.put_u8(51);

        // name-list authentications that can continue
        let methods_str = self.methods_can_continue.join(",");
        write_string(&mut buf, &methods_str);

        // boolean partial success
        buf.put_u8(if self.partial_success { 1 } else { 0 });

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "USERAUTH_FAILURE message is empty".to_string(),
            ));
        }

        if data[0] != 51 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 51 (SSH_MSG_USERAUTH_FAILURE), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        // name-list methods
        let methods_str = read_string(data, &mut offset)?;
        let methods_can_continue: Vec<String> = if methods_str.is_empty() {
            vec![]
        } else {
            methods_str.split(',').map(String::from).collect()
        };

        // boolean partial success
        if offset >= data.len() {
            return Err(FynxError::Protocol(
                "USERAUTH_FAILURE truncated (missing partial success flag)".to_string(),
            ));
        }
        let partial_success = data[offset] != 0;

        Ok(Self {
            methods_can_continue,
            partial_success,
        })
    }
}

/// SSH_MSG_USERAUTH_SUCCESS message (RFC 4252 Section 5.1).
///
/// Sent by the server when authentication succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSuccess;

impl AuthSuccess {
    /// Creates a new authentication success message.
    pub fn new() -> Self {
        Self
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![52] // SSH_MSG_USERAUTH_SUCCESS (52)
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() || data[0] != 52 {
            return Err(FynxError::Protocol(
                "Invalid USERAUTH_SUCCESS message".to_string(),
            ));
        }
        Ok(Self)
    }
}

impl Default for AuthSuccess {
    fn default() -> Self {
        Self::new()
    }
}

/// SSH_MSG_USERAUTH_BANNER message (RFC 4252 Section 5.4).
///
/// Sent by the server to display a banner message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBanner {
    /// Banner message
    message: String,
    /// Language tag (usually "")
    language_tag: String,
}

impl AuthBanner {
    /// Creates a new banner message.
    pub fn new(message: String) -> Self {
        Self {
            message,
            language_tag: String::new(),
        }
    }

    /// Returns the banner message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_USERAUTH_BANNER (53)
        buf.put_u8(53);

        // string message
        write_string(&mut buf, &self.message);

        // string language tag
        write_string(&mut buf, &self.language_tag);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "USERAUTH_BANNER message is empty".to_string(),
            ));
        }

        if data[0] != 53 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 53 (SSH_MSG_USERAUTH_BANNER), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let message = read_string(data, &mut offset)?;
        let language_tag = read_string(data, &mut offset)?;

        Ok(Self {
            message,
            language_tag,
        })
    }
}

/// SSH_MSG_USERAUTH_PK_OK message (RFC 4252 Section 7).
///
/// Sent by the server to indicate that the public key is acceptable
/// for authentication (in response to a try-then-sign query).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPkOk {
    /// Public key algorithm name
    algorithm: String,
    /// Public key blob
    public_key: Vec<u8>,
}

impl AuthPkOk {
    /// Creates a new SSH_MSG_USERAUTH_PK_OK message.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Public key algorithm name (e.g., "ssh-ed25519")
    /// * `public_key` - Public key blob
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::auth::AuthPkOk;
    ///
    /// let pk_ok = AuthPkOk::new("ssh-ed25519", vec![1, 2, 3, 4]);
    /// ```
    pub fn new(algorithm: impl Into<String>, public_key: Vec<u8>) -> Self {
        Self {
            algorithm: algorithm.into(),
            public_key,
        }
    }

    /// Returns the algorithm name.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the public key blob.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Serializes to bytes.
    ///
    /// Format (RFC 4252 Section 7):
    /// ```text
    /// byte      SSH_MSG_USERAUTH_PK_OK (60)
    /// string    public key algorithm name
    /// string    public key blob
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_USERAUTH_PK_OK (60)
        buf.put_u8(60);

        // string algorithm name
        write_string(&mut buf, &self.algorithm);

        // string public key blob
        write_bytes(&mut buf, &self.public_key);

        buf.to_vec()
    }

    /// Parses from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if the data is invalid.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "USERAUTH_PK_OK message is empty".to_string(),
            ));
        }

        if data[0] != 60 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 60 (SSH_MSG_USERAUTH_PK_OK), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        // string algorithm name
        let algorithm = read_string(data, &mut offset)?;

        // string public key blob
        let public_key = read_bytes(data, &mut offset)?;

        Ok(Self {
            algorithm,
            public_key,
        })
    }
}

/// Constructs the data to be signed for public key authentication (RFC 4252 Section 7).
///
/// # Arguments
///
/// * `session_id` - Session identifier from key exchange
/// * `user_name` - User name for authentication
/// * `service_name` - Service name (usually "ssh-connection")
/// * `algorithm` - Public key algorithm name
/// * `public_key_blob` - Public key in SSH wire format
///
/// # Returns
///
/// Bytes to be signed
///
/// # Format
///
/// ```text
/// string    session identifier
/// byte      SSH_MSG_USERAUTH_REQUEST (50)
/// string    user name
/// string    service name
/// string    "publickey"
/// boolean   TRUE (has signature)
/// string    public key algorithm name
/// string    public key blob
/// ```
pub fn construct_signature_data(
    session_id: &[u8],
    user_name: &str,
    service_name: &str,
    algorithm: &str,
    public_key_blob: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::new();

    // string session identifier
    write_bytes(&mut buf, session_id);

    // byte SSH_MSG_USERAUTH_REQUEST (50)
    buf.put_u8(50);

    // string user name
    write_string(&mut buf, user_name);

    // string service name
    write_string(&mut buf, service_name);

    // string "publickey"
    write_string(&mut buf, "publickey");

    // boolean TRUE (has signature)
    buf.put_u8(1);

    // string public key algorithm name
    write_string(&mut buf, algorithm);

    // string public key blob
    write_bytes(&mut buf, public_key_blob);

    buf.to_vec()
}

/// Compares two passwords in constant time to prevent timing attacks.
///
/// # Arguments
///
/// * `a` - First password
/// * `b` - Second password
///
/// # Returns
///
/// `true` if passwords match, `false` otherwise
///
/// # Security
///
/// This function uses constant-time comparison to prevent timing attacks
/// that could reveal information about the password.
///
/// # Example
///
/// ```rust
/// use fynx_proto::ssh::auth::constant_time_compare;
///
/// assert!(constant_time_compare("secret", "secret"));
/// assert!(!constant_time_compare("secret", "wrong"));
/// ```
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    // Hash both passwords first to ensure constant-time comparison
    // even if lengths differ
    let hash_a = Sha256::digest(a.as_bytes());
    let hash_b = Sha256::digest(b.as_bytes());

    // Use constant-time comparison
    hash_a.ct_eq(&hash_b).into()
}

// Helper functions for string encoding/decoding

fn write_string(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

fn write_bytes(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

fn read_string(data: &[u8], offset: &mut usize) -> FynxResult<String> {
    let bytes = read_bytes(data, offset)?;
    String::from_utf8(bytes)
        .map_err(|_| FynxError::Protocol("String contains invalid UTF-8".to_string()))
}

fn read_bytes(data: &[u8], offset: &mut usize) -> FynxResult<Vec<u8>> {
    if *offset + 4 > data.len() {
        return Err(FynxError::Protocol(format!(
            "Cannot read length at offset {}",
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
            "Data truncated: expected {} bytes at offset {}",
            length, offset
        )));
    }

    let bytes = data[*offset..*offset + length].to_vec();
    *offset += length;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_request_password() {
        let auth = AuthRequest::new(
            "alice",
            "ssh-connection",
            AuthMethod::Password("secret".to_string()),
        );

        assert_eq!(auth.user_name(), "alice");
        assert_eq!(auth.service_name(), "ssh-connection");
        assert_eq!(auth.method().name(), "password");

        let bytes = auth.to_bytes();
        let parsed = AuthRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.user_name(), "alice");
        assert_eq!(parsed.service_name(), "ssh-connection");
        if let AuthMethod::Password(pw) = parsed.method() {
            assert_eq!(pw, "secret");
        } else {
            panic!("Expected Password method");
        }
    }

    #[test]
    fn test_auth_request_publickey() {
        let public_key = vec![1, 2, 3, 4];
        let auth = AuthRequest::new(
            "bob",
            "ssh-connection",
            AuthMethod::PublicKey {
                algorithm: "ssh-ed25519".to_string(),
                public_key: public_key.clone(),
                signature: None,
            },
        );

        let bytes = auth.to_bytes();
        let parsed = AuthRequest::from_bytes(&bytes).unwrap();

        if let AuthMethod::PublicKey {
            algorithm,
            public_key: pk,
            signature,
        } = parsed.method()
        {
            assert_eq!(algorithm, "ssh-ed25519");
            assert_eq!(pk, &public_key);
            assert!(signature.is_none());
        } else {
            panic!("Expected PublicKey method");
        }
    }

    #[test]
    fn test_auth_request_none() {
        let auth = AuthRequest::new("test", "ssh-connection", AuthMethod::None);

        let bytes = auth.to_bytes();
        let parsed = AuthRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.method(), &AuthMethod::None);
    }

    #[test]
    fn test_auth_failure() {
        let failure =
            AuthFailure::new(vec!["publickey".to_string(), "password".to_string()], false);

        assert_eq!(
            failure.methods_can_continue(),
            &["publickey".to_string(), "password".to_string()]
        );
        assert!(!failure.partial_success());

        let bytes = failure.to_bytes();
        let parsed = AuthFailure::from_bytes(&bytes).unwrap();

        assert_eq!(
            parsed.methods_can_continue(),
            failure.methods_can_continue()
        );
        assert_eq!(parsed.partial_success(), failure.partial_success());
    }

    #[test]
    fn test_auth_success() {
        let success = AuthSuccess::new();
        let bytes = success.to_bytes();
        let parsed = AuthSuccess::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, success);
    }

    #[test]
    fn test_auth_banner() {
        let banner = AuthBanner::new("Welcome to SSH Server".to_string());
        assert_eq!(banner.message(), "Welcome to SSH Server");

        let bytes = banner.to_bytes();
        let parsed = AuthBanner::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.message(), banner.message());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("password123", "password123"));
        assert!(!constant_time_compare("password123", "password124"));
        assert!(!constant_time_compare("short", "verylongpassword"));
    }

    #[test]
    fn test_auth_method_zeroize() {
        let method = AuthMethod::Password("secret".to_string());
        drop(method);
        // Password should be zeroized (can't test directly, but ensures no panic)
    }

    #[test]
    fn test_auth_pk_ok() {
        let public_key = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let pk_ok = AuthPkOk::new("ssh-ed25519", public_key.clone());

        assert_eq!(pk_ok.algorithm(), "ssh-ed25519");
        assert_eq!(pk_ok.public_key(), &public_key);

        let bytes = pk_ok.to_bytes();
        assert_eq!(bytes[0], 60); // SSH_MSG_USERAUTH_PK_OK

        let parsed = AuthPkOk::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.algorithm(), "ssh-ed25519");
        assert_eq!(parsed.public_key(), &public_key);
    }

    #[test]
    fn test_auth_pk_ok_invalid_message_type() {
        let data = vec![50, 0, 0, 0, 0]; // Wrong message type (50 instead of 60)
        let result = AuthPkOk::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_construct_signature_data() {
        let session_id = vec![1, 2, 3, 4];
        let user_name = "alice";
        let service_name = "ssh-connection";
        let algorithm = "ssh-ed25519";
        let public_key_blob = vec![5, 6, 7, 8];

        let data = construct_signature_data(
            &session_id,
            user_name,
            service_name,
            algorithm,
            &public_key_blob,
        );

        // Should contain all required fields
        assert!(!data.is_empty());

        // Check that session_id is at the beginning
        let sid_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        assert_eq!(sid_len, session_id.len());
        assert_eq!(&data[4..4 + sid_len], &session_id[..]);

        // Check SSH_MSG_USERAUTH_REQUEST (50)
        let msg_type_offset = 4 + sid_len;
        assert_eq!(data[msg_type_offset], 50);
    }
}
