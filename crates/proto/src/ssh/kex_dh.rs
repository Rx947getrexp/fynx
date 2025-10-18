//! Diffie-Hellman key exchange (RFC 4253, RFC 8268).
//!
//! This module implements:
//! - diffie-hellman-group14-sha256 (RFC 8268)
//! - Curve25519-SHA256 (RFC 8731)
//!
//! # Security
//!
//! - DH Group14: 2048-bit MODP group (minimum secure size)
//! - Curve25519: Modern elliptic curve, constant-time operations
//! - All keys are zeroized on drop
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::kex_dh::DhGroup14Exchange;
//!
//! // Client generates ephemeral key pair
//! let client_exchange = DhGroup14Exchange::new();
//! let client_public = client_exchange.public_key();
//! ```

use fynx_platform::{FynxError, FynxResult};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Diffie-Hellman Group 14 parameters (RFC 3526).
///
/// This is a 2048-bit MODP group.
mod dh_group14 {
    use num_bigint::BigUint;
    use once_cell::sync::Lazy;

    /// DH Group 14 prime (2048-bit)
    pub static P: Lazy<BigUint> = Lazy::new(|| {
        BigUint::from_bytes_be(
            &hex::decode(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
             29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
             EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
             E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
             EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
             C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
             83655D23DCA3AD961C62F356208552BB9ED529077096966D\
             670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
             E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
             DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
             15728E5A8AACAA68FFFFFFFFFFFFFFFF"
                    .replace([' ', '\n'], "")
                    .as_str(),
            )
            .expect("Invalid hex"),
        )
    });

    /// DH Group 14 generator
    pub static G: Lazy<BigUint> = Lazy::new(|| BigUint::from(2u32));
}

/// Diffie-Hellman Group 14 key exchange.
///
/// Implements the diffie-hellman-group14-sha256 algorithm (RFC 8268).
pub struct DhGroup14Exchange {
    /// Private key (x)
    private_key: Vec<u8>,
    /// Public key (g^x mod p)
    public_key: Vec<u8>,
}

impl DhGroup14Exchange {
    /// Generates a new DH Group 14 key exchange.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex_dh::DhGroup14Exchange;
    ///
    /// let exchange = DhGroup14Exchange::new();
    /// let public_key = exchange.public_key();
    /// assert!(!public_key.is_empty());
    /// ```
    pub fn new() -> Self {
        use num_bigint::{BigUint, RandBigInt};
        use rand::thread_rng;

        let mut rng = thread_rng();

        // Generate random private key x (1 < x < p-1)
        let p_minus_one = dh_group14::P.clone() - 1u32;
        let x = rng.gen_biguint_range(&BigUint::from(2u32), &p_minus_one);

        // Compute public key: y = g^x mod p
        let y = dh_group14::G.modpow(&x, &dh_group14::P);

        Self {
            private_key: x.to_bytes_be(),
            public_key: y.to_bytes_be(),
        }
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Computes the shared secret given the peer's public key.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - Peer's public key bytes
    ///
    /// # Returns
    ///
    /// Shared secret K
    ///
    /// # Errors
    ///
    /// Returns error if peer's public key is invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex_dh::DhGroup14Exchange;
    ///
    /// let client = DhGroup14Exchange::new();
    /// let server = DhGroup14Exchange::new();
    ///
    /// // Exchange public keys
    /// let client_secret = client.compute_shared_secret(server.public_key()).unwrap();
    /// let server_secret = server.compute_shared_secret(client.public_key()).unwrap();
    ///
    /// // Both should compute the same shared secret
    /// assert_eq!(client_secret, server_secret);
    /// ```
    pub fn compute_shared_secret(&self, peer_public: &[u8]) -> FynxResult<Vec<u8>> {
        use num_bigint::BigUint;

        let y_peer = BigUint::from_bytes_be(peer_public);

        // Validate peer's public key: 1 < y < p-1
        if y_peer <= BigUint::from(1u32) || y_peer >= *dh_group14::P {
            return Err(FynxError::Protocol(
                "Invalid peer public key: out of range".to_string(),
            ));
        }

        let x = BigUint::from_bytes_be(&self.private_key);

        // Compute shared secret: K = y_peer^x mod p
        let k = y_peer.modpow(&x, &dh_group14::P);

        Ok(k.to_bytes_be())
    }
}

impl Default for DhGroup14Exchange {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DhGroup14Exchange {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Curve25519 key exchange.
///
/// Implements curve25519-sha256 and curve25519-sha256@libssh.org (RFC 8731).
pub struct Curve25519Exchange {
    /// Private key
    private_key: EphemeralPrivateKey,
    /// Public key (32 bytes)
    public_key: [u8; 32],
}

impl Curve25519Exchange {
    /// Generates a new Curve25519 key exchange.
    ///
    /// # Returns
    ///
    /// A new key exchange or an error if RNG fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex_dh::Curve25519Exchange;
    ///
    /// let exchange = Curve25519Exchange::new().unwrap();
    /// let public_key = exchange.public_key();
    /// assert_eq!(public_key.len(), 32);
    /// ```
    pub fn new() -> FynxResult<Self> {
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| FynxError::Security("Failed to generate Curve25519 key".to_string()))?;

        let public_key = private_key.compute_public_key().map_err(|_| {
            FynxError::Security("Failed to compute Curve25519 public key".to_string())
        })?;

        let mut public_key_bytes = [0u8; 32];
        public_key_bytes.copy_from_slice(public_key.as_ref());

        Ok(Self {
            private_key,
            public_key: public_key_bytes,
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Computes the shared secret given the peer's public key.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - Peer's public key (32 bytes)
    ///
    /// # Returns
    ///
    /// Shared secret K (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns error if key agreement fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::kex_dh::Curve25519Exchange;
    ///
    /// let client = Curve25519Exchange::new().unwrap();
    /// let server = Curve25519Exchange::new().unwrap();
    ///
    /// // Save public keys before moving the exchanges
    /// let client_public = *client.public_key();
    /// let server_public = *server.public_key();
    ///
    /// // Exchange public keys (consumes the exchanges)
    /// let client_secret = client.compute_shared_secret(&server_public).unwrap();
    /// let server_secret = server.compute_shared_secret(&client_public).unwrap();
    ///
    /// // Both should compute the same shared secret
    /// assert_eq!(client_secret, server_secret);
    /// ```
    pub fn compute_shared_secret(self, peer_public: &[u8; 32]) -> FynxResult<Vec<u8>> {
        let peer_public_key = UnparsedPublicKey::new(&X25519, peer_public);

        agree_ephemeral(self.private_key, &peer_public_key, |key_material| {
            key_material.to_vec()
        })
        .map_err(|_| FynxError::Security("Curve25519 key agreement failed".to_string()))
    }
}

/// Derives SSH session keys from shared secret (RFC 4253 Section 7.2).
///
/// # Key Derivation
///
/// ```text
/// Initial IV client to server:  HASH(K || H || "A" || session_id)
/// Initial IV server to client:  HASH(K || H || "B" || session_id)
/// Encryption key client to server: HASH(K || H || "C" || session_id)
/// Encryption key server to client: HASH(K || H || "D" || session_id)
/// Integrity key client to server:  HASH(K || H || "E" || session_id)
/// Integrity key server to client:  HASH(K || H || "F" || session_id)
/// ```
///
/// Where:
/// - K = shared secret from key exchange
/// - H = exchange hash (SHA-256 for our implementations)
/// - session_id = H from first key exchange
///
/// # Arguments
///
/// * `shared_secret` - Shared secret K from key exchange
/// * `exchange_hash` - Exchange hash H
/// * `session_id` - Session identifier (H from first KEX)
/// * `key_type` - Key type identifier ('A' through 'F')
/// * `key_length` - Desired key length in bytes
///
/// # Returns
///
/// Derived key bytes
///
/// # Example
///
/// ```rust
/// use fynx_proto::ssh::kex_dh::derive_key;
///
/// let shared_secret = vec![0x42; 32];
/// let exchange_hash = vec![0x01; 32];
/// let session_id = vec![0x02; 32];
///
/// // Derive encryption key client to server
/// let key = derive_key(&shared_secret, &exchange_hash, &session_id, b'C', 32);
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    session_id: &[u8],
    key_type: u8,
    key_length: usize,
) -> Vec<u8> {
    let mut key = Vec::new();
    let mut hasher = Sha256::new();

    // K is encoded as mpint (SSH format)
    let k_mpint = encode_mpint(shared_secret);

    // First block: HASH(K || H || key_type || session_id)
    hasher.update(&k_mpint);
    hasher.update(exchange_hash);
    hasher.update([key_type]);
    hasher.update(session_id);
    let block = hasher.finalize_reset();
    key.extend_from_slice(&block);

    // If we need more bytes, keep hashing: HASH(K || H || previous_block)
    while key.len() < key_length {
        hasher.update(&k_mpint);
        hasher.update(exchange_hash);
        hasher.update(&key[key.len() - 32..]);
        let block = hasher.finalize_reset();
        key.extend_from_slice(&block);
    }

    key.truncate(key_length);
    key
}

/// Encodes a big integer as SSH mpint format.
///
/// Format: uint32 length + bytes (with high bit padding if needed)
fn encode_mpint(data: &[u8]) -> Vec<u8> {
    // Remove leading zeros
    let trimmed = data
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect::<Vec<_>>();

    if trimmed.is_empty() {
        return vec![0, 0, 0, 0]; // Zero is encoded as length 0
    }

    // If high bit is set, prepend 0x00 to make it positive
    let needs_padding = trimmed[0] & 0x80 != 0;
    let length = if needs_padding {
        trimmed.len() + 1
    } else {
        trimmed.len()
    };

    let mut result = Vec::with_capacity(4 + length);
    result.extend_from_slice(&(length as u32).to_be_bytes());

    if needs_padding {
        result.push(0);
    }
    result.extend_from_slice(&trimmed);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_group14_key_exchange() {
        let client = DhGroup14Exchange::new();
        let server = DhGroup14Exchange::new();

        // Both parties should be able to compute the same shared secret
        let client_secret = client.compute_shared_secret(server.public_key()).unwrap();
        let server_secret = server.compute_shared_secret(client.public_key()).unwrap();

        assert_eq!(client_secret, server_secret);
        assert!(!client_secret.is_empty());
    }

    #[test]
    fn test_dh_group14_invalid_peer_key() {
        let exchange = DhGroup14Exchange::new();

        // Test with peer key = 1 (invalid)
        let invalid_key = vec![1u8];
        let result = exchange.compute_shared_secret(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_curve25519_key_exchange() {
        let client = Curve25519Exchange::new().unwrap();
        let server = Curve25519Exchange::new().unwrap();

        // Exchange public keys
        let client_public = *client.public_key();
        let server_public = *server.public_key();

        // Compute shared secrets
        let client_secret = client.compute_shared_secret(&server_public).unwrap();
        let server_secret = server.compute_shared_secret(&client_public).unwrap();

        assert_eq!(client_secret, server_secret);
        assert_eq!(client_secret.len(), 32);
    }

    #[test]
    fn test_curve25519_public_key_length() {
        let exchange = Curve25519Exchange::new().unwrap();
        assert_eq!(exchange.public_key().len(), 32);
    }

    #[test]
    fn test_derive_key() {
        let shared_secret = vec![0x42; 32];
        let exchange_hash = vec![0x01; 32];
        let session_id = vec![0x02; 32];

        // Derive a 32-byte key
        let key = derive_key(&shared_secret, &exchange_hash, &session_id, b'C', 32);
        assert_eq!(key.len(), 32);

        // Different key types should produce different keys
        let key_a = derive_key(&shared_secret, &exchange_hash, &session_id, b'A', 32);
        let key_c = derive_key(&shared_secret, &exchange_hash, &session_id, b'C', 32);
        assert_ne!(key_a, key_c);
    }

    #[test]
    fn test_derive_key_long() {
        let shared_secret = vec![0x42; 32];
        let exchange_hash = vec![0x01; 32];
        let session_id = vec![0x02; 32];

        // Derive a 64-byte key (requires two hash blocks)
        let key = derive_key(&shared_secret, &exchange_hash, &session_id, b'C', 64);
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_encode_mpint() {
        // Test zero
        let zero = encode_mpint(&[]);
        assert_eq!(zero, vec![0, 0, 0, 0]);

        // Test positive number without high bit set
        let positive = encode_mpint(&[0x12, 0x34]);
        assert_eq!(positive, vec![0, 0, 0, 2, 0x12, 0x34]);

        // Test positive number with high bit set (needs padding)
        let high_bit = encode_mpint(&[0x80, 0x00]);
        assert_eq!(high_bit, vec![0, 0, 0, 3, 0, 0x80, 0x00]);

        // Test with leading zeros (should be trimmed)
        let leading_zeros = encode_mpint(&[0x00, 0x00, 0x12, 0x34]);
        assert_eq!(leading_zeros, vec![0, 0, 0, 2, 0x12, 0x34]);
    }
}
