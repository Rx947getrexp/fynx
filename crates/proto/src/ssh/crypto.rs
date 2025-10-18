//! SSH cryptographic operations.
//!
//! This module implements encryption and MAC algorithms for SSH:
//! - ChaCha20-Poly1305 (AEAD cipher)
//! - AES-128-GCM, AES-256-GCM (AEAD ciphers)
//! - AES-128-CTR, AES-256-CTR (stream ciphers with separate MAC)
//! - HMAC-SHA256, HMAC-SHA512 (MAC algorithms)
//!
//! # Security
//!
//! - **AEAD ciphers** - Authenticated encryption with associated data
//! - **Nonce management** - Ensures nonce uniqueness for AEAD ciphers
//! - **Key derivation** - Uses SSH key derivation from kex_dh module
//!
//! # Example
//!
//! ```rust,ignore
//! use fynx_proto::ssh::crypto::Cipher;
//!
//! // Create ChaCha20-Poly1305 cipher
//! let cipher = Cipher::chacha20_poly1305(&key, &iv);
//! ```

use fynx_platform::{FynxError, FynxResult};
use hmac::{Hmac, Mac};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM,
    AES_256_GCM, CHACHA20_POLY1305,
};
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

/// Nonce counter for AEAD ciphers.
///
/// SSH uses a 64-bit packet sequence number as the nonce.
struct Counter {
    value: u64,
}

impl Counter {
    fn new() -> Self {
        Self { value: 0 }
    }
}

impl NonceSequence for Counter {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let mut nonce_bytes = [0u8; 12];
        // Use packet sequence number as nonce (last 8 bytes)
        nonce_bytes[4..12].copy_from_slice(&self.value.to_be_bytes());
        self.value = self.value.wrapping_add(1);
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Cipher algorithm for SSH encryption.
#[derive(Debug)]
pub enum CipherAlgorithm {
    /// ChaCha20-Poly1305 AEAD cipher
    ChaCha20Poly1305,
    /// AES-128-GCM AEAD cipher
    Aes128Gcm,
    /// AES-256-GCM AEAD cipher
    Aes256Gcm,
    /// AES-128-CTR stream cipher (requires separate MAC)
    Aes128Ctr,
    /// AES-256-CTR stream cipher (requires separate MAC)
    Aes256Ctr,
}

impl CipherAlgorithm {
    /// Returns the algorithm name.
    pub fn name(&self) -> &'static str {
        match self {
            CipherAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
            CipherAlgorithm::Aes128Gcm => "aes128-gcm@openssh.com",
            CipherAlgorithm::Aes256Gcm => "aes256-gcm@openssh.com",
            CipherAlgorithm::Aes128Ctr => "aes128-ctr",
            CipherAlgorithm::Aes256Ctr => "aes256-ctr",
        }
    }

    /// Returns the key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            CipherAlgorithm::ChaCha20Poly1305 => 32,
            CipherAlgorithm::Aes128Gcm => 16,
            CipherAlgorithm::Aes256Gcm => 32,
            CipherAlgorithm::Aes128Ctr => 16,
            CipherAlgorithm::Aes256Ctr => 32,
        }
    }

    /// Returns the IV/nonce size in bytes.
    pub fn iv_size(&self) -> usize {
        match self {
            CipherAlgorithm::ChaCha20Poly1305 => 12,
            CipherAlgorithm::Aes128Gcm => 12,
            CipherAlgorithm::Aes256Gcm => 12,
            CipherAlgorithm::Aes128Ctr => 16,
            CipherAlgorithm::Aes256Ctr => 16,
        }
    }

    /// Returns the authentication tag size in bytes (for AEAD ciphers).
    pub fn tag_size(&self) -> usize {
        match self {
            CipherAlgorithm::ChaCha20Poly1305 => 16,
            CipherAlgorithm::Aes128Gcm => 16,
            CipherAlgorithm::Aes256Gcm => 16,
            CipherAlgorithm::Aes128Ctr => 0,
            CipherAlgorithm::Aes256Ctr => 0,
        }
    }

    /// Returns true if this is an AEAD cipher.
    pub fn is_aead(&self) -> bool {
        matches!(
            self,
            CipherAlgorithm::ChaCha20Poly1305
                | CipherAlgorithm::Aes128Gcm
                | CipherAlgorithm::Aes256Gcm
        )
    }

    /// Parses cipher algorithm from name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20-poly1305@openssh.com" => Some(CipherAlgorithm::ChaCha20Poly1305),
            "aes128-gcm@openssh.com" => Some(CipherAlgorithm::Aes128Gcm),
            "aes256-gcm@openssh.com" => Some(CipherAlgorithm::Aes256Gcm),
            "aes128-ctr" => Some(CipherAlgorithm::Aes128Ctr),
            "aes256-ctr" => Some(CipherAlgorithm::Aes256Ctr),
            _ => None,
        }
    }
}

/// Encryption key for AEAD ciphers.
pub struct EncryptionKey {
    algorithm: CipherAlgorithm,
    key: Option<SealingKey<Counter>>,
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl EncryptionKey {
    /// Creates a new encryption key.
    pub fn new(algorithm: CipherAlgorithm, key_material: &[u8]) -> FynxResult<Self> {
        if key_material.len() < algorithm.key_size() {
            return Err(FynxError::Security(format!(
                "Insufficient key material: expected {}, got {}",
                algorithm.key_size(),
                key_material.len()
            )));
        }

        let key = match algorithm {
            CipherAlgorithm::ChaCha20Poly1305 => {
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_material[..32])
                    .map_err(|_| {
                        FynxError::Security("Failed to create ChaCha20-Poly1305 key".to_string())
                    })?;
                Some(SealingKey::new(unbound_key, Counter::new()))
            }
            CipherAlgorithm::Aes128Gcm => {
                let unbound_key =
                    UnboundKey::new(&AES_128_GCM, &key_material[..16]).map_err(|_| {
                        FynxError::Security("Failed to create AES-128-GCM key".to_string())
                    })?;
                Some(SealingKey::new(unbound_key, Counter::new()))
            }
            CipherAlgorithm::Aes256Gcm => {
                let unbound_key =
                    UnboundKey::new(&AES_256_GCM, &key_material[..32]).map_err(|_| {
                        FynxError::Security("Failed to create AES-256-GCM key".to_string())
                    })?;
                Some(SealingKey::new(unbound_key, Counter::new()))
            }
            CipherAlgorithm::Aes128Ctr | CipherAlgorithm::Aes256Ctr => {
                // CTR mode ciphers need different implementation (not AEAD)
                None
            }
        };

        Ok(Self { algorithm, key })
    }

    /// Encrypts data in place (AEAD mode).
    pub fn encrypt(&mut self, data: &mut Vec<u8>) -> FynxResult<()> {
        if let Some(ref mut key) = self.key {
            key.seal_in_place_append_tag(Aad::empty(), data)
                .map_err(|_| FynxError::Security("Encryption failed".to_string()))?;
            Ok(())
        } else {
            Err(FynxError::Security(
                "CTR mode requires separate implementation".to_string(),
            ))
        }
    }

    /// Returns the algorithm.
    pub fn algorithm(&self) -> &CipherAlgorithm {
        &self.algorithm
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Keys are zeroized by ring's Drop implementation
    }
}

/// Decryption key for AEAD ciphers.
pub struct DecryptionKey {
    algorithm: CipherAlgorithm,
    key: Option<OpeningKey<Counter>>,
}

impl std::fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionKey")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl DecryptionKey {
    /// Creates a new decryption key.
    pub fn new(algorithm: CipherAlgorithm, key_material: &[u8]) -> FynxResult<Self> {
        if key_material.len() < algorithm.key_size() {
            return Err(FynxError::Security(format!(
                "Insufficient key material: expected {}, got {}",
                algorithm.key_size(),
                key_material.len()
            )));
        }

        let key = match algorithm {
            CipherAlgorithm::ChaCha20Poly1305 => {
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key_material[..32])
                    .map_err(|_| {
                        FynxError::Security("Failed to create ChaCha20-Poly1305 key".to_string())
                    })?;
                Some(OpeningKey::new(unbound_key, Counter::new()))
            }
            CipherAlgorithm::Aes128Gcm => {
                let unbound_key =
                    UnboundKey::new(&AES_128_GCM, &key_material[..16]).map_err(|_| {
                        FynxError::Security("Failed to create AES-128-GCM key".to_string())
                    })?;
                Some(OpeningKey::new(unbound_key, Counter::new()))
            }
            CipherAlgorithm::Aes256Gcm => {
                let unbound_key =
                    UnboundKey::new(&AES_256_GCM, &key_material[..32]).map_err(|_| {
                        FynxError::Security("Failed to create AES-256-GCM key".to_string())
                    })?;
                Some(OpeningKey::new(unbound_key, Counter::new()))
            }
            CipherAlgorithm::Aes128Ctr | CipherAlgorithm::Aes256Ctr => {
                // CTR mode ciphers need different implementation (not AEAD)
                None
            }
        };

        Ok(Self { algorithm, key })
    }

    /// Decrypts data in place (AEAD mode).
    pub fn decrypt(&mut self, data: &mut Vec<u8>) -> FynxResult<()> {
        if let Some(ref mut key) = self.key {
            let plaintext_len = {
                let plaintext = key.open_in_place(Aad::empty(), data).map_err(|_| {
                    FynxError::Security(
                        "Decryption failed or authentication tag mismatch".to_string(),
                    )
                })?;
                plaintext.len()
            };
            // Truncate to remove the tag
            data.truncate(plaintext_len);
            Ok(())
        } else {
            Err(FynxError::Security(
                "CTR mode requires separate implementation".to_string(),
            ))
        }
    }

    /// Returns the algorithm.
    pub fn algorithm(&self) -> &CipherAlgorithm {
        &self.algorithm
    }
}

impl Drop for DecryptionKey {
    fn drop(&mut self) {
        // Keys are zeroized by ring's Drop implementation
    }
}

/// MAC algorithm for SSH.
#[derive(Debug, Clone, Copy)]
pub enum MacAlgorithm {
    /// HMAC-SHA256
    HmacSha256,
    /// HMAC-SHA512
    HmacSha512,
}

impl MacAlgorithm {
    /// Returns the algorithm name.
    pub fn name(&self) -> &'static str {
        match self {
            MacAlgorithm::HmacSha256 => "hmac-sha2-256",
            MacAlgorithm::HmacSha512 => "hmac-sha2-512",
        }
    }

    /// Returns the key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha512 => 64,
        }
    }

    /// Returns the MAC output size in bytes.
    pub fn mac_size(&self) -> usize {
        match self {
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha512 => 64,
        }
    }

    /// Parses MAC algorithm from name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "hmac-sha2-256" => Some(MacAlgorithm::HmacSha256),
            "hmac-sha2-512" => Some(MacAlgorithm::HmacSha512),
            _ => None,
        }
    }
}

/// MAC key for computing message authentication codes.
pub struct MacKey {
    algorithm: MacAlgorithm,
    key: Vec<u8>,
    sequence: u32,
}

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKey")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl MacKey {
    /// Creates a new MAC key.
    pub fn new(algorithm: MacAlgorithm, key_material: &[u8]) -> FynxResult<Self> {
        if key_material.len() < algorithm.key_size() {
            return Err(FynxError::Security(format!(
                "Insufficient key material for MAC: expected {}, got {}",
                algorithm.key_size(),
                key_material.len()
            )));
        }

        Ok(Self {
            algorithm,
            key: key_material[..algorithm.key_size()].to_vec(),
            sequence: 0,
        })
    }

    /// Computes MAC for packet data.
    ///
    /// # Arguments
    ///
    /// * `packet_data` - The packet data (without MAC)
    ///
    /// # Returns
    ///
    /// The MAC bytes
    pub fn compute(&mut self, packet_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.sequence.to_be_bytes());
        data.extend_from_slice(packet_data);

        let mac = match self.algorithm {
            MacAlgorithm::HmacSha256 => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key size is valid");
                mac.update(&data);
                mac.finalize().into_bytes().to_vec()
            }
            MacAlgorithm::HmacSha512 => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(&self.key).expect("HMAC key size is valid");
                mac.update(&data);
                mac.finalize().into_bytes().to_vec()
            }
        };

        self.sequence = self.sequence.wrapping_add(1);
        mac
    }

    /// Verifies MAC for packet data.
    ///
    /// # Arguments
    ///
    /// * `packet_data` - The packet data (without MAC)
    /// * `received_mac` - The received MAC bytes
    ///
    /// # Returns
    ///
    /// `Ok(())` if MAC is valid, error otherwise
    pub fn verify(&mut self, packet_data: &[u8], received_mac: &[u8]) -> FynxResult<()> {
        let computed_mac = self.compute(packet_data);

        if computed_mac.len() != received_mac.len() {
            return Err(FynxError::Security("MAC length mismatch".to_string()));
        }

        // Use constant-time comparison
        use subtle::ConstantTimeEq;
        if computed_mac.ct_eq(received_mac).into() {
            Ok(())
        } else {
            Err(FynxError::Security("MAC verification failed".to_string()))
        }
    }

    /// Returns the algorithm.
    pub fn algorithm(&self) -> MacAlgorithm {
        self.algorithm
    }
}

impl Drop for MacKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_algorithm_properties() {
        let chacha = CipherAlgorithm::ChaCha20Poly1305;
        assert_eq!(chacha.name(), "chacha20-poly1305@openssh.com");
        assert_eq!(chacha.key_size(), 32);
        assert_eq!(chacha.iv_size(), 12);
        assert_eq!(chacha.tag_size(), 16);
        assert!(chacha.is_aead());

        let aes128 = CipherAlgorithm::Aes128Gcm;
        assert_eq!(aes128.key_size(), 16);
        assert!(aes128.is_aead());

        let aes256_ctr = CipherAlgorithm::Aes256Ctr;
        assert_eq!(aes256_ctr.key_size(), 32);
        assert!(!aes256_ctr.is_aead());
    }

    #[test]
    fn test_cipher_from_name() {
        assert!(matches!(
            CipherAlgorithm::from_name("chacha20-poly1305@openssh.com"),
            Some(CipherAlgorithm::ChaCha20Poly1305)
        ));
        assert!(matches!(
            CipherAlgorithm::from_name("aes128-gcm@openssh.com"),
            Some(CipherAlgorithm::Aes128Gcm)
        ));
        assert!(CipherAlgorithm::from_name("invalid").is_none());
    }

    #[test]
    fn test_mac_algorithm_properties() {
        let sha256 = MacAlgorithm::HmacSha256;
        assert_eq!(sha256.name(), "hmac-sha2-256");
        assert_eq!(sha256.key_size(), 32);
        assert_eq!(sha256.mac_size(), 32);

        let sha512 = MacAlgorithm::HmacSha512;
        assert_eq!(sha512.key_size(), 64);
        assert_eq!(sha512.mac_size(), 64);
    }

    #[test]
    fn test_mac_from_name() {
        assert!(matches!(
            MacAlgorithm::from_name("hmac-sha2-256"),
            Some(MacAlgorithm::HmacSha256)
        ));
        assert!(matches!(
            MacAlgorithm::from_name("hmac-sha2-512"),
            Some(MacAlgorithm::HmacSha512)
        ));
        assert!(MacAlgorithm::from_name("invalid").is_none());
    }

    #[test]
    fn test_mac_compute_and_verify() {
        let key = vec![0u8; 32];
        let mut mac_key = MacKey::new(MacAlgorithm::HmacSha256, &key).unwrap();

        let data = b"Hello, SSH!";
        let mac = mac_key.compute(data);

        // Reset sequence for verification
        mac_key.sequence = 0;
        assert!(mac_key.verify(data, &mac).is_ok());

        // Wrong MAC should fail
        let wrong_mac = vec![0u8; 32];
        mac_key.sequence = 0;
        assert!(mac_key.verify(data, &wrong_mac).is_err());
    }

    #[test]
    fn test_encryption_key_creation() {
        let key = vec![0u8; 32];
        let enc_key = EncryptionKey::new(CipherAlgorithm::ChaCha20Poly1305, &key);
        assert!(enc_key.is_ok());

        let insufficient_key = vec![0u8; 16];
        let result = EncryptionKey::new(CipherAlgorithm::ChaCha20Poly1305, &insufficient_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryption_key_creation() {
        let key = vec![0u8; 32];
        let dec_key = DecryptionKey::new(CipherAlgorithm::ChaCha20Poly1305, &key);
        assert!(dec_key.is_ok());
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = vec![1u8; 32];
        let mut enc_key = EncryptionKey::new(CipherAlgorithm::ChaCha20Poly1305, &key).unwrap();
        let mut dec_key = DecryptionKey::new(CipherAlgorithm::ChaCha20Poly1305, &key).unwrap();

        let mut plaintext = b"Hello, SSH!".to_vec();
        let original = plaintext.clone();

        // Encrypt
        enc_key.encrypt(&mut plaintext).unwrap();
        assert_ne!(plaintext, original); // Should be different after encryption

        // Decrypt
        dec_key.decrypt(&mut plaintext).unwrap();
        assert_eq!(plaintext, original); // Should match original
    }

    #[test]
    fn test_aes128_gcm_encrypt_decrypt() {
        let key = vec![2u8; 16];
        let mut enc_key = EncryptionKey::new(CipherAlgorithm::Aes128Gcm, &key).unwrap();
        let mut dec_key = DecryptionKey::new(CipherAlgorithm::Aes128Gcm, &key).unwrap();

        let mut plaintext = b"Test data".to_vec();
        let original = plaintext.clone();

        enc_key.encrypt(&mut plaintext).unwrap();
        dec_key.decrypt(&mut plaintext).unwrap();
        assert_eq!(plaintext, original);
    }
}
