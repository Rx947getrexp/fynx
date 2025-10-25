//! Cipher implementations for IKEv2 encryption
//!
//! Implements encryption and decryption for SK payload as defined in RFC 7296.

use crate::ipsec::{Error, Result};
use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce as AesGcmNonce,
};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// Cipher algorithm for SK payload encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    /// AES-GCM with 128-bit key (AEAD)
    AesGcm128,
    /// AES-GCM with 256-bit key (AEAD)
    AesGcm256,
    /// ChaCha20-Poly1305 (AEAD)
    ChaCha20Poly1305,
}

impl CipherAlgorithm {
    /// Get key length in bytes
    pub fn key_len(self) -> usize {
        match self {
            CipherAlgorithm::AesGcm128 => 16,
            CipherAlgorithm::AesGcm256 => 32,
            CipherAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Get IV/nonce length in bytes
    pub fn iv_len(self) -> usize {
        match self {
            CipherAlgorithm::AesGcm128 | CipherAlgorithm::AesGcm256 => 8, // RFC 4106
            CipherAlgorithm::ChaCha20Poly1305 => 12,                      // RFC 7539
        }
    }

    /// Get authentication tag length in bytes (for AEAD ciphers)
    pub fn tag_len(self) -> usize {
        16 // All AEAD ciphers use 16-byte tag
    }

    /// Check if this is an AEAD cipher
    pub fn is_aead(self) -> bool {
        true // All currently supported ciphers are AEAD
    }

    /// Encrypt data with AEAD cipher
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (SK_e)
    /// * `iv` - Initialization vector / nonce
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (IKE header)
    ///
    /// # Returns
    ///
    /// Returns ciphertext with authentication tag appended
    pub fn encrypt(self, key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Validate key length
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }

        // Validate IV length
        if iv.len() != self.iv_len() {
            return Err(Error::InvalidIvLength {
                expected: self.iv_len(),
                actual: iv.len(),
            });
        }

        match self {
            CipherAlgorithm::AesGcm128 => {
                // AES-GCM uses 8-byte IV + 4-byte fixed field (RFC 4106)
                // For IKEv2, we use 8-byte explicit IV
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| Error::CryptoError("Failed to create AES-GCM cipher".into()))?;

                // Pad IV to 12 bytes (8-byte explicit + 4-byte implicit fixed field set to 0)
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(iv);
                let nonce = AesGcmNonce::from_slice(&nonce_bytes);

                let payload = Payload {
                    msg: plaintext,
                    aad,
                };

                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))
            }
            CipherAlgorithm::AesGcm256 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| Error::CryptoError("Failed to create AES-GCM cipher".into()))?;

                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(iv);
                let nonce = AesGcmNonce::from_slice(&nonce_bytes);

                let payload = Payload {
                    msg: plaintext,
                    aad,
                };

                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))
            }
            CipherAlgorithm::ChaCha20Poly1305 => {
                // ChaCha20-Poly1305 uses 12-byte nonce (RFC 7539)
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| Error::CryptoError("Failed to create ChaCha20 cipher".into()))?;

                let nonce = chacha20poly1305::Nonce::from_slice(iv);

                let payload = Payload {
                    msg: plaintext,
                    aad,
                };

                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::CryptoError("ChaCha20-Poly1305 encryption failed".into()))
            }
        }
    }

    /// Decrypt data with AEAD cipher
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key (SK_e)
    /// * `iv` - Initialization vector / nonce
    /// * `ciphertext` - Data to decrypt (includes authentication tag)
    /// * `aad` - Additional authenticated data (IKE header)
    ///
    /// # Returns
    ///
    /// Returns decrypted plaintext
    pub fn decrypt(self, key: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Validate key length
        if key.len() != self.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.key_len(),
                actual: key.len(),
            });
        }

        // Validate IV length
        if iv.len() != self.iv_len() {
            return Err(Error::InvalidIvLength {
                expected: self.iv_len(),
                actual: iv.len(),
            });
        }

        // Validate ciphertext includes tag
        if ciphertext.len() < self.tag_len() {
            return Err(Error::BufferTooShort {
                required: self.tag_len(),
                available: ciphertext.len(),
            });
        }

        match self {
            CipherAlgorithm::AesGcm128 => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| Error::CryptoError("Failed to create AES-GCM cipher".into()))?;

                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(iv);
                let nonce = AesGcmNonce::from_slice(&nonce_bytes);

                let payload = Payload {
                    msg: ciphertext,
                    aad,
                };

                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))
            }
            CipherAlgorithm::AesGcm256 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| Error::CryptoError("Failed to create AES-GCM cipher".into()))?;

                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[..8].copy_from_slice(iv);
                let nonce = AesGcmNonce::from_slice(&nonce_bytes);

                let payload = Payload {
                    msg: ciphertext,
                    aad,
                };

                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))
            }
            CipherAlgorithm::ChaCha20Poly1305 => {
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| Error::CryptoError("Failed to create ChaCha20 cipher".into()))?;

                let nonce = chacha20poly1305::Nonce::from_slice(iv);

                let payload = Payload {
                    msg: ciphertext,
                    aad,
                };

                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::CryptoError("ChaCha20-Poly1305 decryption failed".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_key_lengths() {
        assert_eq!(CipherAlgorithm::AesGcm128.key_len(), 16);
        assert_eq!(CipherAlgorithm::AesGcm256.key_len(), 32);
        assert_eq!(CipherAlgorithm::ChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    fn test_cipher_iv_lengths() {
        assert_eq!(CipherAlgorithm::AesGcm128.iv_len(), 8);
        assert_eq!(CipherAlgorithm::AesGcm256.iv_len(), 8);
        assert_eq!(CipherAlgorithm::ChaCha20Poly1305.iv_len(), 12);
    }

    #[test]
    fn test_cipher_tag_lengths() {
        assert_eq!(CipherAlgorithm::AesGcm128.tag_len(), 16);
        assert_eq!(CipherAlgorithm::AesGcm256.tag_len(), 16);
        assert_eq!(CipherAlgorithm::ChaCha20Poly1305.tag_len(), 16);
    }

    #[test]
    fn test_aes_gcm_128_encrypt_decrypt() {
        let key = vec![0x42; 16]; // 128-bit key
        let iv = vec![0x01; 8]; // 8-byte IV
        let plaintext = b"Hello, IKEv2!";
        let aad = b"IKE header data";

        let ciphertext = CipherAlgorithm::AesGcm128
            .encrypt(&key, &iv, plaintext, aad)
            .unwrap();

        // Ciphertext should include 16-byte tag
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = CipherAlgorithm::AesGcm128
            .decrypt(&key, &iv, &ciphertext, aad)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_256_encrypt_decrypt() {
        let key = vec![0x42; 32]; // 256-bit key
        let iv = vec![0x01; 8];
        let plaintext = b"Test data for AES-GCM-256";
        let aad = b"Additional authenticated data";

        let ciphertext = CipherAlgorithm::AesGcm256
            .encrypt(&key, &iv, plaintext, aad)
            .unwrap();

        let decrypted = CipherAlgorithm::AesGcm256
            .decrypt(&key, &iv, &ciphertext, aad)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = vec![0x42; 32]; // 256-bit key
        let iv = vec![0x01; 12]; // 12-byte nonce
        let plaintext = b"ChaCha20-Poly1305 test";
        let aad = b"AAD for ChaCha20";

        let ciphertext = CipherAlgorithm::ChaCha20Poly1305
            .encrypt(&key, &iv, plaintext, aad)
            .unwrap();

        let decrypted = CipherAlgorithm::ChaCha20Poly1305
            .decrypt(&key, &iv, &ciphertext, aad)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = vec![0x42; 10]; // Wrong length
        let iv = vec![0x01; 8];
        let plaintext = b"test";
        let aad = b"aad";

        let result = CipherAlgorithm::AesGcm128.encrypt(&key, &iv, plaintext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_iv_length() {
        let key = vec![0x42; 16];
        let iv = vec![0x01; 4]; // Wrong length
        let plaintext = b"test";
        let aad = b"aad";

        let result = CipherAlgorithm::AesGcm128.encrypt(&key, &iv, plaintext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_authentication_failure() {
        let key = vec![0x42; 16];
        let iv = vec![0x01; 8];
        let plaintext = b"test";
        let aad = b"aad";

        let mut ciphertext = CipherAlgorithm::AesGcm128
            .encrypt(&key, &iv, plaintext, aad)
            .unwrap();

        // Corrupt the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = CipherAlgorithm::AesGcm128.decrypt(&key, &iv, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_aad() {
        let key = vec![0x42; 16];
        let iv = vec![0x01; 8];
        let plaintext = b"test";
        let aad = b"correct aad";

        let ciphertext = CipherAlgorithm::AesGcm128
            .encrypt(&key, &iv, plaintext, aad)
            .unwrap();

        // Use wrong AAD
        let wrong_aad = b"wrong aad";
        let result = CipherAlgorithm::AesGcm128.decrypt(&key, &iv, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }
}
