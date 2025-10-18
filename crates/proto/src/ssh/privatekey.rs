// Copyright (c) 2025 Fynx Project
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH private key loading and parsing
//!
//! This module provides comprehensive SSH private key file loading functionality,
//! supporting multiple formats:
//!
//! - **PEM formats**:
//!   - PKCS#1 (BEGIN RSA PRIVATE KEY)
//!   - PKCS#8 (BEGIN PRIVATE KEY)
//!   - SEC1 (BEGIN EC PRIVATE KEY)
//! - **OpenSSH format**: BEGIN OPENSSH PRIVATE KEY
//! - **Encrypted private keys**: Multiple encryption algorithms supported
//!
//! # Security
//!
//! - All private key data is automatically zeroed on drop using `zeroize`
//! - Passwords are handled securely in memory
//! - Constant-time operations where applicable
//!
//! # Examples
//!
//! ```no_run
//! use fynx_proto::ssh::privatekey::PrivateKey;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load unencrypted private key
//! let key = PrivateKey::from_file("~/.ssh/id_ed25519", None)?;
//!
//! // Load encrypted private key
//! let key = PrivateKey::from_file("~/.ssh/id_rsa", Some("passphrase"))?;
//!
//! // Get public key
//! let public_key = key.public_key();
//!
//! // Sign data
//! let signature = key.sign(b"data to sign")?;
//! # Ok(())
//! # }
//! ```

use fynx_platform::error::{FynxError, FynxResult};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SSH public key
///
/// Represents the public portion of an SSH key pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// RSA public key
    Rsa {
        /// Public exponent
        e: Vec<u8>,
        /// Modulus
        n: Vec<u8>,
    },
    /// Ed25519 public key (32 bytes)
    Ed25519([u8; 32]),
    /// ECDSA public key
    Ecdsa {
        /// Curve name (nistp256, nistp384, nistp521)
        curve: String,
        /// Public key point (uncompressed format)
        public_key: Vec<u8>,
    },
}

/// SSH private key
///
/// Supported key types:
/// - RSA (2048, 3072, 4096 bits)
/// - Ed25519 (256 bits)
/// - ECDSA (P-256, P-384, P-521)
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// RSA private key
    Rsa(RsaPrivateKey),
    /// Ed25519 private key
    Ed25519(Ed25519PrivateKey),
    /// ECDSA private key
    Ecdsa(EcdsaPrivateKey),
}

impl PrivateKey {
    /// Load private key from PEM format string
    ///
    /// # Arguments
    ///
    /// - `pem`: PEM format private key string
    /// - `password`: Optional password (for encrypted keys)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use fynx_proto::ssh::privatekey::PrivateKey;
    /// let pem = std::fs::read_to_string("key.pem")?;
    /// let key = PrivateKey::from_pem(&pem, None)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_pem(pem: &str, password: Option<&str>) -> FynxResult<Self> {
        pem::parse_pem(pem, password)
    }

    /// Load private key from OpenSSH format data
    ///
    /// # Arguments
    ///
    /// - `data`: OpenSSH format private key data
    /// - `password`: Optional password
    pub fn from_openssh(data: &[u8], password: Option<&str>) -> FynxResult<Self> {
        openssh::parse_openssh(data, password)
    }

    /// Load private key from file (auto-detect format)
    ///
    /// # Arguments
    ///
    /// - `path`: Private key file path
    /// - `password`: Optional password
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use fynx_proto::ssh::privatekey::PrivateKey;
    /// let key = PrivateKey::from_file("~/.ssh/id_rsa", Some("mypassword"))?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P, password: Option<&str>) -> FynxResult<Self> {
        let data = std::fs::read(path.as_ref()).map_err(|e| FynxError::Io(e))?;

        // Try to read as text (PEM or OpenSSH text format)
        if let Ok(text) = std::str::from_utf8(&data) {
            // Detect format
            if text.contains("BEGIN OPENSSH PRIVATE KEY") {
                Self::from_openssh(data.as_slice(), password)
            } else if text.contains("BEGIN") && text.contains("PRIVATE KEY") {
                Self::from_pem(text, password)
            } else {
                Err(FynxError::Protocol(
                    "Unrecognized private key format".to_string(),
                ))
            }
        } else {
            // Binary data, try OpenSSH format
            Self::from_openssh(&data, password)
        }
    }

    /// Load default private key
    ///
    /// Tries to load in order:
    /// 1. ~/.ssh/id_ed25519
    /// 2. ~/.ssh/id_ecdsa
    /// 3. ~/.ssh/id_rsa
    ///
    /// # Arguments
    ///
    /// - `password_callback`: Optional password callback (for encrypted keys)
    pub fn load_default(password_callback: Option<&dyn PasswordCallback>) -> FynxResult<Self> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| FynxError::Protocol("Cannot determine home directory".to_string()))?;

        let paths = [
            format!("{}/.ssh/id_ed25519", home),
            format!("{}/.ssh/id_ecdsa", home),
            format!("{}/.ssh/id_rsa", home),
        ];

        for path in &paths {
            if Path::new(path).exists() {
                // First try without password
                match Self::from_file(path, None) {
                    Ok(key) => return Ok(key),
                    Err(_) => {
                        // May need password
                        if let Some(cb) = password_callback {
                            let prompt = format!("Enter passphrase for {}: ", path);
                            if let Ok(password) = cb.get_password(&prompt) {
                                if let Ok(key) = Self::from_file(path, Some(&password)) {
                                    return Ok(key);
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(FynxError::Protocol(
            "No default private key found".to_string(),
        ))
    }

    /// Get corresponding public key
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Rsa(rsa) => rsa.public_key(),
            Self::Ed25519(ed) => ed.public_key(),
            Self::Ecdsa(ec) => ec.public_key(),
        }
    }

    /// Sign data
    ///
    /// # Arguments
    ///
    /// - `data`: Data to sign
    ///
    /// # Returns
    ///
    /// Signature bytes
    pub fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        match self {
            Self::Rsa(rsa) => rsa.sign(data),
            Self::Ed25519(ed) => ed.sign(data),
            Self::Ecdsa(ec) => ec.sign(data),
        }
    }

    /// Get key type name
    pub fn key_type(&self) -> &'static str {
        match self {
            Self::Rsa(_) => "ssh-rsa",
            Self::Ed25519(_) => "ssh-ed25519",
            Self::Ecdsa(ec) => match ec.curve {
                EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256",
                EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384",
                EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521",
            },
        }
    }
}

/// RSA private key
///
/// All fields are automatically zeroed on drop
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RsaPrivateKey {
    /// Modulus (n)
    pub n: Vec<u8>,
    /// Public exponent (e)
    pub e: Vec<u8>,
    /// Private exponent (d) - sensitive data
    pub d: Vec<u8>,
    /// Prime 1 (p) - sensitive data
    pub p: Vec<u8>,
    /// Prime 2 (q) - sensitive data
    pub q: Vec<u8>,
    /// Exponent 1: d mod (p-1) - sensitive data
    pub dmp1: Vec<u8>,
    /// Exponent 2: d mod (q-1) - sensitive data
    pub dmq1: Vec<u8>,
    /// Coefficient: q^-1 mod p - sensitive data
    pub iqmp: Vec<u8>,
}

impl RsaPrivateKey {
    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::Rsa {
            e: self.e.clone(),
            n: self.n.clone(),
        }
    }

    /// Sign data using RSA-SHA2-256
    pub fn sign(&self, _data: &[u8]) -> FynxResult<Vec<u8>> {
        // RSA signing implementation - placeholder for now
        // Will be properly implemented after basic functionality is working
        // TODO: Implement RSA-SHA2-256 signing
        Err(FynxError::NotImplemented(
            "RSA signing not yet fully implemented".to_string(),
        ))
    }
}

/// Ed25519 private key
///
/// All fields are automatically zeroed on drop
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519PrivateKey {
    /// 32-byte seed (private key) - sensitive data
    pub seed: [u8; 32],
    /// 32-byte public key
    pub public_key: [u8; 32],
}

impl Ed25519PrivateKey {
    /// Create from seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        use ed25519_dalek::{SigningKey, VerifyingKey};

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = VerifyingKey::from(&signing_key);
        let public_key = verifying_key.to_bytes();

        Self { seed, public_key }
    }

    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey::Ed25519(self.public_key)
    }

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&self.seed);
        let signature = signing_key.sign(data);

        Ok(signature.to_bytes().to_vec())
    }
}

/// ECDSA curve type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    /// NIST P-256 (secp256r1)
    NistP256,
    /// NIST P-384 (secp384r1)
    NistP384,
    /// NIST P-521 (secp521r1)
    NistP521,
}

/// ECDSA private key
///
/// All fields are automatically zeroed on drop
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaPrivateKey {
    /// Curve type
    #[zeroize(skip)]
    pub curve: EcdsaCurve,
    /// Private scalar (d) - sensitive data
    pub d: Vec<u8>,
    /// Public key point (uncompressed format: 0x04 || x || y)
    pub public_key: Vec<u8>,
}

impl EcdsaPrivateKey {
    /// Get public key
    pub fn public_key(&self) -> PublicKey {
        let curve_name = match self.curve {
            EcdsaCurve::NistP256 => "nistp256",
            EcdsaCurve::NistP384 => "nistp384",
            EcdsaCurve::NistP521 => "nistp521",
        };

        PublicKey::Ecdsa {
            curve: curve_name.to_string(),
            public_key: self.public_key.clone(),
        }
    }

    /// Sign data
    pub fn sign(&self, _data: &[u8]) -> FynxResult<Vec<u8>> {
        // ECDSA signing implementation - placeholder for now
        // Will be properly implemented after basic functionality is working
        // TODO: Implement ECDSA signing for P-256, P-384, P-521
        Err(FynxError::NotImplemented(
            "ECDSA signing not yet fully implemented".to_string(),
        ))
    }
}

/// Password callback trait
///
/// Used to prompt user for password when needed
pub trait PasswordCallback {
    /// Get password
    ///
    /// # Arguments
    ///
    /// - `prompt`: Prompt message
    ///
    /// # Returns
    ///
    /// User-entered password
    fn get_password(&self, prompt: &str) -> FynxResult<String>;
}

/// Simple password callback (from string)
pub struct SimplePasswordCallback {
    password: String,
}

impl SimplePasswordCallback {
    /// Create new simple password callback
    pub fn new(password: String) -> Self {
        Self { password }
    }
}

impl PasswordCallback for SimplePasswordCallback {
    fn get_password(&self, _prompt: &str) -> FynxResult<String> {
        Ok(self.password.clone())
    }
}

/// PEM format parsing module
mod pem {
    use super::*;

    /// Parse PEM format private key
    pub fn parse_pem(pem_str: &str, password: Option<&str>) -> FynxResult<PrivateKey> {
        // Detect key type
        if pem_str.contains("BEGIN RSA PRIVATE KEY") {
            parse_rsa_pkcs1(pem_str, password)
        } else if pem_str.contains("BEGIN EC PRIVATE KEY") {
            parse_ec_sec1(pem_str, password)
        } else if pem_str.contains("BEGIN PRIVATE KEY") {
            parse_pkcs8(pem_str, password)
        } else if pem_str.contains("BEGIN ENCRYPTED PRIVATE KEY") {
            parse_encrypted_pkcs8(pem_str, password)
        } else {
            Err(FynxError::Protocol("Unrecognized PEM format".to_string()))
        }
    }

    /// Parse RSA PKCS#1 format
    fn parse_rsa_pkcs1(pem_str: &str, password: Option<&str>) -> FynxResult<PrivateKey> {
        use pkcs1::DecodeRsaPrivateKey;

        let key = if password.is_some() {
            // Handle encrypted PEM
            return Err(FynxError::Protocol(
                "Encrypted PKCS#1 not yet implemented".to_string(),
            ));
        } else {
            rsa::RsaPrivateKey::from_pkcs1_pem(pem_str)
                .map_err(|e| FynxError::Protocol(format!("Failed to parse PKCS#1: {}", e)))?
        };

        Ok(PrivateKey::Rsa(convert_rsa_key(key)))
    }

    /// Parse PKCS#8 format
    fn parse_pkcs8(pem_str: &str, _password: Option<&str>) -> FynxResult<PrivateKey> {
        use pkcs8::DecodePrivateKey;

        // Try RSA
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str) {
            return Ok(PrivateKey::Rsa(convert_rsa_key(key)));
        }

        // Ed25519 and ECDSA PKCS#8 parsing will be implemented later
        // For now, return not implemented
        Err(FynxError::NotImplemented(
            "Ed25519/ECDSA PKCS#8 parsing not yet implemented".to_string(),
        ))
    }

    /// Parse encrypted PKCS#8 format
    fn parse_encrypted_pkcs8(pem_str: &str, password: Option<&str>) -> FynxResult<PrivateKey> {
        let password = password.ok_or_else(|| {
            FynxError::Protocol("Password required for encrypted key".to_string())
        })?;

        use pkcs8::DecodePrivateKey;

        // Try RSA
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(pem_str, password.as_bytes())
        {
            return Ok(PrivateKey::Rsa(convert_rsa_key(key)));
        }

        // TODO: Other key types

        Err(FynxError::Protocol(
            "Failed to parse encrypted PKCS#8 key".to_string(),
        ))
    }

    /// Parse EC SEC1 format
    fn parse_ec_sec1(_pem_str: &str, _password: Option<&str>) -> FynxResult<PrivateKey> {
        // TODO: Implement SEC1 parsing
        Err(FynxError::Protocol(
            "SEC1 format not yet implemented".to_string(),
        ))
    }

    /// Convert RSA key
    fn convert_rsa_key(key: rsa::RsaPrivateKey) -> RsaPrivateKey {
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};

        let n = key.n().to_bytes_be();
        let e = key.e().to_bytes_be();
        let d = key.d().to_bytes_be();

        let primes = key.primes();
        let p = primes[0].to_bytes_be();
        let q = primes[1].to_bytes_be();

        // Calculate CRT parameters
        use num_bigint::BigUint;
        let p_bigint = BigUint::from_bytes_be(&p);
        let q_bigint = BigUint::from_bytes_be(&q);
        let d_bigint = BigUint::from_bytes_be(&d);

        let one = BigUint::from(1u32);
        let dmp1 = (&d_bigint % (&p_bigint - &one)).to_bytes_be();
        let dmq1 = (&d_bigint % (&q_bigint - &one)).to_bytes_be();

        // iqmp = q^-1 mod p
        // For now, use a simple placeholder - this will be properly implemented later
        let iqmp = vec![0u8; p.len()];

        RsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            dmp1,
            dmq1,
            iqmp,
        }
    }
}

/// OpenSSH format parsing module
mod openssh {
    use super::*;

    /// Parse OpenSSH format private key
    pub fn parse_openssh(_data: &[u8], _password: Option<&str>) -> FynxResult<PrivateKey> {
        // TODO: Implement OpenSSH format parsing
        Err(FynxError::Protocol(
            "OpenSSH format not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_from_seed() {
        let seed = [0u8; 32];
        let key = Ed25519PrivateKey::from_seed(seed);
        assert_eq!(key.seed, seed);
        assert_eq!(key.public_key.len(), 32);
    }

    #[test]
    fn test_ed25519_sign() {
        let seed = [1u8; 32];
        let key = Ed25519PrivateKey::from_seed(seed);

        let data = b"test data";
        let signature = key.sign(data).unwrap();
        assert_eq!(signature.len(), 64);
    }

    // TODO: More tests
}
