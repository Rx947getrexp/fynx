//! SSH Host Key Algorithms
//!
//! This module implements host key algorithms for SSH server authentication
//! according to RFC 4253 Section 6.6.
//!
//! # Supported Algorithms
//!
//! - `ssh-ed25519` - EdDSA signature using Ed25519 (RECOMMENDED, modern)
//! - `rsa-sha2-256` - RSA signature with SHA-256 (REQUIRED)
//! - `rsa-sha2-512` - RSA signature with SHA-512 (REQUIRED)
//!
//! # Security
//!
//! - Ed25519 provides 128-bit security with constant-time operations
//! - RSA keys must be ≥ 2048 bits (3072+ bits recommended)
//! - SHA-256 and SHA-512 are used instead of deprecated SHA-1
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::hostkey::{HostKey, Ed25519HostKey};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new Ed25519 host key
//! let hostkey = Ed25519HostKey::generate()?;
//!
//! // Get the public key bytes
//! let public_key = hostkey.public_key_bytes();
//!
//! // Sign data
//! let signature = hostkey.sign(b"data to sign")?;
//!
//! // Verify signature
//! assert!(Ed25519HostKey::verify(&public_key, b"data to sign", &signature)?);
//! # Ok(())
//! # }
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use fynx_platform::{FynxError, FynxResult};
use ring::signature::{
    RsaKeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA512,
};
use zeroize::Zeroizing;

/// Host key algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyAlgorithm {
    /// ssh-ed25519 - EdDSA signature using Ed25519 (RECOMMENDED, modern)
    SshEd25519,
    /// rsa-sha2-256 - RSA signature with SHA-256 (REQUIRED)
    RsaSha2_256,
    /// rsa-sha2-512 - RSA signature with SHA-512 (REQUIRED)
    RsaSha2_512,
    /// ssh-rsa - Legacy RSA with SHA-1 (DEPRECATED, for compatibility only)
    SshRsa,
    /// ecdsa-sha2-nistp256 - ECDSA signature using P-256 curve
    EcdsaSha2Nistp256,
    /// ecdsa-sha2-nistp384 - ECDSA signature using P-384 curve
    EcdsaSha2Nistp384,
    /// ecdsa-sha2-nistp521 - ECDSA signature using P-521 curve
    EcdsaSha2Nistp521,
}

impl HostKeyAlgorithm {
    /// Get the algorithm name as specified in RFC 4253
    pub fn name(&self) -> &'static str {
        match self {
            HostKeyAlgorithm::SshEd25519 => "ssh-ed25519",
            HostKeyAlgorithm::RsaSha2_256 => "rsa-sha2-256",
            HostKeyAlgorithm::RsaSha2_512 => "rsa-sha2-512",
            HostKeyAlgorithm::SshRsa => "ssh-rsa",
            HostKeyAlgorithm::EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256",
            HostKeyAlgorithm::EcdsaSha2Nistp384 => "ecdsa-sha2-nistp384",
            HostKeyAlgorithm::EcdsaSha2Nistp521 => "ecdsa-sha2-nistp521",
        }
    }

    /// Parse algorithm from name
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(HostKeyAlgorithm::SshEd25519),
            "rsa-sha2-256" => Some(HostKeyAlgorithm::RsaSha2_256),
            "rsa-sha2-512" => Some(HostKeyAlgorithm::RsaSha2_512),
            "ssh-rsa" => Some(HostKeyAlgorithm::SshRsa),
            "ecdsa-sha2-nistp256" => Some(HostKeyAlgorithm::EcdsaSha2Nistp256),
            "ecdsa-sha2-nistp384" => Some(HostKeyAlgorithm::EcdsaSha2Nistp384),
            "ecdsa-sha2-nistp521" => Some(HostKeyAlgorithm::EcdsaSha2Nistp521),
            _ => None,
        }
    }
}

/// Trait for host key operations
pub trait HostKey: Send + Sync {
    /// Get the algorithm identifier
    fn algorithm(&self) -> HostKeyAlgorithm;

    /// Get the public key in SSH wire format
    ///
    /// Format: string algorithm_name, followed by algorithm-specific data
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Sign data and return signature in SSH wire format
    ///
    /// The signature format depends on the algorithm:
    /// - Ed25519: string "ssh-ed25519", string signature (64 bytes)
    /// - RSA: string "rsa-sha2-256" or "rsa-sha2-512", string signature
    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>>;

    /// Get the algorithm name
    fn algorithm_name(&self) -> &'static str {
        self.algorithm().name()
    }
}

/// Ed25519 host key (ssh-ed25519)
///
/// Provides 128-bit security with constant-time operations.
/// This is the recommended modern host key algorithm.
#[derive(Clone)]
pub struct Ed25519HostKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519HostKey {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> FynxResult<Self> {
        let mut csprng = rand::thread_rng();
        let secret_bytes: [u8; SECRET_KEY_LENGTH] = rand::Rng::gen(&mut csprng);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create from raw key bytes (32-byte secret key)
    pub fn from_bytes(secret_bytes: &[u8]) -> FynxResult<Self> {
        if secret_bytes.len() != 32 {
            return Err(FynxError::Security(
                "Ed25519 secret key must be 32 bytes".to_string(),
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(secret_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the secret key bytes (32 bytes)
    ///
    /// WARNING: This exposes the private key material. Handle with care.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Verify an Ed25519 signature
    ///
    /// # Arguments
    ///
    /// * `public_key` - The 32-byte Ed25519 public key
    /// * `data` - The data that was signed
    /// * `signature` - The 64-byte signature
    pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> FynxResult<bool> {
        if public_key.len() != 32 {
            return Err(FynxError::Security(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }
        if signature.len() != 64 {
            return Err(FynxError::Security(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| FynxError::Security(format!("Invalid Ed25519 public key: {}", e)))?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(data, &signature).is_ok())
    }
}

impl HostKey for Ed25519HostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::SshEd25519
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Algorithm name
        let alg_name = b"ssh-ed25519";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        // Public key (32 bytes)
        let public_key = self.verifying_key.as_bytes();
        bytes.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
        bytes.extend_from_slice(public_key);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        let signature = self.signing_key.sign(data);

        let mut bytes = Vec::new();

        // Algorithm name
        let alg_name = b"ssh-ed25519";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        // Signature (64 bytes)
        let sig_bytes = signature.to_bytes();
        bytes.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&sig_bytes);

        Ok(bytes)
    }
}

impl std::fmt::Debug for Ed25519HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519HostKey")
            .field("algorithm", &"ssh-ed25519")
            .field("public_key", &hex::encode(self.verifying_key.as_bytes()))
            .finish_non_exhaustive()
    }
}

/// RSA host key with SHA-256 (rsa-sha2-256)
///
/// Uses RSA signature with SHA-256 hash.
/// Minimum key size is 2048 bits, 3072+ bits recommended.
pub struct RsaSha2_256HostKey {
    key_pair: RsaKeyPair,
    public_key_der: Vec<u8>,
}

impl RsaSha2_256HostKey {
    /// Create from DER-encoded private key
    ///
    /// The private key should be in PKCS#8 DER format.
    pub fn from_der(private_key_der: &[u8]) -> FynxResult<Self> {
        let key_pair = RsaKeyPair::from_pkcs8(private_key_der)
            .map_err(|e| FynxError::Security(format!("Invalid RSA private key: {:?}", e)))?;

        let public_key_der = key_pair.public().as_ref().to_vec();

        Ok(Self {
            key_pair,
            public_key_der,
        })
    }

    /// Get the public key in DER format
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Verify an RSA-SHA256 signature
    ///
    /// # Arguments
    ///
    /// * `public_key_der` - The DER-encoded RSA public key
    /// * `data` - The data that was signed
    /// * `signature` - The RSA signature
    pub fn verify(public_key_der: &[u8], data: &[u8], signature: &[u8]) -> FynxResult<bool> {
        use ring::signature::UnparsedPublicKey;

        let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der);
        Ok(public_key.verify(data, signature).is_ok())
    }
}

impl HostKey for RsaSha2_256HostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::RsaSha2_256
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Algorithm name
        let alg_name = b"rsa-sha2-256";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        // Public key in SSH RSA format
        // For now, we'll include the DER-encoded key
        // TODO: Parse DER and encode as SSH RSA format (e, n)
        bytes.extend_from_slice(&(self.public_key_der.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.public_key_der);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        let mut signature = vec![0u8; self.key_pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();

        self.key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, data, &mut signature)
            .map_err(|e| FynxError::Security(format!("RSA signing failed: {:?}", e)))?;

        let mut bytes = Vec::new();

        // Algorithm name
        let alg_name = b"rsa-sha2-256";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        // Signature
        bytes.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&signature);

        Ok(bytes)
    }
}

impl std::fmt::Debug for RsaSha2_256HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSha2_256HostKey")
            .field("algorithm", &"rsa-sha2-256")
            .field("key_size_bits", &(self.key_pair.public().modulus_len() * 8))
            .finish_non_exhaustive()
    }
}

/// RSA host key with SHA-512 (rsa-sha2-512)
///
/// Uses RSA signature with SHA-512 hash.
/// Minimum key size is 2048 bits, 3072+ bits recommended.
pub struct RsaSha2_512HostKey {
    key_pair: RsaKeyPair,
    public_key_der: Vec<u8>,
}

impl RsaSha2_512HostKey {
    /// Create from DER-encoded private key
    ///
    /// The private key should be in PKCS#8 DER format.
    pub fn from_der(private_key_der: &[u8]) -> FynxResult<Self> {
        let key_pair = RsaKeyPair::from_pkcs8(private_key_der)
            .map_err(|e| FynxError::Security(format!("Invalid RSA private key: {:?}", e)))?;

        let public_key_der = key_pair.public().as_ref().to_vec();

        Ok(Self {
            key_pair,
            public_key_der,
        })
    }

    /// Get the public key in DER format
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Verify an RSA-SHA512 signature
    ///
    /// # Arguments
    ///
    /// * `public_key_der` - The DER-encoded RSA public key
    /// * `data` - The data that was signed
    /// * `signature` - The RSA signature
    pub fn verify(public_key_der: &[u8], data: &[u8], signature: &[u8]) -> FynxResult<bool> {
        use ring::signature::UnparsedPublicKey;

        let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, public_key_der);
        Ok(public_key.verify(data, signature).is_ok())
    }
}

impl HostKey for RsaSha2_512HostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::RsaSha2_512
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Algorithm name
        let alg_name = b"rsa-sha2-512";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        // Public key in SSH RSA format
        // For now, we'll include the DER-encoded key
        // TODO: Parse DER and encode as SSH RSA format (e, n)
        bytes.extend_from_slice(&(self.public_key_der.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.public_key_der);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        let mut signature = vec![0u8; self.key_pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();

        self.key_pair
            .sign(&RSA_PKCS1_SHA512, &rng, data, &mut signature)
            .map_err(|e| FynxError::Security(format!("RSA signing failed: {:?}", e)))?;

        let mut bytes = Vec::new();

        // Algorithm name
        let alg_name = b"rsa-sha2-512";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        // Signature
        bytes.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&signature);

        Ok(bytes)
    }
}

impl std::fmt::Debug for RsaSha2_512HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaSha2_512HostKey")
            .field("algorithm", &"rsa-sha2-512")
            .field("key_size_bits", &(self.key_pair.public().modulus_len() * 8))
            .finish_non_exhaustive()
    }
}

/// RSA host key with SHA-1 (ssh-rsa)
///
/// **DEPRECATED**: Uses RSA signature with SHA-1 hash.
/// Only provided for compatibility with legacy systems.
/// Use RsaSha2_256HostKey or RsaSha2_512HostKey instead.
pub struct SshRsaHostKey {
    key_pair: RsaKeyPair,
    public_key_der: Vec<u8>,
}

impl SshRsaHostKey {
    /// Create from DER-encoded private key
    ///
    /// **SECURITY WARNING**: This uses SHA-1 which is deprecated.
    /// Only use for compatibility with legacy systems.
    pub fn from_der(private_key_der: &[u8]) -> FynxResult<Self> {
        let key_pair = RsaKeyPair::from_pkcs8(private_key_der)
            .map_err(|e| FynxError::Security(format!("Invalid RSA private key: {:?}", e)))?;

        let public_key_der = key_pair.public().as_ref().to_vec();

        Ok(Self {
            key_pair,
            public_key_der,
        })
    }

    /// Get the public key in DER format
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }
}

impl HostKey for SshRsaHostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::SshRsa
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let alg_name = b"ssh-rsa";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        bytes.extend_from_slice(&(self.public_key_der.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.public_key_der);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        // Note: ssh-rsa uses SHA-1 which is deprecated
        // Ring doesn't support RSA-SHA1 signing (only verification for legacy)
        // For now, we'll use SHA-256 internally as a placeholder
        // Real implementation would need a different crypto library for SHA-1 signing

        let mut signature = vec![0u8; self.key_pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();

        // Using SHA-256 as Ring doesn't support SHA-1 signing
        self.key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, data, &mut signature)
            .map_err(|e| FynxError::Security(format!("RSA signing failed: {:?}", e)))?;

        let mut bytes = Vec::new();
        let alg_name = b"ssh-rsa";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);
        bytes.extend_from_slice(&(signature.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&signature);

        Ok(bytes)
    }
}

impl std::fmt::Debug for SshRsaHostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshRsaHostKey")
            .field("algorithm", &"ssh-rsa (DEPRECATED)")
            .field("key_size_bits", &(self.key_pair.public().modulus_len() * 8))
            .finish_non_exhaustive()
    }
}

/// ECDSA host key with P-256 curve (ecdsa-sha2-nistp256)
///
/// Uses ECDSA signature with SHA-256 hash and NIST P-256 curve.
pub struct EcdsaP256HostKey {
    signing_key: p256::ecdsa::SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
}

impl EcdsaP256HostKey {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate() -> FynxResult<Self> {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &p256::ecdsa::VerifyingKey {
        &self.verifying_key
    }

    /// Verify an ECDSA P-256 signature
    pub fn verify(public_key_bytes: &[u8], data: &[u8], signature: &[u8]) -> FynxResult<bool> {
        use signature::Verifier;

        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| FynxError::Security(format!("Invalid P-256 public key: {}", e)))?;

        let sig = p256::ecdsa::Signature::from_slice(signature)
            .map_err(|e| FynxError::Security(format!("Invalid P-256 signature: {}", e)))?;

        Ok(verifying_key.verify(data, &sig).is_ok())
    }
}

impl HostKey for EcdsaP256HostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::EcdsaSha2Nistp256
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let alg_name = b"ecdsa-sha2-nistp256";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        let curve_name = b"nistp256";
        bytes.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(curve_name);

        let public_key = self.verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();
        bytes.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(public_key_bytes);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        use signature::Signer;

        let signature: p256::ecdsa::Signature = self.signing_key.sign(data);

        let mut bytes = Vec::new();
        let alg_name = b"ecdsa-sha2-nistp256";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        let sig_bytes = signature.to_bytes();
        bytes.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&sig_bytes);

        Ok(bytes)
    }
}

impl std::fmt::Debug for EcdsaP256HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP256HostKey")
            .field("algorithm", &"ecdsa-sha2-nistp256")
            .field("curve", &"P-256")
            .finish_non_exhaustive()
    }
}

/// ECDSA host key with P-384 curve (ecdsa-sha2-nistp384)
///
/// Uses ECDSA signature with SHA-384 hash and NIST P-384 curve.
pub struct EcdsaP384HostKey {
    signing_key: p384::ecdsa::SigningKey,
    verifying_key: p384::ecdsa::VerifyingKey,
}

impl EcdsaP384HostKey {
    /// Generate a new ECDSA P-384 key pair
    pub fn generate() -> FynxResult<Self> {
        let signing_key = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let verifying_key = p384::ecdsa::VerifyingKey::from(&signing_key);
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &p384::ecdsa::VerifyingKey {
        &self.verifying_key
    }

    /// Verify an ECDSA P-384 signature
    pub fn verify(public_key_bytes: &[u8], data: &[u8], signature: &[u8]) -> FynxResult<bool> {
        use signature::Verifier;

        let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| FynxError::Security(format!("Invalid P-384 public key: {}", e)))?;

        let sig = p384::ecdsa::Signature::from_slice(signature)
            .map_err(|e| FynxError::Security(format!("Invalid P-384 signature: {}", e)))?;

        Ok(verifying_key.verify(data, &sig).is_ok())
    }
}

impl HostKey for EcdsaP384HostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::EcdsaSha2Nistp384
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let alg_name = b"ecdsa-sha2-nistp384";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        let curve_name = b"nistp384";
        bytes.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(curve_name);

        let public_key = self.verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();
        bytes.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(public_key_bytes);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        use signature::Signer;

        let signature: p384::ecdsa::Signature = self.signing_key.sign(data);

        let mut bytes = Vec::new();
        let alg_name = b"ecdsa-sha2-nistp384";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        let sig_bytes = signature.to_bytes();
        bytes.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&sig_bytes);

        Ok(bytes)
    }
}

impl std::fmt::Debug for EcdsaP384HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP384HostKey")
            .field("algorithm", &"ecdsa-sha2-nistp384")
            .field("curve", &"P-384")
            .finish_non_exhaustive()
    }
}

/// ECDSA host key with P-521 curve (ecdsa-sha2-nistp521)
///
/// Uses ECDSA signature with SHA-512 hash and NIST P-521 curve.
pub struct EcdsaP521HostKey {
    signing_key: p521::ecdsa::SigningKey,
    verifying_key: p521::ecdsa::VerifyingKey,
}

impl EcdsaP521HostKey {
    /// Generate a new ECDSA P-521 key pair
    pub fn generate() -> FynxResult<Self> {
        let signing_key = p521::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &p521::ecdsa::VerifyingKey {
        &self.verifying_key
    }

    /// Verify an ECDSA P-521 signature
    pub fn verify(public_key_bytes: &[u8], data: &[u8], signature: &[u8]) -> FynxResult<bool> {
        use signature::Verifier;

        let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes)
            .map_err(|e| FynxError::Security(format!("Invalid P-521 public key: {}", e)))?;

        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|e| FynxError::Security(format!("Invalid P-521 signature: {}", e)))?;

        Ok(verifying_key.verify(data, &sig).is_ok())
    }
}

impl HostKey for EcdsaP521HostKey {
    fn algorithm(&self) -> HostKeyAlgorithm {
        HostKeyAlgorithm::EcdsaSha2Nistp521
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let alg_name = b"ecdsa-sha2-nistp521";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        let curve_name = b"nistp521";
        bytes.extend_from_slice(&(curve_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(curve_name);

        let public_key = self.verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();
        bytes.extend_from_slice(&(public_key_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(public_key_bytes);

        bytes
    }

    fn sign(&self, data: &[u8]) -> FynxResult<Vec<u8>> {
        use signature::Signer;

        let signature: p521::ecdsa::Signature = self.signing_key.sign(data);

        let mut bytes = Vec::new();
        let alg_name = b"ecdsa-sha2-nistp521";
        bytes.extend_from_slice(&(alg_name.len() as u32).to_be_bytes());
        bytes.extend_from_slice(alg_name);

        let sig_bytes = signature.to_bytes();
        bytes.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&sig_bytes);

        Ok(bytes)
    }
}

impl std::fmt::Debug for EcdsaP521HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP521HostKey")
            .field("algorithm", &"ecdsa-sha2-nistp521")
            .field("curve", &"P-521")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_name() {
        assert_eq!(HostKeyAlgorithm::SshEd25519.name(), "ssh-ed25519");
        assert_eq!(HostKeyAlgorithm::RsaSha2_256.name(), "rsa-sha2-256");
        assert_eq!(HostKeyAlgorithm::RsaSha2_512.name(), "rsa-sha2-512");
        assert_eq!(HostKeyAlgorithm::SshRsa.name(), "ssh-rsa");
        assert_eq!(
            HostKeyAlgorithm::EcdsaSha2Nistp256.name(),
            "ecdsa-sha2-nistp256"
        );
        assert_eq!(
            HostKeyAlgorithm::EcdsaSha2Nistp384.name(),
            "ecdsa-sha2-nistp384"
        );
        assert_eq!(
            HostKeyAlgorithm::EcdsaSha2Nistp521.name(),
            "ecdsa-sha2-nistp521"
        );
    }

    #[test]
    fn test_algorithm_from_name() {
        assert_eq!(
            HostKeyAlgorithm::from_name("ssh-ed25519"),
            Some(HostKeyAlgorithm::SshEd25519)
        );
        assert_eq!(
            HostKeyAlgorithm::from_name("rsa-sha2-256"),
            Some(HostKeyAlgorithm::RsaSha2_256)
        );
        assert_eq!(
            HostKeyAlgorithm::from_name("rsa-sha2-512"),
            Some(HostKeyAlgorithm::RsaSha2_512)
        );
        assert_eq!(
            HostKeyAlgorithm::from_name("ssh-rsa"),
            Some(HostKeyAlgorithm::SshRsa)
        );
        assert_eq!(
            HostKeyAlgorithm::from_name("ecdsa-sha2-nistp256"),
            Some(HostKeyAlgorithm::EcdsaSha2Nistp256)
        );
        assert_eq!(
            HostKeyAlgorithm::from_name("ecdsa-sha2-nistp384"),
            Some(HostKeyAlgorithm::EcdsaSha2Nistp384)
        );
        assert_eq!(
            HostKeyAlgorithm::from_name("ecdsa-sha2-nistp521"),
            Some(HostKeyAlgorithm::EcdsaSha2Nistp521)
        );
        assert_eq!(HostKeyAlgorithm::from_name("unknown"), None);
    }

    #[test]
    fn test_ed25519_generate() {
        let key = Ed25519HostKey::generate().unwrap();
        assert_eq!(key.algorithm(), HostKeyAlgorithm::SshEd25519);
        assert_eq!(key.algorithm_name(), "ssh-ed25519");
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let key = Ed25519HostKey::generate().unwrap();
        let data = b"test data to sign";

        // Sign the data
        let signature_blob = key.sign(data).unwrap();

        // Extract signature from blob (skip algorithm name)
        // Format: string alg_name, string signature
        let mut offset = 4; // length of alg_name
        let alg_name_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;
        offset += alg_name_len + 4; // skip alg_name and sig length
        let sig_len = u32::from_be_bytes([
            signature_blob[offset - 4],
            signature_blob[offset - 3],
            signature_blob[offset - 2],
            signature_blob[offset - 1],
        ]) as usize;
        let signature = &signature_blob[offset..offset + sig_len];

        // Verify the signature
        let public_key = key.verifying_key().as_bytes();
        assert!(Ed25519HostKey::verify(public_key, data, signature).unwrap());

        // Verify fails with wrong data
        assert!(!Ed25519HostKey::verify(public_key, b"wrong data", signature).unwrap());
    }

    #[test]
    fn test_ed25519_from_bytes() {
        let key1 = Ed25519HostKey::generate().unwrap();
        let secret = key1.secret_bytes();

        let key2 = Ed25519HostKey::from_bytes(&*secret).unwrap();

        // Both keys should produce the same public key
        assert_eq!(
            key1.verifying_key().as_bytes(),
            key2.verifying_key().as_bytes()
        );
    }

    #[test]
    fn test_ed25519_public_key_bytes() {
        let key = Ed25519HostKey::generate().unwrap();
        let public_key_blob = key.public_key_bytes();

        // Verify format: string alg_name, string public_key
        assert!(public_key_blob.len() > 8); // At least algorithm name length + alg name + key length

        // Check algorithm name
        let alg_name_len = u32::from_be_bytes([
            public_key_blob[0],
            public_key_blob[1],
            public_key_blob[2],
            public_key_blob[3],
        ]) as usize;
        assert_eq!(alg_name_len, 11); // "ssh-ed25519".len()

        let alg_name = &public_key_blob[4..4 + alg_name_len];
        assert_eq!(alg_name, b"ssh-ed25519");
    }

    #[test]
    fn test_ed25519_debug() {
        let key = Ed25519HostKey::generate().unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("Ed25519HostKey"));
        assert!(debug_str.contains("ssh-ed25519"));
    }

    #[test]
    fn test_ecdsa_p256_generate() {
        let key = EcdsaP256HostKey::generate().unwrap();
        assert_eq!(key.algorithm(), HostKeyAlgorithm::EcdsaSha2Nistp256);
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp256");
    }

    #[test]
    fn test_ecdsa_p256_sign_verify() {
        let key = EcdsaP256HostKey::generate().unwrap();
        let data = b"test data for ecdsa p256";

        // Sign the data
        let signature_blob = key.sign(data).unwrap();

        // Extract signature from blob
        let mut offset = 4;
        let alg_name_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;
        offset += alg_name_len + 4;
        let sig_len = u32::from_be_bytes([
            signature_blob[offset - 4],
            signature_blob[offset - 3],
            signature_blob[offset - 2],
            signature_blob[offset - 1],
        ]) as usize;
        let signature = &signature_blob[offset..offset + sig_len];

        // Verify the signature
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let public_key = key.verifying_key().to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();

        assert!(EcdsaP256HostKey::verify(public_key_bytes, data, signature).unwrap());

        // Verify fails with wrong data
        assert!(!EcdsaP256HostKey::verify(public_key_bytes, b"wrong data", signature).unwrap());
    }

    #[test]
    fn test_ecdsa_p384_generate() {
        let key = EcdsaP384HostKey::generate().unwrap();
        assert_eq!(key.algorithm(), HostKeyAlgorithm::EcdsaSha2Nistp384);
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp384");
    }

    #[test]
    fn test_ecdsa_p384_sign_verify() {
        let key = EcdsaP384HostKey::generate().unwrap();
        let data = b"test data for ecdsa p384";

        // Sign the data
        let signature_blob = key.sign(data).unwrap();

        // Extract signature from blob
        let mut offset = 4;
        let alg_name_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;
        offset += alg_name_len + 4;
        let sig_len = u32::from_be_bytes([
            signature_blob[offset - 4],
            signature_blob[offset - 3],
            signature_blob[offset - 2],
            signature_blob[offset - 1],
        ]) as usize;
        let signature = &signature_blob[offset..offset + sig_len];

        // Verify the signature
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let public_key = key.verifying_key().to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();

        assert!(EcdsaP384HostKey::verify(public_key_bytes, data, signature).unwrap());

        // Verify fails with wrong data
        assert!(!EcdsaP384HostKey::verify(public_key_bytes, b"wrong data", signature).unwrap());
    }

    #[test]
    fn test_ecdsa_p521_generate() {
        let key = EcdsaP521HostKey::generate().unwrap();
        assert_eq!(key.algorithm(), HostKeyAlgorithm::EcdsaSha2Nistp521);
        assert_eq!(key.algorithm_name(), "ecdsa-sha2-nistp521");
    }

    #[test]
    fn test_ecdsa_p521_sign_verify() {
        let key = EcdsaP521HostKey::generate().unwrap();
        let data = b"test data for ecdsa p521";

        // Sign the data
        let signature_blob = key.sign(data).unwrap();

        // Extract signature from blob
        let mut offset = 4;
        let alg_name_len = u32::from_be_bytes([
            signature_blob[0],
            signature_blob[1],
            signature_blob[2],
            signature_blob[3],
        ]) as usize;
        offset += alg_name_len + 4;
        let sig_len = u32::from_be_bytes([
            signature_blob[offset - 4],
            signature_blob[offset - 3],
            signature_blob[offset - 2],
            signature_blob[offset - 1],
        ]) as usize;
        let signature = &signature_blob[offset..offset + sig_len];

        // Verify the signature
        use p521::elliptic_curve::sec1::ToEncodedPoint;
        let public_key = key.verifying_key().to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();

        assert!(EcdsaP521HostKey::verify(public_key_bytes, data, signature).unwrap());

        // Verify fails with wrong data
        assert!(!EcdsaP521HostKey::verify(public_key_bytes, b"wrong data", signature).unwrap());
    }

    #[test]
    fn test_ecdsa_debug_formats() {
        let p256 = EcdsaP256HostKey::generate().unwrap();
        let debug_str = format!("{:?}", p256);
        assert!(debug_str.contains("EcdsaP256HostKey"));
        assert!(debug_str.contains("ecdsa-sha2-nistp256"));

        let p384 = EcdsaP384HostKey::generate().unwrap();
        let debug_str = format!("{:?}", p384);
        assert!(debug_str.contains("EcdsaP384HostKey"));
        assert!(debug_str.contains("ecdsa-sha2-nistp384"));

        let p521 = EcdsaP521HostKey::generate().unwrap();
        let debug_str = format!("{:?}", p521);
        assert!(debug_str.contains("EcdsaP521HostKey"));
        assert!(debug_str.contains("ecdsa-sha2-nistp521"));
    }
}
