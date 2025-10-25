//! Pseudo-Random Function (PRF) implementations
//!
//! Implements PRF algorithms for IKEv2 key derivation as defined in RFC 7296.

use crate::ipsec::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

/// PRF algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfAlgorithm {
    /// HMAC-SHA2-256
    HmacSha256,
    /// HMAC-SHA2-384
    HmacSha384,
    /// HMAC-SHA2-512
    HmacSha512,
}

impl PrfAlgorithm {
    /// Get PRF output length in bytes
    pub fn output_len(self) -> usize {
        match self {
            PrfAlgorithm::HmacSha256 => 32,
            PrfAlgorithm::HmacSha384 => 48,
            PrfAlgorithm::HmacSha512 => 64,
        }
    }

    /// Compute PRF
    ///
    /// # Arguments
    ///
    /// * `key` - PRF key
    /// * `data` - Input data
    ///
    /// # Returns
    ///
    /// Returns PRF output
    pub fn compute(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            PrfAlgorithm::HmacSha256 => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            PrfAlgorithm::HmacSha384 => {
                let mut mac =
                    Hmac::<Sha384>::new_from_slice(key).expect("HMAC can take key of any size");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            PrfAlgorithm::HmacSha512 => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Compute prf+ (key expansion function)
    ///
    /// Defined in RFC 7296 Section 2.13:
    /// ```text
    /// prf+ (K,S) = T1 | T2 | T3 | T4 | ...
    ///
    /// where:
    /// T1 = prf (K, S | 0x01)
    /// T2 = prf (K, T1 | S | 0x02)
    /// T3 = prf (K, T2 | S | 0x03)
    /// T4 = prf (K, T3 | S | 0x04)
    /// ...
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key` - PRF key
    /// * `seed` - Seed data (S)
    /// * `output_len` - Desired output length in bytes
    ///
    /// # Returns
    ///
    /// Returns expanded key material
    pub fn prf_plus(self, key: &[u8], seed: &[u8], output_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut t = Vec::new();
        let mut counter: u8 = 1;

        while output.len() < output_len {
            // Build input: T(i-1) | S | counter
            let mut input = Vec::new();
            input.extend_from_slice(&t);
            input.extend_from_slice(seed);
            input.push(counter);

            // Compute T(i) = prf(K, T(i-1) | S | counter)
            t = self.compute(key, &input);
            output.extend_from_slice(&t);

            counter += 1;
        }

        output.truncate(output_len);
        output
    }
}

/// IKEv2 key material derived from SKEYSEED
///
/// Contains all keys derived during IKE_SA_INIT exchange.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// SK_d - Key for deriving Child SA keys
    pub sk_d: Vec<u8>,

    /// SK_ai - Initiator's integrity key
    pub sk_ai: Vec<u8>,

    /// SK_ar - Responder's integrity key
    pub sk_ar: Vec<u8>,

    /// SK_ei - Initiator's encryption key
    pub sk_ei: Vec<u8>,

    /// SK_er - Responder's encryption key
    pub sk_er: Vec<u8>,

    /// SK_pi - Initiator's AUTH payload key
    pub sk_pi: Vec<u8>,

    /// SK_pr - Responder's AUTH payload key
    pub sk_pr: Vec<u8>,
}

impl KeyMaterial {
    /// Derive IKEv2 key material from SKEYSEED
    ///
    /// Implements key derivation from RFC 7296 Section 2.14:
    /// ```text
    /// SKEYSEED = prf(Ni | Nr, g^ir)
    ///
    /// {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
    ///     = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `prf_alg` - PRF algorithm to use
    /// * `nonce_i` - Initiator's nonce
    /// * `nonce_r` - Responder's nonce
    /// * `shared_secret` - DH shared secret (g^ir)
    /// * `spi_i` - Initiator's SPI
    /// * `spi_r` - Responder's SPI
    /// * `encr_key_len` - Encryption key length in bytes
    /// * `integ_key_len` - Integrity key length in bytes
    ///
    /// # Returns
    ///
    /// Returns derived key material
    pub fn derive(
        prf_alg: PrfAlgorithm,
        nonce_i: &[u8],
        nonce_r: &[u8],
        shared_secret: &[u8],
        spi_i: &[u8; 8],
        spi_r: &[u8; 8],
        encr_key_len: usize,
        integ_key_len: usize,
    ) -> Result<Self> {
        // Step 1: Compute SKEYSEED = prf(Ni | Nr, g^ir)
        let mut prf_key = Vec::new();
        prf_key.extend_from_slice(nonce_i);
        prf_key.extend_from_slice(nonce_r);

        let skeyseed = prf_alg.compute(&prf_key, shared_secret);

        // Step 2: Build seed for prf+: Ni | Nr | SPIi | SPIr
        let mut seed = Vec::new();
        seed.extend_from_slice(nonce_i);
        seed.extend_from_slice(nonce_r);
        seed.extend_from_slice(spi_i);
        seed.extend_from_slice(spi_r);

        // Step 3: Calculate total key material length needed
        let prf_len = prf_alg.output_len();
        let total_len = prf_len + // SK_d
            integ_key_len + // SK_ai
            integ_key_len + // SK_ar
            encr_key_len + // SK_ei
            encr_key_len + // SK_er
            prf_len + // SK_pi
            prf_len; // SK_pr

        // Step 4: Derive key material using prf+
        let keymat = prf_alg.prf_plus(&skeyseed, &seed, total_len);

        // Step 5: Split into individual keys
        let mut offset = 0;

        let sk_d = keymat[offset..offset + prf_len].to_vec();
        offset += prf_len;

        let sk_ai = keymat[offset..offset + integ_key_len].to_vec();
        offset += integ_key_len;

        let sk_ar = keymat[offset..offset + integ_key_len].to_vec();
        offset += integ_key_len;

        let sk_ei = keymat[offset..offset + encr_key_len].to_vec();
        offset += encr_key_len;

        let sk_er = keymat[offset..offset + encr_key_len].to_vec();
        offset += encr_key_len;

        let sk_pi = keymat[offset..offset + prf_len].to_vec();
        offset += prf_len;

        let sk_pr = keymat[offset..offset + prf_len].to_vec();

        Ok(KeyMaterial {
            sk_d,
            sk_ai,
            sk_ar,
            sk_ei,
            sk_er,
            sk_pi,
            sk_pr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_output_len() {
        assert_eq!(PrfAlgorithm::HmacSha256.output_len(), 32);
        assert_eq!(PrfAlgorithm::HmacSha384.output_len(), 48);
        assert_eq!(PrfAlgorithm::HmacSha512.output_len(), 64);
    }

    #[test]
    fn test_prf_hmac_sha256() {
        let key = b"test key";
        let data = b"test data";

        let output = PrfAlgorithm::HmacSha256.compute(key, data);
        assert_eq!(output.len(), 32);

        // PRF should be deterministic
        let output2 = PrfAlgorithm::HmacSha256.compute(key, data);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_different_algorithms() {
        let key = b"test key";
        let data = b"test data";

        let sha256 = PrfAlgorithm::HmacSha256.compute(key, data);
        let sha384 = PrfAlgorithm::HmacSha384.compute(key, data);
        let sha512 = PrfAlgorithm::HmacSha512.compute(key, data);

        // Different algorithms produce different outputs
        assert_ne!(sha256, sha384);
        assert_ne!(sha256, sha512);
        assert_ne!(sha384, sha512);

        // But same length as specified
        assert_eq!(sha256.len(), 32);
        assert_eq!(sha384.len(), 48);
        assert_eq!(sha512.len(), 64);
    }

    #[test]
    fn test_prf_plus_basic() {
        let key = b"secret key";
        let seed = b"seed data";

        let output = PrfAlgorithm::HmacSha256.prf_plus(key, seed, 64);
        assert_eq!(output.len(), 64);

        // prf+ should be deterministic
        let output2 = PrfAlgorithm::HmacSha256.prf_plus(key, seed, 64);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_prf_plus_expansion() {
        let key = b"secret key";
        let seed = b"seed data";

        // Request more bytes than single PRF output
        let output = PrfAlgorithm::HmacSha256.prf_plus(key, seed, 100);
        assert_eq!(output.len(), 100);

        // First 32 bytes should match first PRF iteration
        let first_block = PrfAlgorithm::HmacSha256.prf_plus(key, seed, 32);
        assert_eq!(&output[0..32], &first_block[..]);
    }

    #[test]
    fn test_prf_plus_different_lengths() {
        let key = b"secret key";
        let seed = b"seed data";

        let short = PrfAlgorithm::HmacSha256.prf_plus(key, seed, 16);
        let long = PrfAlgorithm::HmacSha256.prf_plus(key, seed, 64);

        // Short should be prefix of long
        assert_eq!(&short[..], &long[0..16]);
    }

    #[test]
    fn test_key_material_derivation() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let nonce_i = vec![0x01; 32];
        let nonce_r = vec![0x02; 32];
        let shared_secret = vec![0x03; 256];
        let spi_i = [0x04; 8];
        let spi_r = [0x05; 8];
        let encr_key_len = 32; // AES-256
        let integ_key_len = 32; // HMAC-SHA256

        let keymat = KeyMaterial::derive(
            prf_alg,
            &nonce_i,
            &nonce_r,
            &shared_secret,
            &spi_i,
            &spi_r,
            encr_key_len,
            integ_key_len,
        )
        .unwrap();

        // Check key lengths
        assert_eq!(keymat.sk_d.len(), 32); // PRF output length
        assert_eq!(keymat.sk_ai.len(), 32); // integ_key_len
        assert_eq!(keymat.sk_ar.len(), 32);
        assert_eq!(keymat.sk_ei.len(), 32); // encr_key_len
        assert_eq!(keymat.sk_er.len(), 32);
        assert_eq!(keymat.sk_pi.len(), 32); // PRF output length
        assert_eq!(keymat.sk_pr.len(), 32);

        // Keys should be different
        assert_ne!(keymat.sk_d, keymat.sk_ai);
        assert_ne!(keymat.sk_ai, keymat.sk_ar);
        assert_ne!(keymat.sk_ei, keymat.sk_er);
        assert_ne!(keymat.sk_pi, keymat.sk_pr);
    }

    #[test]
    fn test_key_material_deterministic() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let nonce_i = vec![0x01; 32];
        let nonce_r = vec![0x02; 32];
        let shared_secret = vec![0x03; 256];
        let spi_i = [0x04; 8];
        let spi_r = [0x05; 8];

        let keymat1 = KeyMaterial::derive(
            prf_alg,
            &nonce_i,
            &nonce_r,
            &shared_secret,
            &spi_i,
            &spi_r,
            32,
            32,
        )
        .unwrap();

        let keymat2 = KeyMaterial::derive(
            prf_alg,
            &nonce_i,
            &nonce_r,
            &shared_secret,
            &spi_i,
            &spi_r,
            32,
            32,
        )
        .unwrap();

        // Same inputs should produce same keys
        assert_eq!(keymat1.sk_d, keymat2.sk_d);
        assert_eq!(keymat1.sk_ei, keymat2.sk_ei);
        assert_eq!(keymat1.sk_pi, keymat2.sk_pi);
    }

    #[test]
    fn test_key_material_different_nonces() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let nonce_i1 = vec![0x01; 32];
        let nonce_i2 = vec![0x02; 32];
        let nonce_r = vec![0x03; 32];
        let shared_secret = vec![0x04; 256];
        let spi_i = [0x05; 8];
        let spi_r = [0x06; 8];

        let keymat1 = KeyMaterial::derive(
            prf_alg,
            &nonce_i1,
            &nonce_r,
            &shared_secret,
            &spi_i,
            &spi_r,
            32,
            32,
        )
        .unwrap();

        let keymat2 = KeyMaterial::derive(
            prf_alg,
            &nonce_i2,
            &nonce_r,
            &shared_secret,
            &spi_i,
            &spi_r,
            32,
            32,
        )
        .unwrap();

        // Different nonces should produce different keys
        assert_ne!(keymat1.sk_d, keymat2.sk_d);
        assert_ne!(keymat1.sk_ei, keymat2.sk_ei);
    }
}
