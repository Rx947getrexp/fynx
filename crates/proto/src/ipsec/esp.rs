//! ESP (Encapsulating Security Payload) Protocol
//!
//! Implements RFC 4303 - IP Encapsulating Security Payload (ESP).
//!
//! # Overview
//!
//! ESP provides confidentiality, data origin authentication, connectionless integrity,
//! and anti-replay protection for IP packets. It encrypts the payload and optionally
//! authenticates the entire packet.
//!
//! # ESP Packet Format (RFC 4303)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//! |               Security Parameters Index (SPI)                 | ^Auth
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//! |                      Sequence Number                          | |erage
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
//! |                    Payload Data (variable)                    | |  ^
//! ~                                                               ~ |  |
//! |                                                               | |Conf.
//! +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//! |               |     Padding (0-255 bytes)                     | |erage
//! +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |  |
//! |                               |  Pad Length   | Next Header   | v  v
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//! |         Integrity Check Value-ICV   (variable)                |
//! ~                                                               ~
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # AEAD Mode (AES-GCM, ChaCha20-Poly1305)
//!
//! For AEAD ciphers:
//! - IV is transmitted in ESP header (after sequence number)
//! - Authentication tag is appended after encrypted data
//! - No separate ICV field (tag is part of encrypted data)
//! - AAD includes SPI and sequence number
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use fynx_proto::ipsec::esp::EspPacket;
//!
//! // Encapsulate payload
//! let esp = EspPacket::new(spi, seq, iv, encrypted_data, None);
//! let packet_bytes = esp.to_bytes();
//!
//! // Decapsulate
//! let esp = EspPacket::from_bytes(&packet_bytes)?;
//! ```

use crate::ipsec::{
    child_sa::ChildSa,
    crypto::cipher::CipherAlgorithm,
    Error, Result,
};

/// ESP Packet
///
/// Represents an ESP packet as defined in RFC 4303.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspPacket {
    /// Security Parameters Index (SPI)
    ///
    /// 32-bit identifier that, together with the destination IP address,
    /// uniquely identifies the Security Association.
    pub spi: u32,

    /// Sequence Number
    ///
    /// 32-bit counter value that increments for each packet sent.
    /// Used for anti-replay protection.
    pub sequence: u32,

    /// Initialization Vector (IV)
    ///
    /// For AEAD ciphers (AES-GCM, ChaCha20-Poly1305):
    /// - AES-GCM: 8 bytes
    /// - ChaCha20-Poly1305: 8 bytes (RFC 7634 specifies 8-byte IV for IPSec)
    ///
    /// For non-AEAD ciphers:
    /// - AES-CBC: 16 bytes
    pub iv: Vec<u8>,

    /// Encrypted Payload Data
    ///
    /// Contains:
    /// - Original payload data (encrypted)
    /// - Padding (0-255 bytes)
    /// - Pad Length (1 byte)
    /// - Next Header (1 byte)
    ///
    /// For AEAD ciphers, also includes authentication tag at the end.
    pub encrypted_data: Vec<u8>,

    /// Integrity Check Value (ICV)
    ///
    /// Optional field for non-AEAD ciphers.
    /// For AEAD ciphers, the tag is included in encrypted_data.
    pub icv: Option<Vec<u8>>,
}

impl EspPacket {
    /// Create new ESP packet
    ///
    /// # Arguments
    ///
    /// * `spi` - Security Parameters Index
    /// * `sequence` - Sequence number
    /// * `iv` - Initialization vector
    /// * `encrypted_data` - Encrypted payload (includes padding, pad length, next header, and optionally auth tag)
    /// * `icv` - Integrity Check Value (None for AEAD ciphers)
    pub fn new(
        spi: u32,
        sequence: u32,
        iv: Vec<u8>,
        encrypted_data: Vec<u8>,
        icv: Option<Vec<u8>>,
    ) -> Self {
        EspPacket {
            spi,
            sequence,
            iv,
            encrypted_data,
            icv,
        }
    }

    /// Serialize ESP packet to bytes
    ///
    /// # Packet Format
    ///
    /// ```text
    /// | SPI (4) | Sequence (4) | IV (variable) | Encrypted Data (variable) | [ICV (variable)] |
    /// ```
    ///
    /// # Returns
    ///
    /// Returns the serialized ESP packet
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // SPI (4 bytes)
        bytes.extend_from_slice(&self.spi.to_be_bytes());

        // Sequence number (4 bytes)
        bytes.extend_from_slice(&self.sequence.to_be_bytes());

        // IV (variable length)
        bytes.extend_from_slice(&self.iv);

        // Encrypted data (variable length)
        bytes.extend_from_slice(&self.encrypted_data);

        // ICV (optional, for non-AEAD)
        if let Some(icv) = &self.icv {
            bytes.extend_from_slice(icv);
        }

        bytes
    }

    /// Parse ESP packet from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Raw ESP packet bytes
    /// * `iv_len` - Expected IV length (8 for AES-GCM/ChaCha20, 16 for AES-CBC)
    /// * `icv_len` - Expected ICV length (0 for AEAD, or HMAC output length for non-AEAD)
    ///
    /// # Returns
    ///
    /// Returns the parsed ESP packet
    ///
    /// # Errors
    ///
    /// - `BufferTooShort` if packet is too short
    /// - `InvalidLength` if lengths don't match expected values
    pub fn from_bytes(data: &[u8], iv_len: usize, icv_len: usize) -> Result<Self> {
        // Minimum size: SPI (4) + Seq (4) + IV (iv_len)
        let min_len = 8 + iv_len;
        if data.len() < min_len {
            return Err(Error::BufferTooShort {
                required: min_len,
                available: data.len(),
            });
        }

        // Parse SPI
        let spi = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

        // Parse sequence number
        let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Parse IV
        let iv = data[8..8 + iv_len].to_vec();

        // Calculate encrypted data length
        let encrypted_start = 8 + iv_len;
        let encrypted_end = if icv_len > 0 {
            if data.len() < encrypted_start + icv_len {
                return Err(Error::BufferTooShort {
                    required: encrypted_start + icv_len,
                    available: data.len(),
                });
            }
            data.len() - icv_len
        } else {
            data.len()
        };

        let encrypted_data = data[encrypted_start..encrypted_end].to_vec();

        // Parse ICV if present
        let icv = if icv_len > 0 {
            Some(data[encrypted_end..].to_vec())
        } else {
            None
        };

        Ok(EspPacket {
            spi,
            sequence,
            iv,
            encrypted_data,
            icv,
        })
    }

    /// Get total packet length
    pub fn len(&self) -> usize {
        8 + self.iv.len() + self.encrypted_data.len() + self.icv.as_ref().map_or(0, |i| i.len())
    }

    /// Check if packet is empty (should never be true for valid ESP)
    pub fn is_empty(&self) -> bool {
        false // ESP packets always have SPI + Sequence at minimum
    }

    /// Encapsulate (encrypt) payload data using Child SA keys
    ///
    /// Creates an ESP packet by:
    /// 1. Adding padding to align to block size
    /// 2. Encrypting payload + padding + trailer
    /// 3. Generating IV
    /// 4. Computing ICV (for non-AEAD) or including auth tag (for AEAD)
    ///
    /// # Arguments
    ///
    /// * `child_sa` - Child SA containing encryption keys and configuration
    /// * `payload` - Original IP packet payload to protect
    /// * `next_header` - IP protocol number of encapsulated packet (e.g., 4 = IPv4, 41 = IPv6)
    ///
    /// # Returns
    ///
    /// Returns the encrypted ESP packet ready for transmission
    ///
    /// # Errors
    ///
    /// - `CryptoError` if encryption fails
    /// - `InvalidKeyLength` if SA keys are incorrect length
    /// - `Internal` if SA is not properly configured for encryption
    pub fn encapsulate(
        child_sa: &mut ChildSa,
        payload: &[u8],
        next_header: u8,
    ) -> Result<Self> {
        // Verify this is an outbound SA
        if child_sa.is_inbound {
            return Err(Error::Internal(
                "Cannot encapsulate with inbound SA".into(),
            ));
        }

        // Determine cipher algorithm from proposal
        let cipher = extract_cipher_algorithm(&child_sa.proposal)?;

        // Get cipher parameters
        let block_size = if cipher.is_aead() { 4 } else { 16 }; // AEAD uses 4-byte alignment
        let iv_len = cipher.iv_len();

        // Calculate padding
        let pad_len = calculate_padding(payload.len(), block_size);

        // Build plaintext: Payload | Padding | Pad Length | Next Header
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(payload);

        // Add padding bytes (RFC 4303: padding can be any value, typically 1, 2, 3, ...)
        for i in 1..=pad_len {
            plaintext.push(i as u8);
        }

        plaintext.push(pad_len as u8); // Pad length field
        plaintext.push(next_header); // Next header field

        // Generate IV (first iv_len bytes of sequence number + random)
        let mut iv = vec![0u8; iv_len];
        // Use sequence number as part of IV for uniqueness
        let seq_bytes = child_sa.seq_out.to_be_bytes();
        let copy_len = iv_len.min(8);
        iv[iv_len - copy_len..].copy_from_slice(&seq_bytes[8 - copy_len..]);

        // Build AAD (Additional Authenticated Data): SPI | Sequence Number
        let mut aad = Vec::new();
        aad.extend_from_slice(&child_sa.spi.to_be_bytes());
        aad.extend_from_slice(&(child_sa.seq_out as u32).to_be_bytes());

        // Encrypt payload
        let encrypted_data = cipher.encrypt(&child_sa.sk_e, &iv, &plaintext, &aad)?;

        // Increment sequence number
        child_sa.seq_out += 1;

        // Update byte count
        child_sa.bytes_processed += payload.len() as u64;

        // For AEAD, ICV is None (tag is in encrypted_data)
        // For non-AEAD, we would compute HMAC here (not implemented as we only support AEAD currently)
        let icv = None;

        Ok(EspPacket {
            spi: child_sa.spi,
            sequence: (child_sa.seq_out - 1) as u32,
            iv,
            encrypted_data,
            icv,
        })
    }

    /// Decapsulate (decrypt) ESP packet using Child SA keys
    ///
    /// Decrypts an ESP packet by:
    /// 1. Verifying sequence number (anti-replay)
    /// 2. Verifying ICV/auth tag
    /// 3. Decrypting payload
    /// 4. Removing padding
    ///
    /// # Arguments
    ///
    /// * `child_sa` - Child SA containing decryption keys and configuration
    ///
    /// # Returns
    ///
    /// Returns tuple of (decrypted_payload, next_header)
    ///
    /// # Errors
    ///
    /// - `CryptoError` if decryption or authentication fails
    /// - `InvalidSequence` if sequence number is invalid (anti-replay)
    /// - `InvalidSpi` if SPI doesn't match SA
    /// - `InvalidLength` if packet is malformed
    pub fn decapsulate(&self, child_sa: &mut ChildSa) -> Result<(Vec<u8>, u8)> {
        // Verify this is an inbound SA
        if !child_sa.is_inbound {
            return Err(Error::Internal(
                "Cannot decapsulate with outbound SA".into(),
            ));
        }

        // Verify SPI matches
        if self.spi != child_sa.spi {
            return Err(Error::InvalidSpi(self.spi));
        }

        // Anti-replay check (RFC 4303 Section 3.4.3)
        // Convert 32-bit sequence to 64-bit for replay window
        let seq = self.sequence as u64;

        if let Some(ref mut replay_window) = child_sa.replay_window {
            if !replay_window.check_and_update(seq) {
                return Err(Error::ReplayDetected(seq));
            }
        }
        // If no replay window configured, accept packet (replay protection disabled)

        // Determine cipher algorithm from proposal
        let cipher = extract_cipher_algorithm(&child_sa.proposal)?;

        // Build AAD: SPI | Sequence Number
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.spi.to_be_bytes());
        aad.extend_from_slice(&self.sequence.to_be_bytes());

        // Decrypt payload
        let plaintext = cipher.decrypt(&child_sa.sk_e, &self.iv, &self.encrypted_data, &aad)?;

        // Verify minimum length (at least pad_length + next_header)
        if plaintext.len() < 2 {
            return Err(Error::InvalidLength {
                expected: 2,
                actual: plaintext.len(),
            });
        }

        // Extract trailer fields
        let pad_len = plaintext[plaintext.len() - 2] as usize;
        let next_header = plaintext[plaintext.len() - 1];

        // Verify pad length is valid
        if pad_len + 2 > plaintext.len() {
            return Err(Error::InvalidLength {
                expected: pad_len + 2,
                actual: plaintext.len(),
            });
        }

        // Extract payload (everything before padding)
        let payload_len = plaintext.len() - pad_len - 2;
        let payload = plaintext[..payload_len].to_vec();

        // Update byte count
        child_sa.bytes_processed += payload.len() as u64;

        Ok((payload, next_header))
    }
}

/// Extract cipher algorithm from Child SA proposal
///
/// Looks through the proposal transforms to find the encryption algorithm.
///
/// # Arguments
///
/// * `proposal` - Child SA proposal containing negotiated transforms
///
/// # Returns
///
/// Returns the cipher algorithm to use for ESP encryption/decryption
///
/// # Errors
///
/// - `InvalidProposal` if no supported encryption transform is found
fn extract_cipher_algorithm(
    proposal: &crate::ipsec::ikev2::proposal::Proposal,
) -> Result<CipherAlgorithm> {
    use crate::ipsec::ikev2::proposal::TransformType;

    // Find encryption transform
    for transform in &proposal.transforms {
        if transform.transform_type == TransformType::Encr {
            // Map transform ID to CipherAlgorithm
            // Transform IDs from RFC 7296 Section 3.3.2
            match transform.transform_id {
                20 => return Ok(CipherAlgorithm::AesGcm128), // ENCR_AES_GCM_16 with 128-bit key
                21 => return Ok(CipherAlgorithm::AesGcm256), // ENCR_AES_GCM_16 with 256-bit key
                28 => return Ok(CipherAlgorithm::ChaCha20Poly1305), // ENCR_CHACHA20_POLY1305
                _ => continue,
            }
        }
    }

    Err(Error::InvalidProposal(
        "No supported encryption algorithm found in proposal".into(),
    ))
}

/// Calculate padding length needed for ESP
///
/// Padding is required to:
/// 1. Align encrypted payload to cipher block size
/// 2. Conceal actual payload length (optional)
///
/// # Arguments
///
/// * `payload_len` - Length of payload + pad_length (1 byte) + next_header (1 byte)
/// * `block_size` - Cipher block size (8 for ChaCha20, 16 for AES)
///
/// # Returns
///
/// Returns the number of padding bytes needed (0-255)
///
/// # Formula
///
/// ```text
/// total_len = payload_len + pad_len + 2  // +2 for pad_length and next_header bytes
/// total_len % block_size == 0
/// ```
pub fn calculate_padding(payload_len: usize, block_size: usize) -> usize {
    let total_with_trailer = payload_len + 2; // +2 for pad_length and next_header
    let remainder = total_with_trailer % block_size;
    if remainder == 0 {
        0
    } else {
        block_size - remainder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_packet_creation() {
        let spi = 0x12345678;
        let seq = 42;
        let iv = vec![0xAA; 8];
        let encrypted_data = vec![0xBB; 64];

        let esp = EspPacket::new(spi, seq, iv.clone(), encrypted_data.clone(), None);

        assert_eq!(esp.spi, spi);
        assert_eq!(esp.sequence, seq);
        assert_eq!(esp.iv, iv);
        assert_eq!(esp.encrypted_data, encrypted_data);
        assert!(esp.icv.is_none());
    }

    #[test]
    fn test_esp_packet_with_icv() {
        let spi = 0x87654321;
        let seq = 100;
        let iv = vec![0xCC; 16];
        let encrypted_data = vec![0xDD; 32];
        let icv = vec![0xEE; 32]; // HMAC-SHA256

        let esp = EspPacket::new(spi, seq, iv.clone(), encrypted_data.clone(), Some(icv.clone()));

        assert_eq!(esp.spi, spi);
        assert_eq!(esp.sequence, seq);
        assert_eq!(esp.iv, iv);
        assert_eq!(esp.encrypted_data, encrypted_data);
        assert_eq!(esp.icv, Some(icv));
    }

    #[test]
    fn test_esp_packet_serialization_aead() {
        let spi = 0x11223344;
        let seq = 1;
        let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let encrypted_data = vec![0xAA; 48]; // Includes auth tag

        let esp = EspPacket::new(spi, seq, iv.clone(), encrypted_data.clone(), None);
        let bytes = esp.to_bytes();

        // Verify length: SPI (4) + Seq (4) + IV (8) + Data (48) = 64
        assert_eq!(bytes.len(), 64);

        // Verify SPI
        assert_eq!(&bytes[0..4], &[0x11, 0x22, 0x33, 0x44]);

        // Verify Sequence
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x01]);

        // Verify IV
        assert_eq!(&bytes[8..16], &iv[..]);

        // Verify encrypted data
        assert_eq!(&bytes[16..], &encrypted_data[..]);
    }

    #[test]
    fn test_esp_packet_serialization_non_aead() {
        let spi = 0xAABBCCDD;
        let seq = 999;
        let iv = vec![0xFF; 16]; // AES-CBC
        let encrypted_data = vec![0x55; 32];
        let icv = vec![0x77; 32]; // HMAC-SHA256

        let esp = EspPacket::new(
            spi,
            seq,
            iv.clone(),
            encrypted_data.clone(),
            Some(icv.clone()),
        );
        let bytes = esp.to_bytes();

        // Verify length: SPI (4) + Seq (4) + IV (16) + Data (32) + ICV (32) = 88
        assert_eq!(bytes.len(), 88);

        // Verify components
        assert_eq!(&bytes[0..4], &spi.to_be_bytes());
        assert_eq!(&bytes[4..8], &seq.to_be_bytes());
        assert_eq!(&bytes[8..24], &iv[..]);
        assert_eq!(&bytes[24..56], &encrypted_data[..]);
        assert_eq!(&bytes[56..88], &icv[..]);
    }

    #[test]
    fn test_esp_packet_deserialization_aead() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678u32.to_be_bytes()); // SPI
        data.extend_from_slice(&42u32.to_be_bytes()); // Sequence
        data.extend_from_slice(&[0xAA; 8]); // IV (8 bytes for AES-GCM)
        data.extend_from_slice(&[0xBB; 64]); // Encrypted data (includes tag)

        let esp = EspPacket::from_bytes(&data, 8, 0).unwrap();

        assert_eq!(esp.spi, 0x12345678);
        assert_eq!(esp.sequence, 42);
        assert_eq!(esp.iv.len(), 8);
        assert_eq!(esp.encrypted_data.len(), 64);
        assert!(esp.icv.is_none());
    }

    #[test]
    fn test_esp_packet_deserialization_non_aead() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x87654321u32.to_be_bytes()); // SPI
        data.extend_from_slice(&100u32.to_be_bytes()); // Sequence
        data.extend_from_slice(&[0xCC; 16]); // IV (16 bytes for AES-CBC)
        data.extend_from_slice(&[0xDD; 32]); // Encrypted data
        data.extend_from_slice(&[0xEE; 32]); // ICV (HMAC-SHA256)

        let esp = EspPacket::from_bytes(&data, 16, 32).unwrap();

        assert_eq!(esp.spi, 0x87654321);
        assert_eq!(esp.sequence, 100);
        assert_eq!(esp.iv.len(), 16);
        assert_eq!(esp.encrypted_data.len(), 32);
        assert_eq!(esp.icv.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_esp_packet_roundtrip_aead() {
        let original = EspPacket::new(
            0x11111111,
            555,
            vec![0x12; 8],
            vec![0x34; 80],
            None,
        );

        let bytes = original.to_bytes();
        let parsed = EspPacket::from_bytes(&bytes, 8, 0).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_esp_packet_roundtrip_non_aead() {
        let original = EspPacket::new(
            0x22222222,
            777,
            vec![0xAB; 16],
            vec![0xCD; 48],
            Some(vec![0xEF; 32]),
        );

        let bytes = original.to_bytes();
        let parsed = EspPacket::from_bytes(&bytes, 16, 32).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_esp_packet_buffer_too_short() {
        let data = vec![0u8; 10]; // Too short (need at least 8 + iv_len)

        let result = EspPacket::from_bytes(&data, 8, 0);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::BufferTooShort { .. }));
    }

    #[test]
    fn test_calculate_padding_no_padding() {
        // Payload of 14 bytes + 2 bytes trailer = 16 bytes (aligned to block size 16)
        assert_eq!(calculate_padding(14, 16), 0);
    }

    #[test]
    fn test_calculate_padding_needed() {
        // Payload of 10 bytes + 2 bytes trailer = 12 bytes, need 4 bytes padding for block size 16
        assert_eq!(calculate_padding(10, 16), 4);

        // Payload of 5 bytes + 2 bytes trailer = 7 bytes, need 1 byte padding for block size 8
        assert_eq!(calculate_padding(5, 8), 1);
    }

    #[test]
    fn test_calculate_padding_various_sizes() {
        // Block size 16
        assert_eq!(calculate_padding(0, 16), 14); // 0 + 2 = 2, need 14 to reach 16
        assert_eq!(calculate_padding(1, 16), 13);
        assert_eq!(calculate_padding(13, 16), 1);
        assert_eq!(calculate_padding(14, 16), 0);
        assert_eq!(calculate_padding(15, 16), 15); // 15 + 2 = 17, need 15 to reach 32

        // Block size 8
        assert_eq!(calculate_padding(0, 8), 6); // 0 + 2 = 2, need 6 to reach 8
        assert_eq!(calculate_padding(6, 8), 0); // 6 + 2 = 8, aligned
        assert_eq!(calculate_padding(7, 8), 7); // 7 + 2 = 9, need 7 to reach 16
    }

    #[test]
    fn test_esp_packet_len() {
        let esp = EspPacket::new(0x12345678, 1, vec![0; 8], vec![0; 64], None);
        assert_eq!(esp.len(), 8 + 8 + 64); // SPI + Seq + IV + Data

        let esp_with_icv = EspPacket::new(0x12345678, 1, vec![0; 16], vec![0; 32], Some(vec![0; 32]));
        assert_eq!(esp_with_icv.len(), 8 + 16 + 32 + 32); // SPI + Seq + IV + Data + ICV
    }

    #[test]
    fn test_esp_packet_is_empty() {
        let esp = EspPacket::new(0, 0, vec![], vec![], None);
        assert!(!esp.is_empty()); // ESP packets are never considered empty
    }

    // --- Encapsulation/Decapsulation Tests ---

    #[test]
    fn test_esp_encapsulate_decapsulate_roundtrip() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            crypto::prf::PrfAlgorithm,
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{DhTransformId, PrfTransformId, Proposal, ProtocolId, Transform, TransformType},
            },
        };

        // Create test proposal with AES-GCM-128
        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![
                Transform {
                    transform_type: TransformType::Encr,
                    transform_id: 20, // ENCR_AES_GCM_16 with 128-bit key
                    attributes: vec![],
                },
                Transform {
                    transform_type: TransformType::Prf,
                    transform_id: PrfTransformId::HmacSha256 as u16,
                    attributes: vec![],
                },
                Transform {
                    transform_type: TransformType::Dh,
                    transform_id: DhTransformId::Group14 as u16,
                    attributes: vec![],
                },
            ],
        };

        // Create dummy traffic selectors
        let ts_i = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        let ts_r = ts_i.clone();

        // Derive test keys
        let sk_d = vec![0xAA; 32];
        let nonce_i = vec![0xBB; 32];
        let nonce_r = vec![0xCC; 32];

        let (sk_ei, _sk_ai, sk_er, _sk_ar) = crate::ipsec::child_sa::derive_child_sa_keys(
            PrfAlgorithm::HmacSha256,
            &sk_d,
            &nonce_i,
            &nonce_r,
            None,
            16, // AES-GCM-128 key length
            0,  // No separate auth key for AEAD
        );

        // Create outbound SA (use same key for this test)
        let mut sa_out = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: false,
            sk_e: sk_ei.clone(),
            sk_a: None,
            ts_i: ts_i.clone(),
            ts_r: ts_r.clone(),
            proposal: proposal.clone(),
            seq_out: 1,
            replay_window: None, // Outbound SA doesn't need replay window
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        // Create inbound SA with same key (for roundtrip test)
        // In real IPSec, initiator and responder would use different keys
        let mut sa_in = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: true,
            sk_e: sk_ei, // Use same key for roundtrip test
            sk_a: None,
            ts_i,
            ts_r,
            proposal,
            seq_out: 0,
            replay_window: Some(crate::ipsec::replay::ReplayWindow::default()), // Enable anti-replay
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        // Original payload
        let payload = b"Hello, ESP encryption!";
        let next_header = 4; // IPv4

        // Encapsulate
        let esp_packet = EspPacket::encapsulate(&mut sa_out, payload, next_header).unwrap();

        // Verify ESP packet structure
        assert_eq!(esp_packet.spi, 0x12345678);
        assert_eq!(esp_packet.sequence, 1);
        assert!(esp_packet.icv.is_none()); // AEAD mode

        // Decapsulate
        let (decrypted_payload, decrypted_next_header) = esp_packet.decapsulate(&mut sa_in).unwrap();

        // Verify roundtrip
        assert_eq!(decrypted_payload, payload);
        assert_eq!(decrypted_next_header, next_header);

        // Verify sequence number was incremented
        assert_eq!(sa_out.seq_out, 2);

        // Verify byte count was updated
        assert_eq!(sa_out.bytes_processed, payload.len() as u64);
        assert_eq!(sa_in.bytes_processed, payload.len() as u64);
    }

    #[test]
    fn test_esp_encapsulate_requires_outbound_sa() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{Proposal, ProtocolId, Transform, TransformType},
            },
        };

        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 20,
                attributes: vec![],
            }],
        };

        let ts = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        // Create inbound SA (wrong direction)
        let mut sa = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: true, // INBOUND - should fail
            sk_e: vec![0xAA; 16],
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts,
            proposal,
            seq_out: 1,
            replay_window: None,
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        let result = EspPacket::encapsulate(&mut sa, b"test", 4);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[test]
    fn test_esp_decapsulate_requires_inbound_sa() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{Proposal, ProtocolId, Transform, TransformType},
            },
        };

        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 20,
                attributes: vec![],
            }],
        };

        let ts = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        // Create outbound SA (wrong direction)
        let mut sa = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: false, // OUTBOUND - should fail
            sk_e: vec![0xAA; 16],
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts,
            proposal,
            seq_out: 1,
            replay_window: None,
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        let esp = EspPacket::new(0x12345678, 1, vec![0; 8], vec![0; 32], None);
        let result = esp.decapsulate(&mut sa);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[test]
    fn test_esp_decapsulate_spi_mismatch() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{Proposal, ProtocolId, Transform, TransformType},
            },
        };

        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 20,
                attributes: vec![],
            }],
        };

        let ts = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        let mut sa = ChildSa {
            spi: 0xAAAAAAAA, // Different SPI
            protocol: ProtocolId::Esp as u8,
            is_inbound: true,
            sk_e: vec![0xAA; 16],
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts,
            proposal,
            seq_out: 0,
            replay_window: None,
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        let esp = EspPacket::new(0xBBBBBBBB, 1, vec![0; 8], vec![0; 32], None);
        let result = esp.decapsulate(&mut sa);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidSpi(_)));
    }

    #[test]
    fn test_esp_padding_calculation() {
        // Test with various payload sizes and block sizes
        let payload = b"Short";
        let next_header = 4;

        // For AEAD (block_size = 4)
        let pad_len = calculate_padding(payload.len(), 4);
        let total = payload.len() + pad_len + 2; // +2 for pad_length and next_header
        assert_eq!(total % 4, 0);

        // For AES-CBC (block_size = 16)
        let pad_len = calculate_padding(payload.len(), 16);
        let total = payload.len() + pad_len + 2;
        assert_eq!(total % 16, 0);
    }

    #[test]
    fn test_extract_cipher_algorithm() {
        use crate::ipsec::ikev2::proposal::{Proposal, ProtocolId, Transform, TransformType};

        // Test AES-GCM-128
        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 20,
                attributes: vec![],
            }],
        };
        let cipher = extract_cipher_algorithm(&proposal).unwrap();
        assert_eq!(cipher, CipherAlgorithm::AesGcm128);

        // Test AES-GCM-256
        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 21,
                attributes: vec![],
            }],
        };
        let cipher = extract_cipher_algorithm(&proposal).unwrap();
        assert_eq!(cipher, CipherAlgorithm::AesGcm256);

        // Test ChaCha20-Poly1305
        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 28,
                attributes: vec![],
            }],
        };
        let cipher = extract_cipher_algorithm(&proposal).unwrap();
        assert_eq!(cipher, CipherAlgorithm::ChaCha20Poly1305);

        // Test unsupported cipher
        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 999,
                attributes: vec![],
            }],
        };
        let result = extract_cipher_algorithm(&proposal);
        assert!(result.is_err());
    }

    // --- Anti-Replay Integration Tests ---

    #[test]
    fn test_anti_replay_reject_duplicate_sequence() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            crypto::prf::PrfAlgorithm,
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{DhTransformId, PrfTransformId, Proposal, ProtocolId, Transform, TransformType},
            },
        };

        // Create proposal and traffic selectors (same as roundtrip test)
        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![
                Transform {
                    transform_type: TransformType::Encr,
                    transform_id: 20,
                    attributes: vec![],
                },
                Transform {
                    transform_type: TransformType::Prf,
                    transform_id: PrfTransformId::HmacSha256 as u16,
                    attributes: vec![],
                },
                Transform {
                    transform_type: TransformType::Dh,
                    transform_id: DhTransformId::Group14 as u16,
                    attributes: vec![],
                },
            ],
        };

        let ts = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        let (sk_ei, _, _, _) = crate::ipsec::child_sa::derive_child_sa_keys(
            PrfAlgorithm::HmacSha256,
            &vec![0xAA; 32],
            &vec![0xBB; 32],
            &vec![0xCC; 32],
            None,
            16,
            0,
        );

        let mut sa_out = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: false,
            sk_e: sk_ei.clone(),
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts.clone(),
            proposal: proposal.clone(),
            seq_out: 1,
            replay_window: None,
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        let mut sa_in = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: true,
            sk_e: sk_ei,
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts,
            proposal,
            seq_out: 0,
            replay_window: Some(crate::ipsec::replay::ReplayWindow::default()),
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        // Encrypt and send first packet
        let esp1 = EspPacket::encapsulate(&mut sa_out, b"First packet", 4).unwrap();

        // Decrypt first packet - should succeed
        let (payload1, _) = esp1.decapsulate(&mut sa_in).unwrap();
        assert_eq!(payload1, b"First packet");

        // Try to decrypt same packet again - should fail (replay detected)
        let result = esp1.decapsulate(&mut sa_in);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ReplayDetected(_)));
    }

    #[test]
    fn test_anti_replay_accept_out_of_order() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            crypto::prf::PrfAlgorithm,
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{DhTransformId, PrfTransformId, Proposal, ProtocolId, Transform, TransformType},
            },
        };

        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 20,
                attributes: vec![],
            }],
        };

        let ts = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        let (sk_ei, _, _, _) = crate::ipsec::child_sa::derive_child_sa_keys(
            PrfAlgorithm::HmacSha256,
            &vec![0xAA; 32],
            &vec![0xBB; 32],
            &vec![0xCC; 32],
            None,
            16,
            0,
        );

        let mut sa_out = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: false,
            sk_e: sk_ei.clone(),
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts.clone(),
            proposal: proposal.clone(),
            seq_out: 1,
            replay_window: None,
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        let mut sa_in = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: true,
            sk_e: sk_ei,
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts,
            proposal,
            seq_out: 0,
            replay_window: Some(crate::ipsec::replay::ReplayWindow::default()),
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        // Encrypt packets with sequences 1, 2, 3
        let esp1 = EspPacket::encapsulate(&mut sa_out, b"Packet 1", 4).unwrap();
        let esp2 = EspPacket::encapsulate(&mut sa_out, b"Packet 2", 4).unwrap();
        let esp3 = EspPacket::encapsulate(&mut sa_out, b"Packet 3", 4).unwrap();

        // Receive out of order: 3, 1, 2
        assert!(esp3.decapsulate(&mut sa_in).is_ok()); // seq=3
        assert!(esp1.decapsulate(&mut sa_in).is_ok()); // seq=1 (out of order, but within window)
        assert!(esp2.decapsulate(&mut sa_in).is_ok()); // seq=2 (out of order, but within window)
    }

    #[test]
    fn test_anti_replay_reject_old_packet() {
        use crate::ipsec::{
            child_sa::{ChildSa, SaLifetime},
            crypto::prf::PrfAlgorithm,
            ikev2::{
                payload::{TrafficSelector, TrafficSelectorsPayload, TsType},
                proposal::{Proposal, ProtocolId, Transform, TransformType},
            },
        };

        let proposal = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![Transform {
                transform_type: TransformType::Encr,
                transform_id: 20,
                attributes: vec![],
            }],
        };

        let ts = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector {
                ts_type: TsType::Ipv4AddrRange,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_address: vec![0; 4],
                end_address: vec![255; 4],
            }],
        };

        let (sk_ei, _, _, _) = crate::ipsec::child_sa::derive_child_sa_keys(
            PrfAlgorithm::HmacSha256,
            &vec![0xAA; 32],
            &vec![0xBB; 32],
            &vec![0xCC; 32],
            None,
            16,
            0,
        );

        let mut sa_out = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: false,
            sk_e: sk_ei.clone(),
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts.clone(),
            proposal: proposal.clone(),
            seq_out: 1,
            replay_window: None,
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        let mut sa_in = ChildSa {
            spi: 0x12345678,
            protocol: ProtocolId::Esp as u8,
            is_inbound: true,
            sk_e: sk_ei,
            sk_a: None,
            ts_i: ts.clone(),
            ts_r: ts,
            proposal,
            seq_out: 0,
            replay_window: Some(crate::ipsec::replay::ReplayWindow::new(64)),
            lifetime: SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
        };

        // Create packet with seq=1
        let esp_old = EspPacket::encapsulate(&mut sa_out, b"Old packet", 4).unwrap();

        // Advance window by sending many packets
        for _ in 0..100 {
            let esp = EspPacket::encapsulate(&mut sa_out, b"New packet", 4).unwrap();
            let _ = esp.decapsulate(&mut sa_in);
        }

        // Now try to decrypt old packet (seq=1) - should fail (too old, outside window)
        let result = esp_old.decapsulate(&mut sa_in);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ReplayDetected(_)));
    }
}
