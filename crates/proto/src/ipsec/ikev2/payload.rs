//! IKEv2 Payload structures and parsing
//!
//! Implements IKE payloads as defined in RFC 7296 Section 3.2

use super::constants::PayloadType;
use crate::ipsec::{Error, Result};

/// Generic IKE payload header (4 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Next payload type
    pub next_payload: PayloadType,

    /// Critical bit (if set, must understand this payload)
    pub critical: bool,

    /// Total payload length including header (4 bytes + data)
    pub length: u16,
}

impl PayloadHeader {
    /// Minimum payload header size
    pub const SIZE: usize = 4;

    /// Create new payload header
    pub fn new(next_payload: PayloadType, critical: bool, length: u16) -> Self {
        PayloadHeader {
            next_payload,
            critical,
            length,
        }
    }

    /// Parse payload header from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing at least 4 bytes
    ///
    /// # Returns
    ///
    /// Returns the parsed header
    ///
    /// # Errors
    ///
    /// Returns error if buffer is too short or payload type is unknown
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(Error::BufferTooShort {
                required: Self::SIZE,
                available: data.len(),
            });
        }

        // Parse next payload type
        let next_payload = PayloadType::from_u8(data[0])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown payload type: {}", data[0])))?;

        // Parse critical bit (bit 7 of second byte)
        let critical = (data[1] & 0x80) != 0;

        // Parse length (bytes 2-3, big-endian)
        let length = u16::from_be_bytes([data[2], data[3]]);

        // Validate length
        if (length as usize) < Self::SIZE {
            return Err(Error::InvalidLength {
                expected: Self::SIZE,
                actual: length as usize,
            });
        }

        Ok(PayloadHeader {
            next_payload,
            critical,
            length,
        })
    }

    /// Serialize payload header to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];

        // Write next payload type
        bytes[0] = self.next_payload.to_u8();

        // Write critical bit and reserved (bits 0-6 must be zero)
        bytes[1] = if self.critical { 0x80 } else { 0x00 };

        // Write length (big-endian)
        bytes[2..4].copy_from_slice(&self.length.to_be_bytes());

        bytes
    }

    /// Get payload data length (excluding header)
    pub fn data_length(&self) -> usize {
        self.length as usize - Self::SIZE
    }
}

/// IKE Payload types
#[derive(Debug, Clone, PartialEq)]
pub enum IkePayload {
    /// Security Association payload
    SA(SaPayload),

    /// Key Exchange payload
    KE(KePayload),

    /// Nonce payload
    Nonce(NoncePayload),

    /// Unknown/unimplemented payload (store raw data)
    Unknown {
        /// Payload type
        payload_type: PayloadType,
        /// Raw payload data (excluding header)
        data: Vec<u8>,
    },
}

impl IkePayload {
    /// Get payload type
    pub fn payload_type(&self) -> PayloadType {
        match self {
            IkePayload::SA(_) => PayloadType::SA,
            IkePayload::KE(_) => PayloadType::KE,
            IkePayload::Nonce(_) => PayloadType::Nonce,
            IkePayload::Unknown { payload_type, .. } => *payload_type,
        }
    }

    /// Parse payload from bytes (with header)
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing header + payload data
    ///
    /// # Returns
    ///
    /// Returns tuple of (payload, next_payload_type, bytes_consumed)
    pub fn from_bytes(data: &[u8]) -> Result<(Self, PayloadType, usize)> {
        // Parse header
        let header = PayloadHeader::from_bytes(data)?;

        // Validate we have enough data
        if data.len() < header.length as usize {
            return Err(Error::BufferTooShort {
                required: header.length as usize,
                available: data.len(),
            });
        }

        // Extract payload data (skip header)
        let payload_data = &data[PayloadHeader::SIZE..header.length as usize];

        // Parse based on payload type (from previous payload's next_payload)
        // For now, we'll determine type from context, but we'll enhance this later
        let payload = IkePayload::Unknown {
            payload_type: header.next_payload,
            data: payload_data.to_vec(),
        };

        Ok((payload, header.next_payload, header.length as usize))
    }
}

/// Nonce Payload (RFC 7296 Section 3.9)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                            Nonce Data                         ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoncePayload {
    /// Nonce data (typically 16-32 bytes of random data)
    pub nonce: Vec<u8>,
}

impl NoncePayload {
    /// Minimum nonce size (16 bytes)
    pub const MIN_SIZE: usize = 16;

    /// Maximum nonce size (256 bytes)
    pub const MAX_SIZE: usize = 256;

    /// Create new nonce payload
    pub fn new(nonce: Vec<u8>) -> Result<Self> {
        if nonce.len() < Self::MIN_SIZE {
            return Err(Error::InvalidPayload(format!(
                "Nonce too short: {} bytes (minimum {})",
                nonce.len(),
                Self::MIN_SIZE
            )));
        }

        if nonce.len() > Self::MAX_SIZE {
            return Err(Error::InvalidPayload(format!(
                "Nonce too long: {} bytes (maximum {})",
                nonce.len(),
                Self::MAX_SIZE
            )));
        }

        Ok(NoncePayload { nonce })
    }

    /// Parse nonce payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        Self::new(data.to_vec())
    }

    /// Serialize nonce payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + self.nonce.len()) as u16
    }
}

/// Key Exchange Payload (RFC 7296 Section 3.4)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Diffie-Hellman Group Num    |           RESERVED            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                       Key Exchange Data                       ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KePayload {
    /// Diffie-Hellman group number
    pub dh_group: u16,

    /// Key exchange data (public key)
    pub key_data: Vec<u8>,
}

impl KePayload {
    /// DH Group 14 (2048-bit MODP)
    pub const DH_GROUP_14: u16 = 14;

    /// DH Group 31 (Curve25519)
    pub const DH_GROUP_31: u16 = 31;

    /// Create new KE payload
    pub fn new(dh_group: u16, key_data: Vec<u8>) -> Self {
        KePayload { dh_group, key_data }
    }

    /// Parse KE payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                required: 4,
                available: data.len(),
            });
        }

        // Parse DH group (bytes 0-1)
        let dh_group = u16::from_be_bytes([data[0], data[1]]);

        // Skip reserved (bytes 2-3)

        // Key data starts at byte 4
        let key_data = data[4..].to_vec();

        Ok(KePayload { dh_group, key_data })
    }

    /// Serialize KE payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + self.key_data.len());

        // Write DH group (big-endian)
        data.extend_from_slice(&self.dh_group.to_be_bytes());

        // Write reserved (2 bytes of zeros)
        data.extend_from_slice(&[0u8, 0u8]);

        // Write key data
        data.extend_from_slice(&self.key_data);

        data
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + 4 + self.key_data.len()) as u16
    }
}

/// Security Association Payload (RFC 7296 Section 3.3)
///
/// This is a simplified version. Full implementation will come later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaPayload {
    /// Raw SA payload data (will be parsed later)
    pub data: Vec<u8>,
}

impl SaPayload {
    /// Create new SA payload
    pub fn new(data: Vec<u8>) -> Self {
        SaPayload { data }
    }

    /// Parse SA payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        Ok(SaPayload {
            data: data.to_vec(),
        })
    }

    /// Serialize SA payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + self.data.len()) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_header_parse() {
        let data = [
            33,  // Next payload (SA)
            0x80, // Critical bit set, reserved = 0
            0,   50, // Length = 50
        ];

        let header = PayloadHeader::from_bytes(&data).unwrap();
        assert_eq!(header.next_payload, PayloadType::SA);
        assert!(header.critical);
        assert_eq!(header.length, 50);
        assert_eq!(header.data_length(), 46); // 50 - 4
    }

    #[test]
    fn test_payload_header_roundtrip() {
        let header = PayloadHeader::new(PayloadType::Nonce, true, 100);
        let bytes = header.to_bytes();
        let parsed = PayloadHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_payload_header_not_critical() {
        let data = [
            40, // Next payload (Nonce)
            0,  // Critical bit not set
            0, 20, // Length = 20
        ];

        let header = PayloadHeader::from_bytes(&data).unwrap();
        assert!(!header.critical);
    }

    #[test]
    fn test_nonce_payload() {
        let nonce_data = vec![1u8; 32]; // 32 bytes of 0x01
        let nonce = NoncePayload::new(nonce_data.clone()).unwrap();

        assert_eq!(nonce.nonce, nonce_data);
        assert_eq!(nonce.total_length(), 36); // 4 (header) + 32 (data)

        // Test serialization
        let serialized = nonce.to_payload_data();
        assert_eq!(serialized, nonce_data);

        // Test parsing
        let parsed = NoncePayload::from_payload_data(&serialized).unwrap();
        assert_eq!(parsed, nonce);
    }

    #[test]
    fn test_nonce_too_short() {
        let nonce_data = vec![1u8; 10]; // Only 10 bytes
        let result = NoncePayload::new(nonce_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_too_long() {
        let nonce_data = vec![1u8; 300]; // 300 bytes
        let result = NoncePayload::new(nonce_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_ke_payload() {
        let key_data = vec![0xAAu8; 32]; // 32 bytes of 0xAA
        let ke = KePayload::new(KePayload::DH_GROUP_31, key_data.clone());

        assert_eq!(ke.dh_group, 31);
        assert_eq!(ke.key_data, key_data);
        assert_eq!(ke.total_length(), 40); // 4 (header) + 4 (dh_group + reserved) + 32 (data)

        // Test serialization
        let serialized = ke.to_payload_data();
        assert_eq!(serialized.len(), 36); // 4 (dh_group + reserved) + 32 (data)
        assert_eq!(&serialized[0..2], &31u16.to_be_bytes());
        assert_eq!(&serialized[2..4], &[0u8, 0u8]); // Reserved
        assert_eq!(&serialized[4..], &key_data[..]);

        // Test parsing
        let parsed = KePayload::from_payload_data(&serialized).unwrap();
        assert_eq!(parsed, ke);
    }

    #[test]
    fn test_ke_payload_group_14() {
        let key_data = vec![0xBBu8; 256]; // 256 bytes for 2048-bit key
        let ke = KePayload::new(KePayload::DH_GROUP_14, key_data.clone());

        assert_eq!(ke.dh_group, 14);
        assert_eq!(ke.total_length(), 264); // 4 + 4 + 256

        let serialized = ke.to_payload_data();
        let parsed = KePayload::from_payload_data(&serialized).unwrap();
        assert_eq!(parsed.dh_group, 14);
        assert_eq!(parsed.key_data, key_data);
    }

    #[test]
    fn test_sa_payload() {
        let sa_data = vec![1, 2, 3, 4, 5];
        let sa = SaPayload::new(sa_data.clone());

        assert_eq!(sa.data, sa_data);
        assert_eq!(sa.total_length(), 9); // 4 (header) + 5 (data)

        let serialized = sa.to_payload_data();
        let parsed = SaPayload::from_payload_data(&serialized).unwrap();
        assert_eq!(parsed, sa);
    }

    #[test]
    fn test_payload_header_buffer_too_short() {
        let data = [1, 2]; // Only 2 bytes
        let result = PayloadHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::BufferTooShort { .. })));
    }

    #[test]
    fn test_payload_header_invalid_length() {
        let data = [
            33, // Next payload
            0,  // Flags
            0, 2, // Length = 2 (too short, minimum is 4)
        ];
        let result = PayloadHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidLength { .. })));
    }
}
