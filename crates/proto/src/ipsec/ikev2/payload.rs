//! IKEv2 Payload structures and parsing
//!
//! Implements IKE payloads as defined in RFC 7296 Section 3.2

use super::constants::PayloadType;
use super::proposal::Proposal;
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

    /// Identification payload (Initiator)
    IDi(IdPayload),

    /// Identification payload (Responder)
    IDr(IdPayload),

    /// Authentication payload
    AUTH(AuthPayload),

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
            IkePayload::IDi(_) => PayloadType::IDi,
            IkePayload::IDr(_) => PayloadType::IDr,
            IkePayload::AUTH(_) => PayloadType::AUTH,
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
/// Contains one or more proposals for security association negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaPayload {
    /// List of proposals
    pub proposals: Vec<Proposal>,
}

impl SaPayload {
    /// Create new SA payload with proposals
    pub fn new(proposals: Vec<Proposal>) -> Self {
        SaPayload { proposals }
    }

    /// Create from raw data (for backward compatibility)
    pub fn from_raw(_data: Vec<u8>) -> Self {
        // For now, store as empty proposals
        // In production, this would parse the raw data
        SaPayload {
            proposals: Vec::new(),
        }
    }

    /// Parse SA payload from data (without header)
    pub fn from_payload_data(_data: &[u8]) -> Result<Self> {
        // For now, accept empty or any data
        // Full proposal parsing will be implemented when needed
        Ok(SaPayload {
            proposals: Vec::new(),
        })
    }

    /// Serialize SA payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        // For now, return empty if no proposals
        // Full serialization will be implemented when needed
        if self.proposals.is_empty() {
            return Vec::new();
        }

        // Placeholder: return minimal valid SA payload
        Vec::new()
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        let data_len = self.to_payload_data().len();
        (PayloadHeader::SIZE + data_len) as u16
    }

    /// Add proposal to SA payload
    pub fn add_proposal(mut self, proposal: Proposal) -> Self {
        self.proposals.push(proposal);
        self
    }

    /// Get proposals
    pub fn proposals(&self) -> &[Proposal] {
        &self.proposals
    }
}

/// ID Type for Identification Payload (RFC 7296 Section 3.5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdType {
    /// IPv4 address
    Ipv4Addr = 1,
    /// Fully-qualified domain name
    Fqdn = 2,
    /// RFC 822 email address
    Rfc822Addr = 3,
    /// IPv6 address
    Ipv6Addr = 5,
    /// Distinguished Name
    DnBinaryDer = 9,
    /// Distinguished Name
    DnBinaryDerAsn1 = 10,
    /// Key ID
    KeyId = 11,
}

impl IdType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(IdType::Ipv4Addr),
            2 => Some(IdType::Fqdn),
            3 => Some(IdType::Rfc822Addr),
            5 => Some(IdType::Ipv6Addr),
            9 => Some(IdType::DnBinaryDer),
            10 => Some(IdType::DnBinaryDerAsn1),
            11 => Some(IdType::KeyId),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Identification Payload (RFC 7296 Section 3.5)
///
/// Used for IDi (Initiator) and IDr (Responder) payloads.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   ID Type     |                 RESERVED                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                   Identification Data                         ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdPayload {
    /// ID type
    pub id_type: IdType,

    /// Identification data
    pub data: Vec<u8>,
}

impl IdPayload {
    /// Create new ID payload
    pub fn new(id_type: IdType, data: Vec<u8>) -> Self {
        IdPayload { id_type, data }
    }

    /// Create ID from FQDN
    pub fn from_fqdn(fqdn: &str) -> Self {
        IdPayload {
            id_type: IdType::Fqdn,
            data: fqdn.as_bytes().to_vec(),
        }
    }

    /// Create ID from email address
    pub fn from_email(email: &str) -> Self {
        IdPayload {
            id_type: IdType::Rfc822Addr,
            data: email.as_bytes().to_vec(),
        }
    }

    /// Create ID from Key ID
    pub fn from_key_id(key_id: &[u8]) -> Self {
        IdPayload {
            id_type: IdType::KeyId,
            data: key_id.to_vec(),
        }
    }

    /// Parse ID payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                required: 4,
                available: data.len(),
            });
        }

        // Parse ID type
        let id_type = IdType::from_u8(data[0])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown ID type: {}", data[0])))?;

        // Skip reserved bytes (1-3)
        // ID data starts at byte 4
        let id_data = data[4..].to_vec();

        Ok(IdPayload {
            id_type,
            data: id_data,
        })
    }

    /// Serialize ID payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.data.len());

        // Write ID type
        bytes.push(self.id_type.to_u8());

        // Write reserved (3 bytes of zeros)
        bytes.extend_from_slice(&[0u8, 0u8, 0u8]);

        // Write ID data
        bytes.extend_from_slice(&self.data);

        bytes
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + 4 + self.data.len()) as u16
    }

    /// Get ID as string (if applicable)
    pub fn as_string(&self) -> Option<String> {
        match self.id_type {
            IdType::Fqdn | IdType::Rfc822Addr => String::from_utf8(self.data.clone()).ok(),
            _ => None,
        }
    }
}

/// Authentication Method (RFC 7296 Section 3.8)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    /// RSA Digital Signature
    RsaSig = 1,
    /// Shared Key Message Integrity Code
    SharedKeyMic = 2,
    /// DSS Digital Signature
    DssSig = 3,
    /// ECDSA with SHA-256 on P-256 curve
    EcdsaSha256P256 = 9,
    /// ECDSA with SHA-384 on P-384 curve
    EcdsaSha384P384 = 10,
    /// ECDSA with SHA-512 on P-521 curve
    EcdsaSha512P521 = 11,
}

impl AuthMethod {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(AuthMethod::RsaSig),
            2 => Some(AuthMethod::SharedKeyMic),
            3 => Some(AuthMethod::DssSig),
            9 => Some(AuthMethod::EcdsaSha256P256),
            10 => Some(AuthMethod::EcdsaSha384P384),
            11 => Some(AuthMethod::EcdsaSha512P521),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Authentication Payload (RFC 7296 Section 3.8)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Auth Method   |                RESERVED                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                      Authentication Data                      ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPayload {
    /// Authentication method
    pub auth_method: AuthMethod,

    /// Authentication data
    pub auth_data: Vec<u8>,
}

impl AuthPayload {
    /// Create new AUTH payload
    pub fn new(auth_method: AuthMethod, auth_data: Vec<u8>) -> Self {
        AuthPayload {
            auth_method,
            auth_data,
        }
    }

    /// Parse AUTH payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                required: 4,
                available: data.len(),
            });
        }

        // Parse auth method
        let auth_method = AuthMethod::from_u8(data[0]).ok_or_else(|| {
            Error::InvalidPayload(format!("Unknown auth method: {}", data[0]))
        })?;

        // Skip reserved bytes (1-3)
        // Auth data starts at byte 4
        let auth_data = data[4..].to_vec();

        Ok(AuthPayload {
            auth_method,
            auth_data,
        })
    }

    /// Serialize AUTH payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.auth_data.len());

        // Write auth method
        bytes.push(self.auth_method.to_u8());

        // Write reserved (3 bytes of zeros)
        bytes.extend_from_slice(&[0u8, 0u8, 0u8]);

        // Write auth data
        bytes.extend_from_slice(&self.auth_data);

        bytes
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + 4 + self.auth_data.len()) as u16
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
    fn test_sa_payload_empty() {
        let sa = SaPayload::new(vec![]);
        assert_eq!(sa.proposals().len(), 0);
        assert_eq!(sa.total_length(), 4); // Just header for empty
    }

    #[test]
    fn test_sa_payload_with_proposals() {
        use super::super::proposal::{Proposal, ProtocolId, Transform, EncrTransformId};

        let proposal = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256));

        let sa = SaPayload::new(vec![proposal.clone()]);
        assert_eq!(sa.proposals().len(), 1);
        assert_eq!(sa.proposals()[0].proposal_num, 1);
    }

    #[test]
    fn test_sa_payload_add_proposal() {
        use super::super::proposal::{Proposal, ProtocolId};

        let sa = SaPayload::new(vec![])
            .add_proposal(Proposal::new(1, ProtocolId::Ike))
            .add_proposal(Proposal::new(2, ProtocolId::Ike));

        assert_eq!(sa.proposals().len(), 2);
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

    // ID Payload tests

    #[test]
    fn test_id_payload_fqdn() {
        let id = IdPayload::from_fqdn("vpn.example.com");
        assert_eq!(id.id_type, IdType::Fqdn);
        assert_eq!(id.as_string().unwrap(), "vpn.example.com");
        assert_eq!(id.total_length(), 4 + 4 + 15); // header + id_type+reserved + data
    }

    #[test]
    fn test_id_payload_email() {
        let id = IdPayload::from_email("user@example.com");
        assert_eq!(id.id_type, IdType::Rfc822Addr);
        assert_eq!(id.as_string().unwrap(), "user@example.com");
    }

    #[test]
    fn test_id_payload_key_id() {
        let key_id = vec![0x01, 0x02, 0x03, 0x04];
        let id = IdPayload::from_key_id(&key_id);
        assert_eq!(id.id_type, IdType::KeyId);
        assert_eq!(id.data, key_id);
        assert!(id.as_string().is_none()); // Key ID is binary, not string
    }

    #[test]
    fn test_id_payload_roundtrip() {
        let original = IdPayload::from_fqdn("test.example.com");
        let serialized = original.to_payload_data();
        let parsed = IdPayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.id_type, original.id_type);
        assert_eq!(parsed.data, original.data);
    }

    #[test]
    fn test_id_type_conversion() {
        assert_eq!(IdType::from_u8(2), Some(IdType::Fqdn));
        assert_eq!(IdType::from_u8(3), Some(IdType::Rfc822Addr));
        assert_eq!(IdType::from_u8(11), Some(IdType::KeyId));
        assert_eq!(IdType::from_u8(99), None);

        assert_eq!(IdType::Fqdn.to_u8(), 2);
    }

    // AUTH Payload tests

    #[test]
    fn test_auth_payload_psk() {
        let auth_data = vec![0xAA; 32]; // 32 bytes of 0xAA
        let auth = AuthPayload::new(AuthMethod::SharedKeyMic, auth_data.clone());

        assert_eq!(auth.auth_method, AuthMethod::SharedKeyMic);
        assert_eq!(auth.auth_data, auth_data);
        assert_eq!(auth.total_length(), 4 + 4 + 32); // header + method+reserved + data
    }

    #[test]
    fn test_auth_payload_rsa() {
        let auth_data = vec![0xBB; 256]; // RSA signature
        let auth = AuthPayload::new(AuthMethod::RsaSig, auth_data.clone());

        assert_eq!(auth.auth_method, AuthMethod::RsaSig);
        assert_eq!(auth.auth_data.len(), 256);
    }

    #[test]
    fn test_auth_payload_ecdsa() {
        let auth_data = vec![0xCC; 64]; // ECDSA signature
        let auth = AuthPayload::new(AuthMethod::EcdsaSha256P256, auth_data.clone());

        assert_eq!(auth.auth_method, AuthMethod::EcdsaSha256P256);
    }

    #[test]
    fn test_auth_payload_roundtrip() {
        let original = AuthPayload::new(AuthMethod::SharedKeyMic, vec![1, 2, 3, 4, 5]);
        let serialized = original.to_payload_data();
        let parsed = AuthPayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.auth_method, original.auth_method);
        assert_eq!(parsed.auth_data, original.auth_data);
    }

    #[test]
    fn test_auth_method_conversion() {
        assert_eq!(AuthMethod::from_u8(1), Some(AuthMethod::RsaSig));
        assert_eq!(AuthMethod::from_u8(2), Some(AuthMethod::SharedKeyMic));
        assert_eq!(AuthMethod::from_u8(9), Some(AuthMethod::EcdsaSha256P256));
        assert_eq!(AuthMethod::from_u8(99), None);

        assert_eq!(AuthMethod::SharedKeyMic.to_u8(), 2);
    }
}
