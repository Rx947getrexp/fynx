//! IKEv2 Proposal and Transform structures
//!
//! Implements SA proposal negotiation as defined in RFC 7296 Section 3.3.
//!
//! # Structure
//!
//! ```text
//! SA Payload
//!   └── Proposal(s)
//!         └── Transform(s)
//! ```

use crate::ipsec::{Error, Result};

/// Transform Type (RFC 7296 Section 3.3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransformType {
    /// Encryption Algorithm (ENCR)
    Encr = 1,
    /// Pseudo-random Function (PRF)
    Prf = 2,
    /// Integrity Algorithm (INTEG)
    Integ = 3,
    /// Diffie-Hellman Group (D-H)
    Dh = 4,
    /// Extended Sequence Numbers (ESN)
    Esn = 5,
}

impl TransformType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(TransformType::Encr),
            2 => Some(TransformType::Prf),
            3 => Some(TransformType::Integ),
            4 => Some(TransformType::Dh),
            5 => Some(TransformType::Esn),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Transform ID for Encryption (ENCR) algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EncrTransformId {
    /// AES-CBC with 128-bit key
    AesCbc128 = 12,
    /// AES-CBC with 256-bit key
    AesCbc256 = 14,
    /// AES-GCM with 128-bit key and 16-byte ICV
    AesGcm128 = 20,
    /// AES-GCM with 256-bit key and 16-byte ICV
    AesGcm256 = 21,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 28,
}

impl EncrTransformId {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            12 => Some(EncrTransformId::AesCbc128),
            14 => Some(EncrTransformId::AesCbc256),
            20 => Some(EncrTransformId::AesGcm128),
            21 => Some(EncrTransformId::AesGcm256),
            28 => Some(EncrTransformId::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    /// Check if this is an AEAD cipher
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            EncrTransformId::AesGcm128
                | EncrTransformId::AesGcm256
                | EncrTransformId::ChaCha20Poly1305
        )
    }
}

/// Transform ID for PRF algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PrfTransformId {
    /// HMAC-SHA2-256
    HmacSha256 = 5,
    /// HMAC-SHA2-384
    HmacSha384 = 6,
    /// HMAC-SHA2-512
    HmacSha512 = 7,
}

impl PrfTransformId {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            5 => Some(PrfTransformId::HmacSha256),
            6 => Some(PrfTransformId::HmacSha384),
            7 => Some(PrfTransformId::HmacSha512),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Transform ID for Integrity algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IntegTransformId {
    /// HMAC-SHA2-256-128 (128-bit ICV)
    HmacSha256_128 = 12,
    /// HMAC-SHA2-384-192 (192-bit ICV)
    HmacSha384_192 = 13,
    /// HMAC-SHA2-512-256 (256-bit ICV)
    HmacSha512_256 = 14,
}

impl IntegTransformId {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            12 => Some(IntegTransformId::HmacSha256_128),
            13 => Some(IntegTransformId::HmacSha384_192),
            14 => Some(IntegTransformId::HmacSha512_256),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Transform ID for Diffie-Hellman groups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DhTransformId {
    /// 2048-bit MODP Group
    Group14 = 14,
    /// 3072-bit MODP Group
    Group15 = 15,
    /// 4096-bit MODP Group
    Group16 = 16,
    /// Curve25519
    Group31 = 31,
}

impl DhTransformId {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            14 => Some(DhTransformId::Group14),
            15 => Some(DhTransformId::Group15),
            16 => Some(DhTransformId::Group16),
            31 => Some(DhTransformId::Group31),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Transform attribute (e.g., key length)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformAttribute {
    /// Attribute type
    pub attr_type: u16,
    /// Attribute value
    pub value: Vec<u8>,
}

/// IKE Transform
///
/// Represents a single cryptographic algorithm choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    /// Transform type
    pub transform_type: TransformType,

    /// Transform ID
    pub transform_id: u16,

    /// Attributes (e.g., key length)
    pub attributes: Vec<TransformAttribute>,
}

impl Transform {
    /// Create new transform
    pub fn new(transform_type: TransformType, transform_id: u16) -> Self {
        Transform {
            transform_type,
            transform_id,
            attributes: Vec::new(),
        }
    }

    /// Create encryption transform
    pub fn encr(id: EncrTransformId) -> Self {
        Transform::new(TransformType::Encr, id.to_u16())
    }

    /// Create PRF transform
    pub fn prf(id: PrfTransformId) -> Self {
        Transform::new(TransformType::Prf, id.to_u16())
    }

    /// Create integrity transform
    pub fn integ(id: IntegTransformId) -> Self {
        Transform::new(TransformType::Integ, id.to_u16())
    }

    /// Create DH group transform
    pub fn dh(id: DhTransformId) -> Self {
        Transform::new(TransformType::Dh, id.to_u16())
    }

    /// Add attribute
    pub fn with_attribute(mut self, attr_type: u16, value: Vec<u8>) -> Self {
        self.attributes
            .push(TransformAttribute { attr_type, value });
        self
    }

    /// Check if this transform is compatible with another
    pub fn is_compatible_with(&self, other: &Transform) -> bool {
        self.transform_type == other.transform_type && self.transform_id == other.transform_id
    }

    /// Serialize transform to bytes (RFC 7296 Section 3.3.2)
    ///
    /// Format:
    /// - Byte 0: Last/More flag (0 = last, 3 = more)
    /// - Bytes 1-3: Reserved
    /// - Bytes 4-5: Transform Length
    /// - Byte 6: Transform Type
    /// - Byte 7: Reserved
    /// - Bytes 8-9: Transform ID
    /// - Bytes 10+: Attributes (if any)
    pub fn to_bytes(&self, is_last: bool) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Calculate total length (from length field onwards)
        // Transform Length = length field (2) + type (1) + reserved (1) + id (2) + attributes
        // = 6 + attr_len
        let attr_bytes: Vec<Vec<u8>> = self
            .attributes
            .iter()
            .map(|attr| {
                // Attribute format: 2 bytes type/len, then value
                let mut ab = Vec::new();
                ab.extend_from_slice(&attr.attr_type.to_be_bytes());
                ab.extend_from_slice(&attr.value);
                ab
            })
            .collect();
        let attr_len: usize = attr_bytes.iter().map(|ab| ab.len()).sum();
        let total_len = 2 + 1 + 1 + 2 + attr_len; // = 6 + attr_len

        // Byte 0: Last/More (0 = last, 3 = more)
        bytes.push(if is_last { 0 } else { 3 });

        // Bytes 1-3: Reserved
        bytes.extend_from_slice(&[0u8; 3]);

        // Bytes 4-5: Transform Length
        bytes.extend_from_slice(&(total_len as u16).to_be_bytes());

        // Byte 6: Transform Type
        bytes.push(self.transform_type.to_u8());

        // Byte 7: Reserved
        bytes.push(0);

        // Bytes 8-9: Transform ID
        bytes.extend_from_slice(&self.transform_id.to_be_bytes());

        // Attributes
        for attr_byte in attr_bytes {
            bytes.extend_from_slice(&attr_byte);
        }

        bytes
    }

    /// Parse transform from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, bool, usize)> {
        if data.len() < 8 {
            return Err(Error::BufferTooShort {
                required: 8,
                available: data.len(),
            });
        }

        // Byte 0: Last/More
        let is_last = data[0] == 0;

        // Bytes 4-5: Transform Length
        let transform_len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < transform_len {
            return Err(Error::BufferTooShort {
                required: transform_len,
                available: data.len(),
            });
        }

        // Byte 6: Transform Type
        let transform_type = TransformType::from_u8(data[6])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown transform type: {}", data[6])))?;

        // Bytes 8-9: Transform ID
        let transform_id = u16::from_be_bytes([data[8], data[9]]);

        // Parse attributes (simplified - skip for now)
        let attributes = Vec::new();

        let transform = Transform {
            transform_type,
            transform_id,
            attributes,
        };

        // Return total bytes consumed (including last/more + reserved header)
        // = 4 (header) + transform_len
        Ok((transform, is_last, 4 + transform_len))
    }
}

/// Protocol ID for proposals
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProtocolId {
    /// IKE SA
    Ike = 1,
    /// AH (Authentication Header) - not commonly used
    Ah = 2,
    /// ESP (Encapsulating Security Payload)
    Esp = 3,
}

impl ProtocolId {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ProtocolId::Ike),
            2 => Some(ProtocolId::Ah),
            3 => Some(ProtocolId::Esp),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// IKE Proposal
///
/// Represents a single proposal containing one or more transforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Proposal number (1-based)
    pub proposal_num: u8,

    /// Protocol ID (IKE, ESP, AH)
    pub protocol_id: ProtocolId,

    /// SPI (Security Parameter Index) - empty for IKE_SA_INIT
    pub spi: Vec<u8>,

    /// List of transforms
    pub transforms: Vec<Transform>,
}

impl Proposal {
    /// Create new proposal
    pub fn new(proposal_num: u8, protocol_id: ProtocolId) -> Self {
        Proposal {
            proposal_num,
            protocol_id,
            spi: Vec::new(),
            transforms: Vec::new(),
        }
    }

    /// Add transform to proposal
    pub fn add_transform(mut self, transform: Transform) -> Self {
        self.transforms.push(transform);
        self
    }

    /// Set SPI
    pub fn with_spi(mut self, spi: Vec<u8>) -> Self {
        self.spi = spi;
        self
    }

    /// Check if proposal is acceptable given a list of configured proposals
    ///
    /// Returns true if all transforms in this proposal match at least one configured proposal.
    pub fn is_acceptable(&self, configured: &[Proposal]) -> bool {
        // Find a configured proposal with same protocol
        for config in configured {
            if config.protocol_id != self.protocol_id {
                continue;
            }

            // Check if all our transforms are in configured proposal
            let all_match = self.transforms.iter().all(|our_transform| {
                config
                    .transforms
                    .iter()
                    .any(|config_transform| our_transform.is_compatible_with(config_transform))
            });

            if all_match {
                return true;
            }
        }

        false
    }

    /// Get transform by type
    pub fn get_transform(&self, transform_type: TransformType) -> Option<&Transform> {
        self.transforms
            .iter()
            .find(|t| t.transform_type == transform_type)
    }

    /// Serialize proposal to bytes (RFC 7296 Section 3.3.1)
    ///
    /// Format:
    /// - Byte 0: Last/More flag (0 = last, 2 = more)
    /// - Bytes 1-3: Reserved
    /// - Bytes 4-5: Proposal Length
    /// - Byte 6: Proposal Number
    /// - Byte 7: Protocol ID
    /// - Byte 8: SPI Size
    /// - Byte 9: Num Transforms
    /// - Bytes 10+: SPI (variable)
    /// - Transforms
    pub fn to_bytes(&self, is_last: bool) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize all transforms
        let transform_bytes: Vec<Vec<u8>> = self
            .transforms
            .iter()
            .enumerate()
            .map(|(i, t)| t.to_bytes(i == self.transforms.len() - 1))
            .collect();
        let transforms_len: usize = transform_bytes.iter().map(|tb| tb.len()).sum();

        // Calculate total length (from length field onwards)
        // Proposal Length = length (2) + proposal_num (1) + protocol_id (1) + spi_size (1) + num_transforms (1) + SPI + transforms
        // = 6 + spi_size + transforms_len
        let spi_size = self.spi.len();
        let total_len = 2 + 1 + 1 + 1 + 1 + spi_size + transforms_len; // = 6 + spi_size + transforms_len

        // Byte 0: Last/More (0 = last, 2 = more)
        bytes.push(if is_last { 0 } else { 2 });

        // Bytes 1-3: Reserved
        bytes.extend_from_slice(&[0u8; 3]);

        // Bytes 4-5: Proposal Length
        bytes.extend_from_slice(&(total_len as u16).to_be_bytes());

        // Byte 6: Proposal Number
        bytes.push(self.proposal_num);

        // Byte 7: Protocol ID
        bytes.push(self.protocol_id.to_u8());

        // Byte 8: SPI Size
        bytes.push(spi_size as u8);

        // Byte 9: Num Transforms
        bytes.push(self.transforms.len() as u8);

        // SPI
        bytes.extend_from_slice(&self.spi);

        // Transforms
        for transform_byte in transform_bytes {
            bytes.extend_from_slice(&transform_byte);
        }

        bytes
    }

    /// Parse proposal from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, bool, usize)> {
        if data.len() < 8 {
            return Err(Error::BufferTooShort {
                required: 8,
                available: data.len(),
            });
        }

        // Byte 0: Last/More
        let is_last = data[0] == 0;

        // Bytes 4-5: Proposal Length
        let proposal_len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < proposal_len {
            return Err(Error::BufferTooShort {
                required: proposal_len,
                available: data.len(),
            });
        }

        // Byte 6: Proposal Number
        let proposal_num = data[6];

        // Byte 7: Protocol ID
        let protocol_id = ProtocolId::from_u8(data[7])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown protocol ID: {}", data[7])))?;

        // Byte 8: SPI Size
        let spi_size = data[8] as usize;

        // Byte 9: Num Transforms
        let num_transforms = data[9] as usize;

        // Validate we have enough data for SPI
        if data.len() < 10 + spi_size {
            return Err(Error::BufferTooShort {
                required: 10 + spi_size,
                available: data.len(),
            });
        }

        // Parse SPI
        let spi = data[10..10 + spi_size].to_vec();

        // Parse transforms
        let mut transforms = Vec::new();
        let mut offset = 10 + spi_size;

        for _ in 0..num_transforms {
            let (transform, _, transform_len) = Transform::from_bytes(&data[offset..])?;
            transforms.push(transform);
            offset += transform_len;
        }

        let proposal = Proposal {
            proposal_num,
            protocol_id,
            spi,
            transforms,
        };

        // Return total bytes consumed (including last/more + reserved header)
        // = 4 (header) + proposal_len
        Ok((proposal, is_last, 4 + proposal_len))
    }
}

/// Select first acceptable proposal from a list
///
/// This implements the proposal selection algorithm from RFC 7296 Section 2.7.
///
/// # Arguments
///
/// * `offered` - Proposals offered by peer
/// * `configured` - Locally configured acceptable proposals
///
/// # Returns
///
/// Returns the first acceptable proposal, or error if none found.
pub fn select_proposal<'a>(
    offered: &'a [Proposal],
    configured: &[Proposal],
) -> Result<&'a Proposal> {
    for proposal in offered {
        if proposal.is_acceptable(configured) {
            return Ok(proposal);
        }
    }

    Err(Error::NoProposalChosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_serialization() {
        let transform = Transform::encr(EncrTransformId::AesGcm128);
        let bytes = transform.to_bytes(true);

        eprintln!(
            "Transform bytes ({} bytes): {:02x?}",
            bytes.len(),
            &bytes[..std::cmp::min(20, bytes.len())]
        );
        eprintln!("  Byte 0 (last/more): {}", bytes[0]);
        eprintln!(
            "  Bytes 4-5 (length): {:?}",
            u16::from_be_bytes([bytes[4], bytes[5]])
        );
        eprintln!("  Byte 6 (type): {}", bytes[6]);
        eprintln!(
            "  Bytes 8-9 (id): {:?}",
            u16::from_be_bytes([bytes[8], bytes[9]])
        );

        let (parsed, is_last, len) = Transform::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.transform_type, TransformType::Encr);
        assert_eq!(parsed.transform_id, 20); // AES-GCM-128
        assert!(is_last);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn test_transform_type_conversion() {
        assert_eq!(TransformType::from_u8(1), Some(TransformType::Encr));
        assert_eq!(TransformType::from_u8(4), Some(TransformType::Dh));
        assert_eq!(TransformType::from_u8(99), None);

        assert_eq!(TransformType::Encr.to_u8(), 1);
    }

    #[test]
    fn test_encr_transform_id() {
        assert_eq!(
            EncrTransformId::from_u16(20),
            Some(EncrTransformId::AesGcm128)
        );
        assert!(EncrTransformId::AesGcm128.is_aead());
        assert!(!EncrTransformId::AesCbc128.is_aead());
    }

    #[test]
    fn test_transform_creation() {
        let encr = Transform::encr(EncrTransformId::AesGcm256);
        assert_eq!(encr.transform_type, TransformType::Encr);
        assert_eq!(encr.transform_id, 21);

        let prf = Transform::prf(PrfTransformId::HmacSha256);
        assert_eq!(prf.transform_type, TransformType::Prf);
        assert_eq!(prf.transform_id, 5);
    }

    #[test]
    fn test_transform_compatibility() {
        let t1 = Transform::encr(EncrTransformId::AesGcm256);
        let t2 = Transform::encr(EncrTransformId::AesGcm256);
        let t3 = Transform::encr(EncrTransformId::AesGcm128);

        assert!(t1.is_compatible_with(&t2));
        assert!(!t1.is_compatible_with(&t3));
    }

    #[test]
    fn test_proposal_creation() {
        let proposal = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14));

        assert_eq!(proposal.proposal_num, 1);
        assert_eq!(proposal.protocol_id, ProtocolId::Ike);
        assert_eq!(proposal.transforms.len(), 3);
    }

    #[test]
    fn test_proposal_get_transform() {
        let proposal = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256));

        let encr = proposal.get_transform(TransformType::Encr).unwrap();
        assert_eq!(encr.transform_id, 21);

        let integ = proposal.get_transform(TransformType::Integ);
        assert!(integ.is_none());
    }

    #[test]
    fn test_proposal_is_acceptable() {
        // Offered proposal
        let offered = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14));

        // Configured proposals (what we accept)
        let configured = vec![Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14))];

        assert!(offered.is_acceptable(&configured));
    }

    #[test]
    fn test_proposal_not_acceptable() {
        let offered = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256));

        let configured = vec![Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm128))];

        assert!(!offered.is_acceptable(&configured));
    }

    #[test]
    fn test_select_proposal() {
        let offered = vec![
            Proposal::new(1, ProtocolId::Ike)
                .add_transform(Transform::encr(EncrTransformId::AesGcm128)),
            Proposal::new(2, ProtocolId::Ike)
                .add_transform(Transform::encr(EncrTransformId::AesGcm256)),
        ];

        let configured = vec![Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))];

        let selected = select_proposal(&offered, &configured).unwrap();
        assert_eq!(selected.proposal_num, 2);
    }

    #[test]
    fn test_select_proposal_no_match() {
        let offered = vec![Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm128))];

        let configured = vec![Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))];

        let result = select_proposal(&offered, &configured);
        assert!(matches!(result, Err(Error::NoProposalChosen)));
    }

    #[test]
    fn test_protocol_id_conversion() {
        assert_eq!(ProtocolId::from_u8(1), Some(ProtocolId::Ike));
        assert_eq!(ProtocolId::from_u8(3), Some(ProtocolId::Esp));
        assert_eq!(ProtocolId::Esp.to_u8(), 3);
    }
}
