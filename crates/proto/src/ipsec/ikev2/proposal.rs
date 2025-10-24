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

use super::constants::PayloadType;
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
        self.attributes.push(TransformAttribute { attr_type, value });
        self
    }

    /// Check if this transform is compatible with another
    pub fn is_compatible_with(&self, other: &Transform) -> bool {
        self.transform_type == other.transform_type && self.transform_id == other.transform_id
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
        let configured = vec![
            Proposal::new(1, ProtocolId::Ike)
                .add_transform(Transform::encr(EncrTransformId::AesGcm256))
                .add_transform(Transform::prf(PrfTransformId::HmacSha256))
                .add_transform(Transform::dh(DhTransformId::Group14)),
        ];

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
