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

    /// Notify payload
    N(NotifyPayload),

    /// Delete payload
    D(DeletePayload),

    /// Vendor ID payload
    V(VendorIdPayload),

    /// Traffic Selector - Initiator
    TSi(TrafficSelectorsPayload),

    /// Traffic Selector - Responder
    TSr(TrafficSelectorsPayload),

    /// Encrypted payload (SK)
    SK(EncryptedPayload),

    /// NAT Detection Source IP payload
    NatDetectionSourceIp(NatDetectionSourceIpPayload),

    /// NAT Detection Destination IP payload
    NatDetectionDestinationIp(NatDetectionDestinationIpPayload),

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
            IkePayload::N(_) => PayloadType::N,
            IkePayload::D(_) => PayloadType::D,
            IkePayload::V(_) => PayloadType::V,
            IkePayload::TSi(_) => PayloadType::TSi,
            IkePayload::TSr(_) => PayloadType::TSr,
            IkePayload::SK(_) => PayloadType::SK,
            IkePayload::NatDetectionSourceIp(_) => PayloadType::NatDetectionSourceIp,
            IkePayload::NatDetectionDestinationIp(_) => PayloadType::NatDetectionDestinationIp,
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
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(SaPayload {
                proposals: Vec::new(),
            });
        }

        // Parse proposals
        let mut proposals = Vec::new();
        let mut offset = 0;

        loop {
            if offset >= data.len() {
                break;
            }

            let (proposal, is_last, proposal_len) = Proposal::from_bytes(&data[offset..])?;
            proposals.push(proposal);
            offset += proposal_len;

            if is_last {
                break;
            }
        }

        Ok(SaPayload { proposals })
    }

    /// Serialize SA payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        if self.proposals.is_empty() {
            return Vec::new();
        }

        // Serialize all proposals
        let mut bytes = Vec::new();
        for (i, proposal) in self.proposals.iter().enumerate() {
            let is_last = i == self.proposals.len() - 1;
            bytes.extend_from_slice(&proposal.to_bytes(is_last));
        }

        bytes
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
        let auth_method = AuthMethod::from_u8(data[0])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown auth method: {}", data[0])))?;

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

/// Notify Message Types (RFC 7296 Section 3.10.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NotifyType {
    // Error Types (1-16383)
    /// Unsupported critical payload
    UnsupportedCriticalPayload = 1,
    /// Invalid IKE SPI
    InvalidIkeSpi = 4,
    /// Invalid major version
    InvalidMajorVersion = 5,
    /// Invalid syntax
    InvalidSyntax = 7,
    /// Invalid message ID
    InvalidMessageId = 9,
    /// Invalid SPI
    InvalidSpi = 11,
    /// No proposal chosen
    NoProposalChosen = 14,
    /// Invalid KE payload
    InvalidKePayload = 17,
    /// Authentication failed
    AuthenticationFailed = 24,
    /// Single pair required
    SinglePairRequired = 34,
    /// No additional SAs
    NoAdditionalSas = 35,
    /// Internal address failure
    InternalAddressFailure = 36,
    /// Failed CP required
    FailedCpRequired = 37,
    /// TS unacceptable
    TsUnacceptable = 38,
    /// Invalid selectors
    InvalidSelectors = 39,
    /// Temporary failure
    TemporaryFailure = 43,
    /// Child SA not found
    ChildSaNotFound = 44,

    // Status Types (16384-65535)
    /// Initial contact
    InitialContact = 16384,
    /// Set window size
    SetWindowSize = 16385,
    /// Additional TS possible
    AdditionalTsPossible = 16386,
    /// IPComp supported
    IpcompSupported = 16387,
    /// NAT detection source IP
    NatDetectionSourceIp = 16388,
    /// NAT detection destination IP
    NatDetectionDestinationIp = 16389,
    /// Cookie
    Cookie = 16390,
    /// Use transport mode
    UseTransportMode = 16391,
    /// HTTP cert lookup supported
    HttpCertLookupSupported = 16392,
    /// Rekey SA
    RekeySa = 16393,
    /// ESP TFC padding not supported
    EspTfcPaddingNotSupported = 16394,
    /// Non first fragments also
    NonFirstFragmentsAlso = 16395,
}

impl NotifyType {
    /// Convert from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(NotifyType::UnsupportedCriticalPayload),
            4 => Some(NotifyType::InvalidIkeSpi),
            5 => Some(NotifyType::InvalidMajorVersion),
            7 => Some(NotifyType::InvalidSyntax),
            9 => Some(NotifyType::InvalidMessageId),
            11 => Some(NotifyType::InvalidSpi),
            14 => Some(NotifyType::NoProposalChosen),
            17 => Some(NotifyType::InvalidKePayload),
            24 => Some(NotifyType::AuthenticationFailed),
            34 => Some(NotifyType::SinglePairRequired),
            35 => Some(NotifyType::NoAdditionalSas),
            36 => Some(NotifyType::InternalAddressFailure),
            37 => Some(NotifyType::FailedCpRequired),
            38 => Some(NotifyType::TsUnacceptable),
            39 => Some(NotifyType::InvalidSelectors),
            43 => Some(NotifyType::TemporaryFailure),
            44 => Some(NotifyType::ChildSaNotFound),
            16384 => Some(NotifyType::InitialContact),
            16385 => Some(NotifyType::SetWindowSize),
            16386 => Some(NotifyType::AdditionalTsPossible),
            16387 => Some(NotifyType::IpcompSupported),
            16388 => Some(NotifyType::NatDetectionSourceIp),
            16389 => Some(NotifyType::NatDetectionDestinationIp),
            16390 => Some(NotifyType::Cookie),
            16391 => Some(NotifyType::UseTransportMode),
            16392 => Some(NotifyType::HttpCertLookupSupported),
            16393 => Some(NotifyType::RekeySa),
            16394 => Some(NotifyType::EspTfcPaddingNotSupported),
            16395 => Some(NotifyType::NonFirstFragmentsAlso),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    /// Check if this is an error notification
    pub fn is_error(self) -> bool {
        (self as u16) < 16384
    }

    /// Check if this is a status notification
    pub fn is_status(self) -> bool {
        (self as u16) >= 16384
    }
}

/// Protocol ID for NOTIFY payload (RFC 7296 Section 3.10)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NotifyProtocolId {
    /// No protocol (0)
    None = 0,
    /// IKE (1)
    Ike = 1,
    /// AH (2)
    Ah = 2,
    /// ESP (3)
    Esp = 3,
}

impl NotifyProtocolId {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(NotifyProtocolId::None),
            1 => Some(NotifyProtocolId::Ike),
            2 => Some(NotifyProtocolId::Ah),
            3 => Some(NotifyProtocolId::Esp),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// NOTIFY payload (RFC 7296 Section 3.10)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Protocol ID   |   SPI Size    |      Notify Message Type      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                Security Parameter Index (SPI)                 ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                       Notification Data                       ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyPayload {
    /// Protocol ID
    pub protocol_id: NotifyProtocolId,

    /// Notification message type
    pub notify_type: NotifyType,

    /// Security Parameter Index (SPI)
    pub spi: Vec<u8>,

    /// Notification data
    pub notification_data: Vec<u8>,
}

impl NotifyPayload {
    /// Create new NOTIFY payload
    pub fn new(
        protocol_id: NotifyProtocolId,
        notify_type: NotifyType,
        spi: Vec<u8>,
        notification_data: Vec<u8>,
    ) -> Self {
        NotifyPayload {
            protocol_id,
            notify_type,
            spi,
            notification_data,
        }
    }

    /// Create simple error notification (no SPI, no data)
    pub fn error(notify_type: NotifyType) -> Self {
        NotifyPayload {
            protocol_id: NotifyProtocolId::None,
            notify_type,
            spi: Vec::new(),
            notification_data: Vec::new(),
        }
    }

    /// Create status notification with data
    pub fn status(notify_type: NotifyType, data: Vec<u8>) -> Self {
        NotifyPayload {
            protocol_id: NotifyProtocolId::None,
            notify_type,
            spi: Vec::new(),
            notification_data: data,
        }
    }

    /// Parse NOTIFY payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                required: 4,
                available: data.len(),
            });
        }

        // Parse protocol ID
        let protocol_id = NotifyProtocolId::from_u8(data[0])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown protocol ID: {}", data[0])))?;

        // Parse SPI size
        let spi_size = data[1] as usize;

        // Parse notify type (big-endian u16)
        let notify_type_value = u16::from_be_bytes([data[2], data[3]]);
        let notify_type = NotifyType::from_u16(notify_type_value).ok_or_else(|| {
            Error::InvalidPayload(format!("Unknown notify type: {}", notify_type_value))
        })?;

        // Parse SPI
        if data.len() < 4 + spi_size {
            return Err(Error::BufferTooShort {
                required: 4 + spi_size,
                available: data.len(),
            });
        }
        let spi = data[4..4 + spi_size].to_vec();

        // Parse notification data
        let notification_data = data[4 + spi_size..].to_vec();

        Ok(NotifyPayload {
            protocol_id,
            notify_type,
            spi,
            notification_data,
        })
    }

    /// Serialize NOTIFY payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.spi.len() + self.notification_data.len());

        // Write protocol ID
        bytes.push(self.protocol_id.to_u8());

        // Write SPI size
        bytes.push(self.spi.len() as u8);

        // Write notify type (big-endian)
        let notify_type_bytes = self.notify_type.to_u16().to_be_bytes();
        bytes.extend_from_slice(&notify_type_bytes);

        // Write SPI
        bytes.extend_from_slice(&self.spi);

        // Write notification data
        bytes.extend_from_slice(&self.notification_data);

        bytes
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + 4 + self.spi.len() + self.notification_data.len()) as u16
    }

    /// Check if this is an error notification
    pub fn is_error(&self) -> bool {
        self.notify_type.is_error()
    }

    /// Check if this is a status notification
    pub fn is_status(&self) -> bool {
        self.notify_type.is_status()
    }
}

/// DELETE payload (RFC 7296 Section 3.11)
///
/// Used to delete Security Associations.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Protocol ID   |   SPI Size    |           # of SPIs           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~               Security Parameter Index(es) (SPI)              ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletePayload {
    /// Protocol ID (IKE, AH, ESP)
    pub protocol_id: NotifyProtocolId,

    /// SPI size in bytes
    pub spi_size: u8,

    /// List of SPIs to delete
    pub spis: Vec<Vec<u8>>,
}

impl DeletePayload {
    /// Create new DELETE payload
    pub fn new(protocol_id: NotifyProtocolId, spi_size: u8, spis: Vec<Vec<u8>>) -> Self {
        DeletePayload {
            protocol_id,
            spi_size,
            spis,
        }
    }

    /// Create DELETE for IKE SA (no SPIs)
    pub fn delete_ike_sa() -> Self {
        DeletePayload {
            protocol_id: NotifyProtocolId::Ike,
            spi_size: 0,
            spis: Vec::new(),
        }
    }

    /// Create DELETE for single ESP SA
    pub fn delete_esp_sa(spi: Vec<u8>) -> Self {
        let spi_size = spi.len() as u8;
        DeletePayload {
            protocol_id: NotifyProtocolId::Esp,
            spi_size,
            spis: vec![spi],
        }
    }

    /// Parse DELETE payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                required: 4,
                available: data.len(),
            });
        }

        // Parse protocol ID
        let protocol_id = NotifyProtocolId::from_u8(data[0])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown protocol ID: {}", data[0])))?;

        // Parse SPI size
        let spi_size = data[1];

        // Parse number of SPIs (big-endian u16)
        let num_spis = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Validate data length
        let expected_length = 4 + (num_spis * spi_size as usize);
        if data.len() < expected_length {
            return Err(Error::BufferTooShort {
                required: expected_length,
                available: data.len(),
            });
        }

        // Parse SPIs
        let mut spis = Vec::with_capacity(num_spis);
        let mut offset = 4;
        for _ in 0..num_spis {
            let spi = data[offset..offset + spi_size as usize].to_vec();
            spis.push(spi);
            offset += spi_size as usize;
        }

        Ok(DeletePayload {
            protocol_id,
            spi_size,
            spis,
        })
    }

    /// Serialize DELETE payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.spis.len() * self.spi_size as usize);

        // Write protocol ID
        bytes.push(self.protocol_id.to_u8());

        // Write SPI size
        bytes.push(self.spi_size);

        // Write number of SPIs (big-endian)
        let num_spis = (self.spis.len() as u16).to_be_bytes();
        bytes.extend_from_slice(&num_spis);

        // Write SPIs
        for spi in &self.spis {
            bytes.extend_from_slice(spi);
        }

        bytes
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + 4 + self.spis.len() * self.spi_size as usize) as u16
    }

    /// Get number of SPIs
    pub fn spi_count(&self) -> usize {
        self.spis.len()
    }
}

/// VENDOR_ID payload (RFC 7296 Section 3.12)
///
/// Used to identify vendor-specific implementations.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                        Vendor ID Data                         ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorIdPayload {
    /// Vendor ID data
    pub vendor_id: Vec<u8>,
}

impl VendorIdPayload {
    /// Create new VENDOR_ID payload
    pub fn new(vendor_id: Vec<u8>) -> Self {
        VendorIdPayload { vendor_id }
    }

    /// Create VENDOR_ID from string
    pub fn from_string(s: &str) -> Self {
        VendorIdPayload {
            vendor_id: s.as_bytes().to_vec(),
        }
    }

    /// Parse VENDOR_ID payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        Ok(VendorIdPayload {
            vendor_id: data.to_vec(),
        })
    }

    /// Serialize VENDOR_ID payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        self.vendor_id.clone()
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        (PayloadHeader::SIZE + self.vendor_id.len()) as u16
    }

    /// Get vendor ID as string (if valid UTF-8)
    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.vendor_id.clone()).ok()
    }
}

/// TS Type (Traffic Selector Type) - RFC 7296 Section 3.13.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TsType {
    /// IPv4 address range
    Ipv4AddrRange = 7,
    /// IPv6 address range
    Ipv6AddrRange = 8,
}

impl TsType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            7 => Some(TsType::Ipv4AddrRange),
            8 => Some(TsType::Ipv6AddrRange),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Traffic Selector (RFC 7296 Section 3.13.1)
///
/// Describes a range of IP addresses and ports that will be protected by IPSec.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   TS Type     |IP Protocol ID |       Selector Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Start Port          |           End Port            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                         Starting Address                      ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                         Ending Address                        ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelector {
    /// TS type (IPv4 or IPv6)
    pub ts_type: TsType,

    /// IP protocol ID (0 = any, 6 = TCP, 17 = UDP)
    pub ip_protocol_id: u8,

    /// Start port (0 = any)
    pub start_port: u16,

    /// End port (65535 = any)
    pub end_port: u16,

    /// Starting address (4 bytes for IPv4, 16 bytes for IPv6)
    pub start_address: Vec<u8>,

    /// Ending address (4 bytes for IPv4, 16 bytes for IPv6)
    pub end_address: Vec<u8>,
}

impl TrafficSelector {
    /// Create new traffic selector
    pub fn new(
        ts_type: TsType,
        ip_protocol_id: u8,
        start_port: u16,
        end_port: u16,
        start_address: Vec<u8>,
        end_address: Vec<u8>,
    ) -> Result<Self> {
        // Validate address lengths
        let expected_len = match ts_type {
            TsType::Ipv4AddrRange => 4,
            TsType::Ipv6AddrRange => 16,
        };

        if start_address.len() != expected_len {
            return Err(Error::InvalidPayload(format!(
                "Invalid start address length: expected {}, got {}",
                expected_len,
                start_address.len()
            )));
        }

        if end_address.len() != expected_len {
            return Err(Error::InvalidPayload(format!(
                "Invalid end address length: expected {}, got {}",
                expected_len,
                end_address.len()
            )));
        }

        Ok(TrafficSelector {
            ts_type,
            ip_protocol_id,
            start_port,
            end_port,
            start_address,
            end_address,
        })
    }

    /// Create IPv4 traffic selector for any address/port
    pub fn ipv4_any() -> Self {
        TrafficSelector {
            ts_type: TsType::Ipv4AddrRange,
            ip_protocol_id: 0, // Any protocol
            start_port: 0,
            end_port: 65535,
            start_address: vec![0, 0, 0, 0],
            end_address: vec![255, 255, 255, 255],
        }
    }

    /// Create IPv4 traffic selector for specific address
    pub fn ipv4_addr(addr: [u8; 4]) -> Self {
        TrafficSelector {
            ts_type: TsType::Ipv4AddrRange,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: 65535,
            start_address: addr.to_vec(),
            end_address: addr.to_vec(),
        }
    }

    /// Create IPv6 traffic selector for any address/port
    pub fn ipv6_any() -> Self {
        TrafficSelector {
            ts_type: TsType::Ipv6AddrRange,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: 65535,
            start_address: vec![0; 16],
            end_address: vec![0xFF; 16],
        }
    }

    /// Parse traffic selector from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::BufferTooShort {
                required: 8,
                available: data.len(),
            });
        }

        // Parse TS type
        let ts_type = TsType::from_u8(data[0])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown TS type: {}", data[0])))?;

        // Parse IP protocol ID
        let ip_protocol_id = data[1];

        // Parse selector length (big-endian)
        let selector_length = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Validate buffer length
        if data.len() < selector_length {
            return Err(Error::BufferTooShort {
                required: selector_length,
                available: data.len(),
            });
        }

        // Parse ports
        let start_port = u16::from_be_bytes([data[4], data[5]]);
        let end_port = u16::from_be_bytes([data[6], data[7]]);

        // Determine address length based on type
        let addr_len = match ts_type {
            TsType::Ipv4AddrRange => 4,
            TsType::Ipv6AddrRange => 16,
        };

        // Validate we have enough data for addresses
        if data.len() < 8 + addr_len * 2 {
            return Err(Error::BufferTooShort {
                required: 8 + addr_len * 2,
                available: data.len(),
            });
        }

        // Parse addresses
        let start_address = data[8..8 + addr_len].to_vec();
        let end_address = data[8 + addr_len..8 + addr_len * 2].to_vec();

        Ok(TrafficSelector {
            ts_type,
            ip_protocol_id,
            start_port,
            end_port,
            start_address,
            end_address,
        })
    }

    /// Serialize traffic selector to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.start_address.len() + self.end_address.len());

        // Write TS type
        bytes.push(self.ts_type.to_u8());

        // Write IP protocol ID
        bytes.push(self.ip_protocol_id);

        // Write selector length (big-endian)
        let selector_length = (8 + self.start_address.len() + self.end_address.len()) as u16;
        bytes.extend_from_slice(&selector_length.to_be_bytes());

        // Write ports
        bytes.extend_from_slice(&self.start_port.to_be_bytes());
        bytes.extend_from_slice(&self.end_port.to_be_bytes());

        // Write addresses
        bytes.extend_from_slice(&self.start_address);
        bytes.extend_from_slice(&self.end_address);

        bytes
    }

    /// Get selector length
    pub fn length(&self) -> u16 {
        (8 + self.start_address.len() + self.end_address.len()) as u16
    }
}

/// Traffic Selectors Payload (RFC 7296 Section 3.13)
///
/// Contains one or more traffic selectors.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Number of TSs |                 RESERVED                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                       Traffic Selectors                       ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelectorsPayload {
    /// List of traffic selectors
    pub selectors: Vec<TrafficSelector>,
}

impl TrafficSelectorsPayload {
    /// Create new traffic selectors payload
    pub fn new(selectors: Vec<TrafficSelector>) -> Self {
        TrafficSelectorsPayload { selectors }
    }

    /// Create payload with single selector
    pub fn single(selector: TrafficSelector) -> Self {
        TrafficSelectorsPayload {
            selectors: vec![selector],
        }
    }

    /// Parse traffic selectors payload from data (without header)
    pub fn from_payload_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::BufferTooShort {
                required: 4,
                available: data.len(),
            });
        }

        // Parse number of TSs
        let num_ts = data[0] as usize;

        // Reserved bytes 1-3

        // Parse traffic selectors
        let mut selectors = Vec::with_capacity(num_ts);
        let mut offset = 4;

        for _ in 0..num_ts {
            if offset >= data.len() {
                return Err(Error::BufferTooShort {
                    required: offset + 8,
                    available: data.len(),
                });
            }

            let ts = TrafficSelector::from_bytes(&data[offset..])?;
            let ts_len = ts.length() as usize;
            offset += ts_len;
            selectors.push(ts);
        }

        Ok(TrafficSelectorsPayload { selectors })
    }

    /// Serialize traffic selectors payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write number of TSs
        bytes.push(self.selectors.len() as u8);

        // Write reserved (3 bytes)
        bytes.extend_from_slice(&[0u8, 0u8, 0u8]);

        // Write traffic selectors
        for ts in &self.selectors {
            bytes.extend_from_slice(&ts.to_bytes());
        }

        bytes
    }

    /// Get total payload length (header + data)
    pub fn total_length(&self) -> u16 {
        let data_len: usize = 4 + self
            .selectors
            .iter()
            .map(|ts| ts.length() as usize)
            .sum::<usize>();
        (PayloadHeader::SIZE + data_len) as u16
    }

    /// Get number of selectors
    pub fn count(&self) -> usize {
        self.selectors.len()
    }
}

/// Encrypted Payload (SK) (RFC 7296 Section 3.14)
///
/// The Encrypted payload contains encrypted and integrity-protected data.
/// It is used in IKE_AUTH and subsequent exchanges to protect payload confidentiality.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Initialization Vector                     |
/// |         (length is block size for encryption algorithm)       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                    Encrypted IKE Payloads                     ~
/// +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               |             Padding (0-255 octets)            |
/// +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
/// |                                               |  Pad Length   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                    Integrity Checksum Data                    ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// Initialization Vector (IV)
    /// Length depends on encryption algorithm:
    /// - AES-GCM: 8 bytes (RFC 4106)
    /// - AES-CBC: 16 bytes (AES block size)
    /// - ChaCha20-Poly1305: 12 bytes (RFC 7539)
    pub iv: Vec<u8>,

    /// Encrypted data (includes inner payloads + padding + pad_length)
    /// For AEAD ciphers (AES-GCM, ChaCha20), this includes the auth tag
    pub encrypted_data: Vec<u8>,

    /// Integrity Checksum (ICV) for non-AEAD ciphers
    /// Empty for AEAD ciphers (auth tag is part of encrypted_data)
    pub icv: Vec<u8>,
}

impl EncryptedPayload {
    /// Create new encrypted payload
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector
    /// * `encrypted_data` - Encrypted payload data
    /// * `icv` - Integrity check value (empty for AEAD)
    pub fn new(iv: Vec<u8>, encrypted_data: Vec<u8>, icv: Vec<u8>) -> Self {
        EncryptedPayload {
            iv,
            encrypted_data,
            icv,
        }
    }

    /// Create encrypted payload for AEAD cipher
    ///
    /// AEAD ciphers (AES-GCM, ChaCha20-Poly1305) include the authentication tag
    /// in the encrypted data, so ICV is empty.
    pub fn new_aead(iv: Vec<u8>, encrypted_data_with_tag: Vec<u8>) -> Self {
        EncryptedPayload {
            iv,
            encrypted_data: encrypted_data_with_tag,
            icv: Vec::new(),
        }
    }

    /// Parse encrypted payload from bytes (without header)
    ///
    /// # Arguments
    ///
    /// * `data` - Payload data (IV + encrypted data + ICV)
    /// * `iv_len` - Expected IV length based on encryption algorithm
    /// * `icv_len` - Expected ICV length (0 for AEAD ciphers)
    ///
    /// # Returns
    ///
    /// Returns parsed encrypted payload
    pub fn from_payload_data(data: &[u8], iv_len: usize, icv_len: usize) -> Result<Self> {
        // Validate minimum length: IV + at least 1 byte encrypted + ICV
        if data.len() < iv_len + 1 + icv_len {
            return Err(Error::BufferTooShort {
                required: iv_len + 1 + icv_len,
                available: data.len(),
            });
        }

        // Parse IV
        let iv = data[..iv_len].to_vec();

        // Parse encrypted data (everything between IV and ICV)
        let encrypted_end = data.len() - icv_len;
        let encrypted_data = data[iv_len..encrypted_end].to_vec();

        // Parse ICV (if non-AEAD)
        let icv = if icv_len > 0 {
            data[encrypted_end..].to_vec()
        } else {
            Vec::new()
        };

        Ok(EncryptedPayload {
            iv,
            encrypted_data,
            icv,
        })
    }

    /// Serialize encrypted payload to bytes (without header)
    pub fn to_payload_data(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write IV
        bytes.extend_from_slice(&self.iv);

        // Write encrypted data
        bytes.extend_from_slice(&self.encrypted_data);

        // Write ICV (if non-AEAD)
        bytes.extend_from_slice(&self.icv);

        bytes
    }

    /// Get total payload length (header + IV + encrypted data + ICV)
    pub fn total_length(&self) -> u16 {
        let data_len = self.iv.len() + self.encrypted_data.len() + self.icv.len();
        (PayloadHeader::SIZE + data_len) as u16
    }

    /// Get IV length
    pub fn iv_len(&self) -> usize {
        self.iv.len()
    }

    /// Get encrypted data length
    pub fn encrypted_len(&self) -> usize {
        self.encrypted_data.len()
    }

    /// Get ICV length
    pub fn icv_len(&self) -> usize {
        self.icv.len()
    }

    /// Check if this is an AEAD payload (no separate ICV)
    pub fn is_aead(&self) -> bool {
        self.icv.is_empty()
    }
}

/// NAT Detection Source IP Payload
///
/// Contains SHA-1 hash of (SPIi | SPIr | source IP | source port).
/// Used to detect if the source IP/port has been modified by NAT.
///
/// # Format (RFC 3947 Section 4)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Payload  |C|  RESERVED   |         Payload Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                 HASH (20 bytes for SHA-1)                    ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatDetectionSourceIpPayload {
    /// SHA-1 hash (20 bytes)
    pub hash: [u8; 20],
}

impl NatDetectionSourceIpPayload {
    /// Hash size (SHA-1 produces 20 bytes)
    pub const HASH_SIZE: usize = 20;

    /// Create new NAT detection source IP payload
    pub fn new(hash: [u8; 20]) -> Self {
        NatDetectionSourceIpPayload { hash }
    }

    /// Create from hash bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::HASH_SIZE {
            return Err(Error::InvalidPayload(format!(
                "Invalid NAT detection hash size: {} (expected {})",
                data.len(),
                Self::HASH_SIZE
            )));
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(data);
        Ok(NatDetectionSourceIpPayload { hash })
    }

    /// Serialize to bytes (without payload header)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    /// Get payload length (including header)
    pub fn payload_length(&self) -> u16 {
        (PayloadHeader::SIZE + Self::HASH_SIZE) as u16
    }
}

/// NAT Detection Destination IP Payload
///
/// Contains SHA-1 hash of (SPIi | SPIr | destination IP | destination port).
/// Used to detect if the destination IP/port has been modified by NAT.
///
/// # Format (RFC 3947 Section 4)
///
/// Same format as NAT_DETECTION_SOURCE_IP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatDetectionDestinationIpPayload {
    /// SHA-1 hash (20 bytes)
    pub hash: [u8; 20],
}

impl NatDetectionDestinationIpPayload {
    /// Hash size (SHA-1 produces 20 bytes)
    pub const HASH_SIZE: usize = 20;

    /// Create new NAT detection destination IP payload
    pub fn new(hash: [u8; 20]) -> Self {
        NatDetectionDestinationIpPayload { hash }
    }

    /// Create from hash bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::HASH_SIZE {
            return Err(Error::InvalidPayload(format!(
                "Invalid NAT detection hash size: {} (expected {})",
                data.len(),
                Self::HASH_SIZE
            )));
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(data);
        Ok(NatDetectionDestinationIpPayload { hash })
    }

    /// Serialize to bytes (without payload header)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    /// Get payload length (including header)
    pub fn payload_length(&self) -> u16 {
        (PayloadHeader::SIZE + Self::HASH_SIZE) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_header_parse() {
        let data = [
            33,   // Next payload (SA)
            0x80, // Critical bit set, reserved = 0
            0, 50, // Length = 50
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
        use super::super::proposal::{EncrTransformId, Proposal, ProtocolId, Transform};

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

    // NOTIFY Payload Tests

    #[test]
    fn test_notify_type_error() {
        assert!(NotifyType::NoProposalChosen.is_error());
        assert!(!NotifyType::NoProposalChosen.is_status());
        assert_eq!(NotifyType::NoProposalChosen.to_u16(), 14);
    }

    #[test]
    fn test_notify_type_status() {
        assert!(NotifyType::InitialContact.is_status());
        assert!(!NotifyType::InitialContact.is_error());
        assert_eq!(NotifyType::InitialContact.to_u16(), 16384);
    }

    #[test]
    fn test_notify_type_conversion() {
        assert_eq!(NotifyType::from_u16(14), Some(NotifyType::NoProposalChosen));
        assert_eq!(
            NotifyType::from_u16(16384),
            Some(NotifyType::InitialContact)
        );
        assert_eq!(NotifyType::from_u16(65000), None); // Unknown notify type
    }

    #[test]
    fn test_notify_protocol_id_conversion() {
        assert_eq!(NotifyProtocolId::from_u8(0), Some(NotifyProtocolId::None));
        assert_eq!(NotifyProtocolId::from_u8(1), Some(NotifyProtocolId::Ike));
        assert_eq!(NotifyProtocolId::from_u8(3), Some(NotifyProtocolId::Esp));
        assert_eq!(NotifyProtocolId::from_u8(99), None);

        assert_eq!(NotifyProtocolId::Esp.to_u8(), 3);
    }

    #[test]
    fn test_notify_simple_error() {
        let notify = NotifyPayload::error(NotifyType::AuthenticationFailed);

        assert_eq!(notify.protocol_id, NotifyProtocolId::None);
        assert_eq!(notify.notify_type, NotifyType::AuthenticationFailed);
        assert!(notify.spi.is_empty());
        assert!(notify.notification_data.is_empty());
        assert!(notify.is_error());
        assert!(!notify.is_status());
    }

    #[test]
    fn test_notify_status_with_data() {
        let data = vec![1, 2, 3, 4];
        let notify = NotifyPayload::status(NotifyType::InitialContact, data.clone());

        assert_eq!(notify.protocol_id, NotifyProtocolId::None);
        assert_eq!(notify.notify_type, NotifyType::InitialContact);
        assert!(notify.spi.is_empty());
        assert_eq!(notify.notification_data, data);
        assert!(!notify.is_error());
        assert!(notify.is_status());
    }

    #[test]
    fn test_notify_with_spi() {
        let spi = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let notify = NotifyPayload::new(
            NotifyProtocolId::Esp,
            NotifyType::InvalidSpi,
            spi.clone(),
            Vec::new(),
        );

        assert_eq!(notify.protocol_id, NotifyProtocolId::Esp);
        assert_eq!(notify.notify_type, NotifyType::InvalidSpi);
        assert_eq!(notify.spi, spi);
    }

    #[test]
    fn test_notify_roundtrip() {
        let original = NotifyPayload::new(
            NotifyProtocolId::Ike,
            NotifyType::NoProposalChosen,
            Vec::new(),
            vec![1, 2, 3],
        );

        let serialized = original.to_payload_data();
        let parsed = NotifyPayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.protocol_id, original.protocol_id);
        assert_eq!(parsed.notify_type, original.notify_type);
        assert_eq!(parsed.spi, original.spi);
        assert_eq!(parsed.notification_data, original.notification_data);
    }

    #[test]
    fn test_notify_roundtrip_with_spi() {
        let original = NotifyPayload::new(
            NotifyProtocolId::Esp,
            NotifyType::ChildSaNotFound,
            vec![0x11, 0x22, 0x33, 0x44],
            vec![0xAA, 0xBB],
        );

        let serialized = original.to_payload_data();
        let parsed = NotifyPayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.protocol_id, original.protocol_id);
        assert_eq!(parsed.notify_type, original.notify_type);
        assert_eq!(parsed.spi, original.spi);
        assert_eq!(parsed.notification_data, original.notification_data);
    }

    #[test]
    fn test_notify_total_length() {
        let notify = NotifyPayload::new(
            NotifyProtocolId::None,
            NotifyType::InitialContact,
            Vec::new(),
            vec![1, 2, 3, 4, 5],
        );

        // Header (4) + Protocol (1) + SPI Size (1) + Notify Type (2) + Data (5) = 13
        assert_eq!(notify.total_length(), 13);
    }

    #[test]
    fn test_notify_cookie() {
        let cookie_data = vec![0xFF; 20];
        let notify = NotifyPayload::status(NotifyType::Cookie, cookie_data.clone());

        assert_eq!(notify.notify_type, NotifyType::Cookie);
        assert_eq!(notify.notification_data, cookie_data);
    }

    #[test]
    fn test_notify_nat_detection() {
        let hash_data = vec![0xAA; 20]; // SHA1 hash
        let notify = NotifyPayload::status(NotifyType::NatDetectionSourceIp, hash_data.clone());

        assert_eq!(notify.notify_type, NotifyType::NatDetectionSourceIp);
        assert_eq!(notify.notification_data, hash_data);
    }

    // DELETE Payload Tests

    #[test]
    fn test_delete_ike_sa() {
        let delete = DeletePayload::delete_ike_sa();

        assert_eq!(delete.protocol_id, NotifyProtocolId::Ike);
        assert_eq!(delete.spi_size, 0);
        assert_eq!(delete.spi_count(), 0);
        assert!(delete.spis.is_empty());
    }

    #[test]
    fn test_delete_esp_sa() {
        let spi = vec![0x11, 0x22, 0x33, 0x44];
        let delete = DeletePayload::delete_esp_sa(spi.clone());

        assert_eq!(delete.protocol_id, NotifyProtocolId::Esp);
        assert_eq!(delete.spi_size, 4);
        assert_eq!(delete.spi_count(), 1);
        assert_eq!(delete.spis[0], spi);
    }

    #[test]
    fn test_delete_multiple_spis() {
        let spis = vec![
            vec![0x11, 0x22, 0x33, 0x44],
            vec![0x55, 0x66, 0x77, 0x88],
            vec![0x99, 0xAA, 0xBB, 0xCC],
        ];
        let delete = DeletePayload::new(NotifyProtocolId::Esp, 4, spis.clone());

        assert_eq!(delete.protocol_id, NotifyProtocolId::Esp);
        assert_eq!(delete.spi_size, 4);
        assert_eq!(delete.spi_count(), 3);
        assert_eq!(delete.spis, spis);
    }

    #[test]
    fn test_delete_roundtrip() {
        let original = DeletePayload::new(
            NotifyProtocolId::Esp,
            4,
            vec![vec![0x11, 0x22, 0x33, 0x44], vec![0x55, 0x66, 0x77, 0x88]],
        );

        let serialized = original.to_payload_data();
        let parsed = DeletePayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.protocol_id, original.protocol_id);
        assert_eq!(parsed.spi_size, original.spi_size);
        assert_eq!(parsed.spis, original.spis);
    }

    #[test]
    fn test_delete_total_length() {
        let delete = DeletePayload::new(
            NotifyProtocolId::Esp,
            4,
            vec![vec![0x11, 0x22, 0x33, 0x44], vec![0x55, 0x66, 0x77, 0x88]],
        );

        // Header (4) + Protocol (1) + SPI Size (1) + Num SPIs (2) + 2 SPIs (8) = 16
        assert_eq!(delete.total_length(), 16);
    }

    #[test]
    fn test_delete_empty_spis() {
        let delete = DeletePayload::new(NotifyProtocolId::Ike, 0, Vec::new());

        assert_eq!(delete.spi_count(), 0);
        assert_eq!(delete.total_length(), 8); // Header (4) + 4 bytes
    }

    // VENDOR_ID Payload Tests

    #[test]
    fn test_vendor_id_new() {
        let vendor_data = vec![0x01, 0x02, 0x03, 0x04];
        let vendor_id = VendorIdPayload::new(vendor_data.clone());

        assert_eq!(vendor_id.vendor_id, vendor_data);
    }

    #[test]
    fn test_vendor_id_from_string() {
        let vendor_str = "fynx-ipsec-v0.1.0";
        let vendor_id = VendorIdPayload::from_string(vendor_str);

        assert_eq!(vendor_id.vendor_id, vendor_str.as_bytes());
        assert_eq!(vendor_id.as_string(), Some(vendor_str.to_string()));
    }

    #[test]
    fn test_vendor_id_roundtrip() {
        let original = VendorIdPayload::from_string("test-vendor-123");
        let serialized = original.to_payload_data();
        let parsed = VendorIdPayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.vendor_id, original.vendor_id);
        assert_eq!(parsed.as_string(), original.as_string());
    }

    #[test]
    fn test_vendor_id_binary_data() {
        let binary_data = vec![0xFF; 16];
        let vendor_id = VendorIdPayload::new(binary_data.clone());

        assert_eq!(vendor_id.vendor_id, binary_data);
        assert!(vendor_id.as_string().is_none()); // Not valid UTF-8
    }

    #[test]
    fn test_vendor_id_total_length() {
        let vendor_id = VendorIdPayload::from_string("test");

        // Header (4) + "test" (4) = 8
        assert_eq!(vendor_id.total_length(), 8);
    }

    #[test]
    fn test_vendor_id_empty() {
        let vendor_id = VendorIdPayload::new(Vec::new());

        assert!(vendor_id.vendor_id.is_empty());
        assert_eq!(vendor_id.total_length(), 4); // Just header
    }

    // Traffic Selector Tests

    #[test]
    fn test_ts_type_conversions() {
        assert_eq!(TsType::from_u8(7), Some(TsType::Ipv4AddrRange));
        assert_eq!(TsType::from_u8(8), Some(TsType::Ipv6AddrRange));
        assert_eq!(TsType::from_u8(99), None);

        assert_eq!(TsType::Ipv4AddrRange as u8, 7);
        assert_eq!(TsType::Ipv6AddrRange as u8, 8);
    }

    #[test]
    fn test_traffic_selector_ipv4_any() {
        let ts = TrafficSelector::ipv4_any();

        assert_eq!(ts.ts_type, TsType::Ipv4AddrRange);
        assert_eq!(ts.ip_protocol_id, 0); // Any protocol
        assert_eq!(ts.start_port, 0);
        assert_eq!(ts.end_port, 65535);
        assert_eq!(ts.start_address, vec![0, 0, 0, 0]);
        assert_eq!(ts.end_address, vec![255, 255, 255, 255]);
    }

    #[test]
    fn test_traffic_selector_ipv4_addr() {
        let addr = [192, 168, 1, 100];
        let ts = TrafficSelector::ipv4_addr(addr);

        assert_eq!(ts.ts_type, TsType::Ipv4AddrRange);
        assert_eq!(ts.start_address, vec![192, 168, 1, 100]);
        assert_eq!(ts.end_address, vec![192, 168, 1, 100]);
        assert_eq!(ts.start_port, 0);
        assert_eq!(ts.end_port, 65535);
    }

    #[test]
    fn test_traffic_selector_ipv6_any() {
        let ts = TrafficSelector::ipv6_any();

        assert_eq!(ts.ts_type, TsType::Ipv6AddrRange);
        assert_eq!(ts.ip_protocol_id, 0);
        assert_eq!(ts.start_port, 0);
        assert_eq!(ts.end_port, 65535);
        assert_eq!(ts.start_address, vec![0; 16]);
        assert_eq!(ts.end_address, vec![255; 16]);
    }

    #[test]
    fn test_traffic_selector_new_valid() {
        let ts = TrafficSelector::new(
            TsType::Ipv4AddrRange,
            6, // TCP
            80,
            443,
            vec![192, 168, 1, 0],
            vec![192, 168, 1, 255],
        )
        .unwrap();

        assert_eq!(ts.ip_protocol_id, 6);
        assert_eq!(ts.start_port, 80);
        assert_eq!(ts.end_port, 443);
    }

    #[test]
    fn test_traffic_selector_invalid_address_length() {
        // IPv4 should be 4 bytes
        let result = TrafficSelector::new(
            TsType::Ipv4AddrRange,
            0,
            0,
            65535,
            vec![192, 168, 1], // Only 3 bytes
            vec![192, 168, 1, 255],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_traffic_selector_ipv6_invalid_length() {
        // IPv6 should be 16 bytes
        let result = TrafficSelector::new(
            TsType::Ipv6AddrRange,
            0,
            0,
            65535,
            vec![0; 16],
            vec![255; 15], // Only 15 bytes
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_traffic_selector_roundtrip_ipv4() {
        let original = TrafficSelector::ipv4_addr([10, 0, 0, 1]);
        let serialized = original.to_bytes();
        let parsed = TrafficSelector::from_bytes(&serialized).unwrap();

        assert_eq!(parsed.ts_type, original.ts_type);
        assert_eq!(parsed.ip_protocol_id, original.ip_protocol_id);
        assert_eq!(parsed.start_port, original.start_port);
        assert_eq!(parsed.end_port, original.end_port);
        assert_eq!(parsed.start_address, original.start_address);
        assert_eq!(parsed.end_address, original.end_address);
    }

    #[test]
    fn test_traffic_selector_roundtrip_ipv6() {
        let original = TrafficSelector::ipv6_any();
        let serialized = original.to_bytes();
        let parsed = TrafficSelector::from_bytes(&serialized).unwrap();

        assert_eq!(parsed.ts_type, TsType::Ipv6AddrRange);
        assert_eq!(parsed.start_address, vec![0; 16]);
        assert_eq!(parsed.end_address, vec![255; 16]);
    }

    #[test]
    fn test_traffic_selectors_payload_single() {
        let ts = TrafficSelector::ipv4_any();
        let payload = TrafficSelectorsPayload::new(vec![ts]);

        assert_eq!(payload.count(), 1);
        assert_eq!(payload.selectors.len(), 1);
    }

    #[test]
    fn test_traffic_selectors_payload_multiple() {
        let selectors = vec![
            TrafficSelector::ipv4_addr([192, 168, 1, 1]),
            TrafficSelector::ipv4_addr([10, 0, 0, 1]),
            TrafficSelector::ipv6_any(),
        ];
        let payload = TrafficSelectorsPayload::new(selectors.clone());

        assert_eq!(payload.count(), 3);
        assert_eq!(payload.selectors.len(), 3);
    }

    #[test]
    fn test_traffic_selectors_payload_roundtrip() {
        let selectors = vec![
            TrafficSelector::ipv4_any(),
            TrafficSelector::ipv4_addr([192, 168, 1, 100]),
        ];
        let original = TrafficSelectorsPayload::new(selectors);

        let serialized = original.to_payload_data();
        let parsed = TrafficSelectorsPayload::from_payload_data(&serialized).unwrap();

        assert_eq!(parsed.count(), original.count());
        assert_eq!(parsed.selectors.len(), original.selectors.len());

        for (parsed_ts, original_ts) in parsed.selectors.iter().zip(original.selectors.iter()) {
            assert_eq!(parsed_ts.ts_type, original_ts.ts_type);
            assert_eq!(parsed_ts.start_address, original_ts.start_address);
            assert_eq!(parsed_ts.end_address, original_ts.end_address);
        }
    }

    #[test]
    fn test_traffic_selectors_payload_total_length() {
        let selectors = vec![TrafficSelector::ipv4_any()]; // IPv4 TS: 8 + 4 + 4 = 16 bytes
        let payload = TrafficSelectorsPayload::new(selectors);

        // Header (4) + Num TS (1) + Reserved (3) + TS (16) = 24
        assert_eq!(payload.total_length(), 24);
    }

    #[test]
    fn test_traffic_selectors_payload_empty() {
        let payload = TrafficSelectorsPayload::new(Vec::new());

        assert_eq!(payload.count(), 0);
        assert_eq!(payload.total_length(), 8); // Header (4) + Num TS (1) + Reserved (3)
    }

    #[test]
    fn test_traffic_selector_tcp_port_range() {
        let ts = TrafficSelector::new(
            TsType::Ipv4AddrRange,
            6, // TCP
            1024,
            8080,
            vec![0, 0, 0, 0],
            vec![255, 255, 255, 255],
        )
        .unwrap();

        assert_eq!(ts.ip_protocol_id, 6);
        assert_eq!(ts.start_port, 1024);
        assert_eq!(ts.end_port, 8080);
    }

    // Encrypted Payload (SK) Tests

    #[test]
    fn test_encrypted_payload_new() {
        let iv = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let encrypted = vec![0xAA; 32];
        let icv = vec![0xBB; 16];

        let sk = EncryptedPayload::new(iv.clone(), encrypted.clone(), icv.clone());

        assert_eq!(sk.iv, iv);
        assert_eq!(sk.encrypted_data, encrypted);
        assert_eq!(sk.icv, icv);
        assert!(!sk.is_aead());
    }

    #[test]
    fn test_encrypted_payload_new_aead() {
        let iv = vec![1, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes for AES-GCM
        let encrypted_with_tag = vec![0xAA; 48]; // Data + 16-byte auth tag

        let sk = EncryptedPayload::new_aead(iv.clone(), encrypted_with_tag.clone());

        assert_eq!(sk.iv, iv);
        assert_eq!(sk.encrypted_data, encrypted_with_tag);
        assert!(sk.icv.is_empty());
        assert!(sk.is_aead());
    }

    #[test]
    fn test_encrypted_payload_lengths() {
        let iv = vec![0u8; 8];
        let encrypted = vec![0u8; 32];
        let icv = vec![0u8; 16];

        let sk = EncryptedPayload::new(iv, encrypted, icv);

        assert_eq!(sk.iv_len(), 8);
        assert_eq!(sk.encrypted_len(), 32);
        assert_eq!(sk.icv_len(), 16);
        // Total: header (4) + IV (8) + encrypted (32) + ICV (16) = 60
        assert_eq!(sk.total_length(), 60);
    }

    #[test]
    fn test_encrypted_payload_aead_length() {
        let iv = vec![0u8; 8];
        let encrypted_with_tag = vec![0u8; 48]; // 32 data + 16 tag

        let sk = EncryptedPayload::new_aead(iv, encrypted_with_tag);

        assert_eq!(sk.iv_len(), 8);
        assert_eq!(sk.encrypted_len(), 48);
        assert_eq!(sk.icv_len(), 0);
        // Total: header (4) + IV (8) + encrypted+tag (48) = 60
        assert_eq!(sk.total_length(), 60);
    }

    #[test]
    fn test_encrypted_payload_roundtrip_non_aead() {
        let original = EncryptedPayload::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], // 16-byte IV for AES-CBC
            vec![0xAA; 32],
            vec![0xBB; 16],
        );

        let serialized = original.to_payload_data();
        let parsed = EncryptedPayload::from_payload_data(&serialized, 16, 16).unwrap();

        assert_eq!(parsed.iv, original.iv);
        assert_eq!(parsed.encrypted_data, original.encrypted_data);
        assert_eq!(parsed.icv, original.icv);
    }

    #[test]
    fn test_encrypted_payload_roundtrip_aead() {
        let original = EncryptedPayload::new_aead(
            vec![1, 2, 3, 4, 5, 6, 7, 8], // 8-byte IV for AES-GCM
            vec![0xCC; 48],               // Data + tag
        );

        let serialized = original.to_payload_data();
        let parsed = EncryptedPayload::from_payload_data(&serialized, 8, 0).unwrap();

        assert_eq!(parsed.iv, original.iv);
        assert_eq!(parsed.encrypted_data, original.encrypted_data);
        assert!(parsed.icv.is_empty());
        assert!(parsed.is_aead());
    }

    #[test]
    fn test_encrypted_payload_parse_too_short() {
        // Only 10 bytes, need at least IV(8) + 1 byte data + ICV(16) = 25
        let data = vec![0u8; 10];
        let result = EncryptedPayload::from_payload_data(&data, 8, 16);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_payload_chacha20_iv() {
        // ChaCha20-Poly1305 uses 12-byte IV
        let iv = vec![0u8; 12];
        let encrypted_with_tag = vec![0xDD; 64]; // Data + 16-byte tag

        let sk = EncryptedPayload::new_aead(iv.clone(), encrypted_with_tag.clone());

        assert_eq!(sk.iv_len(), 12);
        assert_eq!(sk.encrypted_len(), 64);
        assert!(sk.is_aead());
    }

    #[test]
    fn test_encrypted_payload_serialization_format() {
        let iv = vec![1, 2, 3, 4];
        let encrypted = vec![10, 11, 12];
        let icv = vec![20, 21];

        let sk = EncryptedPayload::new(iv, encrypted, icv);
        let serialized = sk.to_payload_data();

        // Format: IV | encrypted_data | ICV
        assert_eq!(serialized, vec![1, 2, 3, 4, 10, 11, 12, 20, 21]);
    }

    #[test]
    fn test_encrypted_payload_empty_encrypted_data() {
        // Minimum case: IV + at least 1 byte encrypted
        let iv = vec![0u8; 8];
        let encrypted = vec![0xEE]; // Just 1 byte
        let icv = Vec::new();

        let sk = EncryptedPayload::new(iv, encrypted, icv);

        assert_eq!(sk.encrypted_len(), 1);
        assert_eq!(sk.total_length(), 13); // Header(4) + IV(8) + data(1) = 13
    }

    #[test]
    fn test_nat_detection_source_ip_new() {
        let hash = [0x01; 20];
        let payload = NatDetectionSourceIpPayload::new(hash);

        assert_eq!(payload.hash, hash);
        assert_eq!(payload.payload_length(), 24); // Header(4) + Hash(20) = 24
    }

    #[test]
    fn test_nat_detection_source_ip_from_bytes() {
        let data = [0xAA; 20];
        let payload = NatDetectionSourceIpPayload::from_bytes(&data).unwrap();

        assert_eq!(payload.hash, data);
    }

    #[test]
    fn test_nat_detection_source_ip_from_bytes_invalid() {
        let data = [0xAA; 19]; // Wrong size
        let result = NatDetectionSourceIpPayload::from_bytes(&data);

        assert!(result.is_err());
    }

    #[test]
    fn test_nat_detection_source_ip_to_bytes() {
        let hash = [0xBB; 20];
        let payload = NatDetectionSourceIpPayload::new(hash);

        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes, hash.to_vec());
    }

    #[test]
    fn test_nat_detection_destination_ip_new() {
        let hash = [0x02; 20];
        let payload = NatDetectionDestinationIpPayload::new(hash);

        assert_eq!(payload.hash, hash);
        assert_eq!(payload.payload_length(), 24); // Header(4) + Hash(20) = 24
    }

    #[test]
    fn test_nat_detection_destination_ip_from_bytes() {
        let data = [0xCC; 20];
        let payload = NatDetectionDestinationIpPayload::from_bytes(&data).unwrap();

        assert_eq!(payload.hash, data);
    }

    #[test]
    fn test_nat_detection_destination_ip_from_bytes_invalid() {
        let data = [0xCC; 21]; // Wrong size
        let result = NatDetectionDestinationIpPayload::from_bytes(&data);

        assert!(result.is_err());
    }

    #[test]
    fn test_nat_detection_destination_ip_to_bytes() {
        let hash = [0xDD; 20];
        let payload = NatDetectionDestinationIpPayload::new(hash);

        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes, hash.to_vec());
    }
}
