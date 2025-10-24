//! IKEv2 protocol constants from RFC 7296

/// IKE version 2 (major version = 2, minor version = 0)
pub const IKE_VERSION: u8 = 0x20;

/// Maximum IKE message size (64KB - 1)
pub const MAX_IKE_MESSAGE_SIZE: u32 = 65535;

/// IKE header size (28 bytes)
pub const IKE_HEADER_SIZE: usize = 28;

/// Exchange Types (RFC 7296 Section 3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExchangeType {
    /// IKE_SA_INIT exchange (34)
    IkeSaInit = 34,
    /// IKE_AUTH exchange (35)
    IkeAuth = 35,
    /// CREATE_CHILD_SA exchange (36)
    CreateChildSa = 36,
    /// INFORMATIONAL exchange (37)
    Informational = 37,
}

impl ExchangeType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            34 => Some(ExchangeType::IkeSaInit),
            35 => Some(ExchangeType::IkeAuth),
            36 => Some(ExchangeType::CreateChildSa),
            37 => Some(ExchangeType::Informational),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// IKE message flags (RFC 7296 Section 3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeFlags(u8);

impl IkeFlags {
    /// Response flag (bit 5)
    pub const RESPONSE: u8 = 0x20;
    /// Version flag (bit 4)
    pub const VERSION: u8 = 0x10;
    /// Initiator flag (bit 3)
    pub const INITIATOR: u8 = 0x08;

    /// Create new flags
    pub fn new(value: u8) -> Self {
        IkeFlags(value & 0x38) // Mask to only keep bits 3-5
    }

    /// Create flags for request
    pub fn request(is_initiator: bool) -> Self {
        if is_initiator {
            IkeFlags(Self::INITIATOR)
        } else {
            IkeFlags(0)
        }
    }

    /// Create flags for response
    pub fn response(is_initiator: bool) -> Self {
        let mut flags = Self::RESPONSE;
        if is_initiator {
            flags |= Self::INITIATOR;
        }
        IkeFlags(flags)
    }

    /// Check if this is a response
    pub fn is_response(self) -> bool {
        (self.0 & Self::RESPONSE) != 0
    }

    /// Check if this is from initiator
    pub fn is_initiator(self) -> bool {
        (self.0 & Self::INITIATOR) != 0
    }

    /// Get raw value
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Payload Types (RFC 7296 Section 3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PayloadType {
    /// No next payload (0)
    None = 0,
    /// Security Association (33)
    SA = 33,
    /// Key Exchange (34)
    KE = 34,
    /// Identification - Initiator (35)
    IDi = 35,
    /// Identification - Responder (36)
    IDr = 36,
    /// Certificate (37)
    CERT = 37,
    /// Certificate Request (38)
    CERTREQ = 38,
    /// Authentication (39)
    AUTH = 39,
    /// Nonce (40)
    Nonce = 40,
    /// Notify (41)
    N = 41,
    /// Delete (42)
    D = 42,
    /// Vendor ID (43)
    V = 43,
    /// Traffic Selector - Initiator (44)
    TSi = 44,
    /// Traffic Selector - Responder (45)
    TSr = 45,
    /// Encrypted and Authenticated (46)
    SK = 46,
    /// Configuration (47)
    CP = 47,
    /// Extensible Authentication (48)
    EAP = 48,
}

impl PayloadType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PayloadType::None),
            33 => Some(PayloadType::SA),
            34 => Some(PayloadType::KE),
            35 => Some(PayloadType::IDi),
            36 => Some(PayloadType::IDr),
            37 => Some(PayloadType::CERT),
            38 => Some(PayloadType::CERTREQ),
            39 => Some(PayloadType::AUTH),
            40 => Some(PayloadType::Nonce),
            41 => Some(PayloadType::N),
            42 => Some(PayloadType::D),
            43 => Some(PayloadType::V),
            44 => Some(PayloadType::TSi),
            45 => Some(PayloadType::TSr),
            46 => Some(PayloadType::SK),
            47 => Some(PayloadType::CP),
            48 => Some(PayloadType::EAP),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exchange_type_conversion() {
        assert_eq!(ExchangeType::from_u8(34), Some(ExchangeType::IkeSaInit));
        assert_eq!(ExchangeType::from_u8(35), Some(ExchangeType::IkeAuth));
        assert_eq!(ExchangeType::from_u8(36), Some(ExchangeType::CreateChildSa));
        assert_eq!(ExchangeType::from_u8(37), Some(ExchangeType::Informational));
        assert_eq!(ExchangeType::from_u8(99), None);

        assert_eq!(ExchangeType::IkeSaInit.to_u8(), 34);
        assert_eq!(ExchangeType::IkeAuth.to_u8(), 35);
    }

    #[test]
    fn test_ike_flags() {
        let flags = IkeFlags::request(true);
        assert!(!flags.is_response());
        assert!(flags.is_initiator());

        let flags = IkeFlags::response(false);
        assert!(flags.is_response());
        assert!(!flags.is_initiator());

        let flags = IkeFlags::response(true);
        assert!(flags.is_response());
        assert!(flags.is_initiator());
        assert_eq!(flags.value(), IkeFlags::RESPONSE | IkeFlags::INITIATOR);
    }

    #[test]
    fn test_payload_type_conversion() {
        assert_eq!(PayloadType::from_u8(0), Some(PayloadType::None));
        assert_eq!(PayloadType::from_u8(33), Some(PayloadType::SA));
        assert_eq!(PayloadType::from_u8(40), Some(PayloadType::Nonce));
        assert_eq!(PayloadType::from_u8(255), None);

        assert_eq!(PayloadType::SA.to_u8(), 33);
        assert_eq!(PayloadType::Nonce.to_u8(), 40);
    }

    #[test]
    fn test_constants() {
        assert_eq!(IKE_VERSION, 0x20);
        assert_eq!(MAX_IKE_MESSAGE_SIZE, 65535);
        assert_eq!(IKE_HEADER_SIZE, 28);
    }
}
