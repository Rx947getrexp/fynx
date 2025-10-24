//! IKEv2 message structures and parsing
//!
//! Implements the IKE message format defined in RFC 7296 Section 3.1

use super::constants::*;
use crate::ipsec::{Error, Result};

/// IKE message header (28 bytes)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       IKE SA Initiator's SPI                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       IKE SA Responder's SPI                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Message ID                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Length                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkeHeader {
    /// Initiator's Security Parameter Index (8 bytes)
    pub initiator_spi: [u8; 8],

    /// Responder's Security Parameter Index (8 bytes, zero for IKE_SA_INIT request)
    pub responder_spi: [u8; 8],

    /// Next payload type
    pub next_payload: PayloadType,

    /// Protocol version (must be 0x20 for IKEv2)
    pub version: u8,

    /// Exchange type
    pub exchange_type: ExchangeType,

    /// Message flags
    pub flags: IkeFlags,

    /// Message ID (used for replay protection and matching)
    pub message_id: u32,

    /// Total message length in bytes (including header)
    pub length: u32,
}

impl IkeHeader {
    /// Create a new IKE header
    pub fn new(
        initiator_spi: [u8; 8],
        responder_spi: [u8; 8],
        next_payload: PayloadType,
        exchange_type: ExchangeType,
        flags: IkeFlags,
        message_id: u32,
        length: u32,
    ) -> Self {
        IkeHeader {
            initiator_spi,
            responder_spi,
            next_payload,
            version: IKE_VERSION,
            exchange_type,
            flags,
            message_id,
            length,
        }
    }

    /// Parse IKE header from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing at least 28 bytes
    ///
    /// # Returns
    ///
    /// Returns the parsed header on success
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Buffer is too short (< 28 bytes)
    /// - Protocol version is not 0x20
    /// - Exchange type is unknown
    /// - Message length is invalid
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < IKE_HEADER_SIZE {
            return Err(Error::BufferTooShort {
                required: IKE_HEADER_SIZE,
                available: data.len(),
            });
        }

        // Parse SPIs (16 bytes total)
        let mut initiator_spi = [0u8; 8];
        let mut responder_spi = [0u8; 8];
        initiator_spi.copy_from_slice(&data[0..8]);
        responder_spi.copy_from_slice(&data[8..16]);

        // Parse next payload type
        let next_payload = PayloadType::from_u8(data[16])
            .ok_or_else(|| Error::InvalidPayload(format!("Unknown payload type: {}", data[16])))?;

        // Parse version
        let version = data[17];
        if version != IKE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        // Parse exchange type
        let exchange_type = ExchangeType::from_u8(data[18]).ok_or_else(|| {
            Error::UnsupportedExchangeType(data[18])
        })?;

        // Parse flags
        let flags = IkeFlags::new(data[19]);

        // Parse message ID (4 bytes, big-endian)
        let message_id = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

        // Parse length (4 bytes, big-endian)
        let length = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        // Validate length
        if length > MAX_IKE_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge(length));
        }

        if length < IKE_HEADER_SIZE as u32 {
            return Err(Error::InvalidLength {
                expected: IKE_HEADER_SIZE,
                actual: length as usize,
            });
        }

        Ok(IkeHeader {
            initiator_spi,
            responder_spi,
            next_payload,
            version,
            exchange_type,
            flags,
            message_id,
            length,
        })
    }

    /// Serialize IKE header to bytes
    ///
    /// # Returns
    ///
    /// Returns a 28-byte array containing the serialized header
    pub fn to_bytes(&self) -> [u8; IKE_HEADER_SIZE] {
        let mut bytes = [0u8; IKE_HEADER_SIZE];

        // Write SPIs
        bytes[0..8].copy_from_slice(&self.initiator_spi);
        bytes[8..16].copy_from_slice(&self.responder_spi);

        // Write next payload
        bytes[16] = self.next_payload.to_u8();

        // Write version
        bytes[17] = self.version;

        // Write exchange type
        bytes[18] = self.exchange_type.to_u8();

        // Write flags
        bytes[19] = self.flags.value();

        // Write message ID (big-endian)
        bytes[20..24].copy_from_slice(&self.message_id.to_be_bytes());

        // Write length (big-endian)
        bytes[24..28].copy_from_slice(&self.length.to_be_bytes());

        bytes
    }

    /// Validate header fields
    pub fn validate(&self) -> Result<()> {
        // Check version
        if self.version != IKE_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }

        // Check length
        if self.length > MAX_IKE_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge(self.length));
        }

        if self.length < IKE_HEADER_SIZE as u32 {
            return Err(Error::InvalidLength {
                expected: IKE_HEADER_SIZE,
                actual: self.length as usize,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = IkeHeader::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [9, 10, 11, 12, 13, 14, 15, 16],
            PayloadType::SA,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            42,
            100,
        );

        let bytes = header.to_bytes();
        let parsed = IkeHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header, parsed);
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; 28];

        // Initiator SPI
        data[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        // Responder SPI
        data[8..16].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);

        // Next payload (SA = 33)
        data[16] = 33;

        // Version (0x20)
        data[17] = 0x20;

        // Exchange type (IKE_SA_INIT = 34)
        data[18] = 34;

        // Flags (initiator = 0x08)
        data[19] = 0x08;

        // Message ID (42)
        data[20..24].copy_from_slice(&42u32.to_be_bytes());

        // Length (100)
        data[24..28].copy_from_slice(&100u32.to_be_bytes());

        let header = IkeHeader::from_bytes(&data).unwrap();

        assert_eq!(header.initiator_spi, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(header.responder_spi, [9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(header.next_payload, PayloadType::SA);
        assert_eq!(header.version, 0x20);
        assert_eq!(header.exchange_type, ExchangeType::IkeSaInit);
        assert!(header.flags.is_initiator());
        assert_eq!(header.message_id, 42);
        assert_eq!(header.length, 100);
    }

    #[test]
    fn test_buffer_too_short() {
        let data = vec![0u8; 27]; // Only 27 bytes
        let result = IkeHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::BufferTooShort { .. })));
    }

    #[test]
    fn test_invalid_version() {
        let mut data = vec![0u8; 28];
        data[17] = 0x10; // Wrong version

        let result = IkeHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::UnsupportedVersion(0x10))));
    }

    #[test]
    fn test_unknown_exchange_type() {
        let mut data = vec![0u8; 28];
        data[17] = 0x20; // Correct version
        data[18] = 99; // Unknown exchange type

        let result = IkeHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::UnsupportedExchangeType(99))));
    }

    #[test]
    fn test_message_too_large() {
        let mut data = vec![0u8; 28];
        data[17] = 0x20; // Correct version
        data[18] = 34; // IKE_SA_INIT
        data[24..28].copy_from_slice(&70000u32.to_be_bytes()); // Too large

        let result = IkeHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::MessageTooLarge(70000))));
    }

    #[test]
    fn test_length_too_small() {
        let mut data = vec![0u8; 28];
        data[17] = 0x20; // Correct version
        data[18] = 34; // IKE_SA_INIT
        data[24..28].copy_from_slice(&20u32.to_be_bytes()); // Too small

        let result = IkeHeader::from_bytes(&data);
        assert!(matches!(result, Err(Error::InvalidLength { .. })));
    }

    #[test]
    fn test_validate() {
        let mut header = IkeHeader::new(
            [0; 8],
            [0; 8],
            PayloadType::SA,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            0,
            100,
        );

        assert!(header.validate().is_ok());

        // Test invalid version
        header.version = 0x10;
        assert!(matches!(
            header.validate(),
            Err(Error::UnsupportedVersion(0x10))
        ));
    }
}
