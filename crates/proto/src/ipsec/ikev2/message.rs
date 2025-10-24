//! IKEv2 message structures and parsing
//!
//! Implements the IKE message format defined in RFC 7296 Section 3.1

use super::constants::*;
use super::payload::*;
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

/// Complete IKE message with header and payloads
///
/// This structure represents a full IKE message as it appears on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct IkeMessage {
    /// IKE message header
    pub header: IkeHeader,

    /// Message payloads (ordered list)
    pub payloads: Vec<IkePayload>,
}

impl IkeMessage {
    /// Create a new IKE message
    pub fn new(header: IkeHeader, payloads: Vec<IkePayload>) -> Self {
        IkeMessage { header, payloads }
    }

    /// Parse complete IKE message from bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing complete IKE message
    ///
    /// # Returns
    ///
    /// Returns the parsed message with header and all payloads
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Header parsing fails
    /// - Payload parsing fails
    /// - Message length doesn't match actual data
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Parse header
        let header = IkeHeader::from_bytes(data)?;

        // Validate we have complete message
        if data.len() < header.length as usize {
            return Err(Error::BufferTooShort {
                required: header.length as usize,
                available: data.len(),
            });
        }

        // Parse payloads
        let mut payloads = Vec::new();
        let mut offset = IKE_HEADER_SIZE;
        let mut next_payload = header.next_payload;

        // Parse payload chain
        while next_payload != PayloadType::None && offset < header.length as usize {
            let remaining = &data[offset..header.length as usize];

            // Parse payload header to get length
            let payload_header = PayloadHeader::from_bytes(remaining)?;

            // Validate payload fits in message
            if offset + payload_header.length as usize > header.length as usize {
                return Err(Error::InvalidLength {
                    expected: header.length as usize - offset,
                    actual: payload_header.length as usize,
                });
            }

            // Extract complete payload data (header + data)
            let payload_bytes = &remaining[..payload_header.length as usize];

            // Parse specific payload type based on current next_payload
            let payload = Self::parse_payload(next_payload, payload_bytes)?;

            payloads.push(payload);

            // Move to next payload
            next_payload = payload_header.next_payload;
            offset += payload_header.length as usize;
        }

        Ok(IkeMessage { header, payloads })
    }

    /// Parse a specific payload type from bytes
    pub(crate) fn parse_payload(payload_type: PayloadType, data: &[u8]) -> Result<IkePayload> {
        // Parse header first
        let header = PayloadHeader::from_bytes(data)?;
        let payload_data = &data[PayloadHeader::SIZE..header.length as usize];

        // Parse based on payload type
        match payload_type {
            PayloadType::SA => {
                let sa = SaPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::SA(sa))
            }
            PayloadType::KE => {
                let ke = KePayload::from_payload_data(payload_data)?;
                Ok(IkePayload::KE(ke))
            }
            PayloadType::Nonce => {
                let nonce = NoncePayload::from_payload_data(payload_data)?;
                Ok(IkePayload::Nonce(nonce))
            }
            PayloadType::IDi => {
                let id = IdPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::IDi(id))
            }
            PayloadType::IDr => {
                let id = IdPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::IDr(id))
            }
            PayloadType::AUTH => {
                let auth = AuthPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::AUTH(auth))
            }
            PayloadType::TSi => {
                let ts = TrafficSelectorsPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::TSi(ts))
            }
            PayloadType::TSr => {
                let ts = TrafficSelectorsPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::TSr(ts))
            }
            PayloadType::N => {
                let notify = NotifyPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::N(notify))
            }
            PayloadType::D => {
                let delete = DeletePayload::from_payload_data(payload_data)?;
                Ok(IkePayload::D(delete))
            }
            PayloadType::V => {
                let vendor = VendorIdPayload::from_payload_data(payload_data)?;
                Ok(IkePayload::V(vendor))
            }
            _ => {
                // Unknown payload type - store as raw data
                Ok(IkePayload::Unknown {
                    payload_type,
                    data: payload_data.to_vec(),
                })
            }
        }
    }

    /// Serialize complete IKE message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Calculate total length
        let payload_length: usize = self
            .payloads
            .iter()
            .map(|p| match p {
                IkePayload::SA(sa) => sa.total_length() as usize,
                IkePayload::KE(ke) => ke.total_length() as usize,
                IkePayload::Nonce(nonce) => nonce.total_length() as usize,
                IkePayload::IDi(id) => id.total_length() as usize,
                IkePayload::IDr(id) => id.total_length() as usize,
                IkePayload::AUTH(auth) => auth.total_length() as usize,
                IkePayload::N(notify) => notify.total_length() as usize,
                IkePayload::D(delete) => delete.total_length() as usize,
                IkePayload::V(vendor_id) => vendor_id.total_length() as usize,
                IkePayload::TSi(ts) => ts.total_length() as usize,
                IkePayload::TSr(ts) => ts.total_length() as usize,
                IkePayload::SK(sk) => sk.total_length() as usize,
                IkePayload::Unknown { data, .. } => PayloadHeader::SIZE + data.len(),
            })
            .sum();

        let total_length = IKE_HEADER_SIZE + payload_length;

        // Update header with correct length and next_payload
        let mut header = self.header.clone();
        header.length = total_length as u32;
        header.next_payload = if self.payloads.is_empty() {
            PayloadType::None
        } else {
            self.payloads[0].payload_type()
        };

        // Serialize header
        bytes.extend_from_slice(&header.to_bytes());

        // Serialize payloads
        for (i, payload) in self.payloads.iter().enumerate() {
            let next_payload = if i + 1 < self.payloads.len() {
                self.payloads[i + 1].payload_type()
            } else {
                PayloadType::None
            };

            // Serialize payload with header
            Self::serialize_payload(payload, next_payload, &mut bytes);
        }

        bytes
    }

    /// Serialize a single payload with its header
    fn serialize_payload(payload: &IkePayload, next_payload: PayloadType, output: &mut Vec<u8>) {
        let (_payload_type, payload_data, total_length) = match payload {
            IkePayload::SA(sa) => (PayloadType::SA, sa.to_payload_data(), sa.total_length()),
            IkePayload::KE(ke) => (PayloadType::KE, ke.to_payload_data(), ke.total_length()),
            IkePayload::Nonce(nonce) => (
                PayloadType::Nonce,
                nonce.to_payload_data(),
                nonce.total_length(),
            ),
            IkePayload::IDi(id) => (PayloadType::IDi, id.to_payload_data(), id.total_length()),
            IkePayload::IDr(id) => (PayloadType::IDr, id.to_payload_data(), id.total_length()),
            IkePayload::AUTH(auth) => (
                PayloadType::AUTH,
                auth.to_payload_data(),
                auth.total_length(),
            ),
            IkePayload::N(notify) => (
                PayloadType::N,
                notify.to_payload_data(),
                notify.total_length(),
            ),
            IkePayload::D(delete) => (
                PayloadType::D,
                delete.to_payload_data(),
                delete.total_length(),
            ),
            IkePayload::V(vendor_id) => (
                PayloadType::V,
                vendor_id.to_payload_data(),
                vendor_id.total_length(),
            ),
            IkePayload::TSi(ts) => (PayloadType::TSi, ts.to_payload_data(), ts.total_length()),
            IkePayload::TSr(ts) => (PayloadType::TSr, ts.to_payload_data(), ts.total_length()),
            IkePayload::SK(sk) => (PayloadType::SK, sk.to_payload_data(), sk.total_length()),
            IkePayload::Unknown { payload_type, data } => {
                (*payload_type, data.clone(), (PayloadHeader::SIZE + data.len()) as u16)
            }
        };

        // Write payload header
        let header = PayloadHeader::new(next_payload, false, total_length);
        output.extend_from_slice(&header.to_bytes());

        // Write payload data
        output.extend_from_slice(&payload_data);
    }

    /// Validate complete message
    pub fn validate(&self) -> Result<()> {
        // Validate header
        self.header.validate()?;

        // Validate payloads exist if header indicates so
        if self.header.next_payload != PayloadType::None && self.payloads.is_empty() {
            return Err(Error::InvalidMessage(
                "Header indicates payloads but none found".to_string(),
            ));
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

    // IkeMessage integration tests

    #[test]
    fn test_message_empty() {
        let header = IkeHeader::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0; 8],
            PayloadType::None,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            0,
            28, // Header only
        );

        let message = IkeMessage::new(header, vec![]);

        // Serialize and parse back
        let bytes = message.to_bytes();
        assert_eq!(bytes.len(), 28);

        let parsed = IkeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payloads.len(), 0);
        assert_eq!(parsed.header.next_payload, PayloadType::None);
    }

    #[test]
    fn test_message_with_nonce() {
        let header = IkeHeader::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0; 8],
            PayloadType::Nonce,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            0,
            100,
        );

        let nonce = NoncePayload::new(vec![0xAAu8; 32]).unwrap();
        let payloads = vec![IkePayload::Nonce(nonce.clone())];

        let message = IkeMessage::new(header, payloads);

        // Serialize
        let bytes = message.to_bytes();

        // Parse back
        let parsed = IkeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payloads.len(), 1);

        match &parsed.payloads[0] {
            IkePayload::Nonce(parsed_nonce) => {
                assert_eq!(parsed_nonce, &nonce);
            }
            _ => panic!("Expected Nonce payload"),
        }
    }

    #[test]
    fn test_message_with_multiple_payloads() {
        let header = IkeHeader::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0; 8],
            PayloadType::SA,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            0,
            200,
        );

        let sa = SaPayload::new(vec![]); // Empty proposals for testing
        let ke = KePayload::new(KePayload::DH_GROUP_31, vec![0xBBu8; 32]);
        let nonce = NoncePayload::new(vec![0xCCu8; 16]).unwrap();

        let payloads = vec![
            IkePayload::SA(sa.clone()),
            IkePayload::KE(ke.clone()),
            IkePayload::Nonce(nonce.clone()),
        ];

        let message = IkeMessage::new(header, payloads);

        // Serialize
        let bytes = message.to_bytes();

        // Parse back
        let parsed = IkeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.payloads.len(), 3);

        // Verify payload chain
        match &parsed.payloads[0] {
            IkePayload::SA(parsed_sa) => assert_eq!(parsed_sa, &sa),
            _ => panic!("Expected SA payload"),
        }

        match &parsed.payloads[1] {
            IkePayload::KE(parsed_ke) => assert_eq!(parsed_ke, &ke),
            _ => panic!("Expected KE payload"),
        }

        match &parsed.payloads[2] {
            IkePayload::Nonce(parsed_nonce) => assert_eq!(parsed_nonce, &nonce),
            _ => panic!("Expected Nonce payload"),
        }
    }

    #[test]
    fn test_message_roundtrip() {
        let header = IkeHeader::new(
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
            PayloadType::KE,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            42,
            100,
        );

        let ke = KePayload::new(KePayload::DH_GROUP_14, vec![0xFFu8; 256]);
        let payloads = vec![IkePayload::KE(ke)];

        let original = IkeMessage::new(header, payloads);

        // Roundtrip
        let bytes = original.to_bytes();
        let parsed = IkeMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.header.initiator_spi, original.header.initiator_spi);
        assert_eq!(parsed.header.responder_spi, original.header.responder_spi);
        assert_eq!(parsed.header.exchange_type, original.header.exchange_type);
        assert_eq!(parsed.payloads.len(), original.payloads.len());
    }

    #[test]
    fn test_message_buffer_too_short() {
        let data = vec![0u8; 20]; // Only 20 bytes, need at least 28
        let result = IkeMessage::from_bytes(&data);
        assert!(matches!(result, Err(Error::BufferTooShort { .. })));
    }

    #[test]
    fn test_message_validate() {
        let header = IkeHeader::new(
            [0; 8],
            [0; 8],
            PayloadType::Nonce,
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            0,
            100,
        );

        let nonce = NoncePayload::new(vec![0xAAu8; 32]).unwrap();
        let message = IkeMessage::new(header, vec![IkePayload::Nonce(nonce)]);

        assert!(message.validate().is_ok());
    }

    #[test]
    fn test_message_validate_empty_payloads_mismatch() {
        let header = IkeHeader::new(
            [0; 8],
            [0; 8],
            PayloadType::Nonce, // Header indicates Nonce payload
            ExchangeType::IkeSaInit,
            IkeFlags::request(true),
            0,
            28,
        );

        // But no payloads provided
        let message = IkeMessage::new(header, vec![]);

        let result = message.validate();
        assert!(matches!(result, Err(Error::InvalidMessage(_))));
    }
}
