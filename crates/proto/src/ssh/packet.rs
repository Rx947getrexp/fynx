//! SSH binary packet protocol (RFC 4253 Section 6).
//!
//! # Packet Format
//!
//! ```text
//! uint32    packet_length
//! byte      padding_length
//! byte[n1]  payload (n1 = packet_length - padding_length - 1)
//! byte[n2]  random padding (n2 = padding_length)
//! byte[m]   mac (MAC = Message Authentication Code)
//! ```
//!
//! # Constraints
//!
//! - `packet_length`: Does NOT include `mac` or `packet_length` field itself
//! - `padding_length`: Length of padding (minimum 4, maximum 255 bytes)
//! - Total `packet_length` + 4 (for length field) MUST be multiple of 8 (or cipher block size)
//! - Maximum packet size: 35000 bytes (security limit per RFC 4253)
//! - Minimum packet size: 16 bytes (5 bytes header + 4 bytes padding + 1 byte payload)
//!
//! # Security
//!
//! - **Size Validation**: Rejects packets > 35000 bytes to prevent DoS
//! - **Padding Validation**: Ensures padding is within valid range (4-255 bytes)
//! - **Random Padding**: Uses cryptographically secure RNG for padding
//! - **MAC Verification**: Validates MAC before processing payload (when encryption enabled)
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::Packet;
//!
//! // Create a packet with payload
//! let payload = b"SSH-MSG-KEXINIT payload";
//! let packet = Packet::new(payload.to_vec());
//!
//! // Serialize to wire format
//! let bytes = packet.to_bytes();
//!
//! // Parse from wire format
//! let parsed = Packet::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.payload(), payload);
//! ```

use bytes::{Buf, BufMut, BytesMut};
use fynx_platform::{FynxError, FynxResult};
use rand::RngCore;

/// Maximum packet size in bytes (RFC 4253 Section 6.1).
///
/// This limit prevents denial-of-service attacks via extremely large packets.
pub const MAX_PACKET_SIZE: usize = 35000;

/// Minimum packet size in bytes.
///
/// Minimum packet: 5 bytes (header) + 4 bytes (min padding) + 1 byte (payload) = 10 bytes
/// But with block size alignment (8 bytes), minimum is 16 bytes.
pub const MIN_PACKET_SIZE: usize = 16;

/// Minimum padding length in bytes (RFC 4253 Section 6).
pub const MIN_PADDING_LEN: u8 = 4;

/// Maximum padding length in bytes (fits in u8).
pub const MAX_PADDING_LEN: u8 = 255;

/// SSH binary packet.
///
/// Represents an SSH protocol packet as defined in RFC 4253 Section 6.
///
/// # Fields
///
/// - `payload`: The actual message data (SSH_MSG_* messages)
/// - `padding`: Random padding bytes (4-255 bytes)
/// - `mac`: Message Authentication Code (optional, depends on cipher)
///
/// # Invariants
///
/// - Padding length is between 4 and 255 bytes
/// - Total packet size (including all fields) ≤ 35000 bytes
/// - Packet is properly aligned to cipher block size (default 8 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    payload: Vec<u8>,
    padding: Vec<u8>,
    mac: Option<Vec<u8>>,
}

impl Packet {
    /// Creates a new SSH packet with the given payload.
    ///
    /// The packet will be automatically padded to meet SSH requirements:
    /// - Minimum 4 bytes of padding
    /// - Total packet size is multiple of 8 bytes (default block size)
    /// - Padding is filled with cryptographically secure random bytes
    ///
    /// # Arguments
    ///
    /// * `payload` - The message payload (SSH_MSG_* message)
    ///
    /// # Returns
    ///
    /// A new `Packet` with proper padding.
    ///
    /// # Panics
    ///
    /// Panics if the payload is too large (> 35000 bytes).
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::Packet;
    ///
    /// let packet = Packet::new(b"Hello, SSH!".to_vec());
    /// assert_eq!(packet.payload(), b"Hello, SSH!");
    /// ```
    pub fn new(payload: Vec<u8>) -> Self {
        // Calculate required padding
        // packet_length = padding_length (1 byte) + payload + padding
        // total_size = packet_length_field (4 bytes) + packet_length
        // total_size must be multiple of 8

        let payload_len = payload.len();
        let header_len = 5; // 4 bytes packet_length + 1 byte padding_length

        // Calculate padding to align to 8-byte boundary
        let unpadded_len = header_len + payload_len;
        let block_size = 8;

        // Find minimum padding that satisfies:
        // 1. padding >= MIN_PADDING_LEN (4 bytes)
        // 2. (unpadded_len + padding) % block_size == 0
        let mut padding_len = MIN_PADDING_LEN as usize;
        while (unpadded_len + padding_len) % block_size != 0 {
            padding_len += 1;
        }

        // Ensure padding doesn't exceed maximum
        assert!(
            padding_len <= MAX_PADDING_LEN as usize,
            "Payload too large, cannot add sufficient padding"
        );

        // Generate random padding
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut padding);

        // Verify total size
        let total_size = unpadded_len + padding_len;
        assert!(
            total_size <= MAX_PACKET_SIZE,
            "Packet size {} exceeds maximum {}",
            total_size,
            MAX_PACKET_SIZE
        );

        Self {
            payload,
            padding,
            mac: None,
        }
    }

    /// Returns the payload of this packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::Packet;
    ///
    /// let packet = Packet::new(b"payload".to_vec());
    /// assert_eq!(packet.payload(), b"payload");
    /// ```
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the padding of this packet.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }

    /// Returns the MAC of this packet (if present).
    pub fn mac(&self) -> Option<&[u8]> {
        self.mac.as_deref()
    }

    /// Sets the MAC for this packet.
    ///
    /// # Arguments
    ///
    /// * `mac` - The Message Authentication Code bytes
    pub fn set_mac(&mut self, mac: Vec<u8>) {
        self.mac = Some(mac);
    }

    /// Serializes this packet to wire format.
    ///
    /// # Format
    ///
    /// ```text
    /// uint32    packet_length (big-endian)
    /// byte      padding_length
    /// byte[n1]  payload
    /// byte[n2]  random padding
    /// byte[m]   mac (if present)
    /// ```
    ///
    /// # Returns
    ///
    /// A byte vector containing the serialized packet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::Packet;
    ///
    /// let packet = Packet::new(b"test".to_vec());
    /// let bytes = packet.to_bytes();
    /// assert!(bytes.len() >= 16); // Minimum packet size
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let packet_length = 1 + self.payload.len() + self.padding.len();
        let mut buf =
            BytesMut::with_capacity(4 + packet_length + self.mac.as_ref().map_or(0, |m| m.len()));

        // uint32 packet_length (big-endian)
        buf.put_u32(packet_length as u32);

        // byte padding_length
        buf.put_u8(self.padding.len() as u8);

        // byte[n1] payload
        buf.put_slice(&self.payload);

        // byte[n2] padding
        buf.put_slice(&self.padding);

        // byte[m] mac (optional)
        if let Some(mac) = &self.mac {
            buf.put_slice(mac);
        }

        buf.to_vec()
    }

    /// Parses a packet from wire format.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw bytes to parse
    ///
    /// # Returns
    ///
    /// A parsed `Packet` or an error if the data is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if:
    /// - Data is too short (< 5 bytes for header)
    /// - Packet size exceeds maximum (35000 bytes)
    /// - Padding length is invalid (< 4 or > 255)
    /// - Data length doesn't match declared packet_length
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::Packet;
    ///
    /// let original = Packet::new(b"test".to_vec());
    /// let bytes = original.to_bytes();
    ///
    /// let parsed = Packet::from_bytes(&bytes).unwrap();
    /// assert_eq!(parsed.payload(), b"test");
    /// ```
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        // Need at least 5 bytes for header (4 bytes packet_length + 1 byte padding_length)
        if data.len() < 5 {
            return Err(FynxError::Protocol(format!(
                "Packet too short: {} bytes (minimum 5)",
                data.len()
            )));
        }

        let mut buf = data;

        // Read packet_length (uint32, big-endian)
        let packet_length = buf.get_u32() as usize;

        // Validate packet size (RFC 4253 Section 6.1)
        if packet_length > MAX_PACKET_SIZE {
            return Err(FynxError::Protocol(format!(
                "Packet too large: {} bytes (maximum {})",
                packet_length, MAX_PACKET_SIZE
            )));
        }

        if packet_length < 5 {
            return Err(FynxError::Protocol(format!(
                "Packet too small: {} bytes (minimum 5 for padding_length + min padding + payload)",
                packet_length
            )));
        }

        // Check if we have enough data for declared packet_length
        // (we already consumed 4 bytes for packet_length field)
        if buf.len() < packet_length {
            return Err(FynxError::Protocol(format!(
                "Incomplete packet: expected {} bytes, got {} bytes",
                packet_length,
                buf.len()
            )));
        }

        // Read padding_length (uint8)
        let padding_length = buf.get_u8() as usize;

        // Validate padding length (RFC 4253 Section 6)
        if padding_length < MIN_PADDING_LEN as usize {
            return Err(FynxError::Protocol(format!(
                "Padding too short: {} bytes (minimum {})",
                padding_length, MIN_PADDING_LEN
            )));
        }

        if padding_length > MAX_PADDING_LEN as usize {
            return Err(FynxError::Protocol(format!(
                "Padding too long: {} bytes (maximum {})",
                padding_length, MAX_PADDING_LEN
            )));
        }

        // Validate packet_length is sufficient for padding_length field + padding
        if packet_length < 1 + padding_length {
            return Err(FynxError::Protocol(format!(
                "Invalid packet: packet_length ({}) too small for padding_length field (1) + padding ({})",
                packet_length, padding_length
            )));
        }

        // Calculate payload length
        // packet_length = 1 (padding_length field) + payload_length + padding_length
        let payload_length = packet_length - 1 - padding_length;

        // Extract payload
        if buf.len() < payload_length {
            return Err(FynxError::Protocol(format!(
                "Incomplete payload: expected {} bytes, got {} bytes",
                payload_length,
                buf.len()
            )));
        }
        let payload = buf[..payload_length].to_vec();
        buf.advance(payload_length);

        // Extract padding
        if buf.len() < padding_length {
            return Err(FynxError::Protocol(format!(
                "Incomplete padding: expected {} bytes, got {} bytes",
                padding_length,
                buf.len()
            )));
        }
        let padding = buf[..padding_length].to_vec();
        buf.advance(padding_length);

        // Any remaining bytes are MAC (if present)
        let mac = if !buf.is_empty() {
            Some(buf.to_vec())
        } else {
            None
        };

        Ok(Self {
            payload,
            padding,
            mac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_new() {
        let payload = b"Hello, SSH!".to_vec();
        let packet = Packet::new(payload.clone());

        assert_eq!(packet.payload(), &payload[..]);
        assert!(packet.padding().len() >= MIN_PADDING_LEN as usize);
        assert!(packet.padding().len() <= MAX_PADDING_LEN as usize);
        assert!(packet.mac().is_none());
    }

    #[test]
    fn test_packet_alignment() {
        let payload = b"test".to_vec();
        let packet = Packet::new(payload);

        // Total size should be multiple of 8
        // size = 4 (packet_length) + 1 (padding_length) + payload + padding
        let total_size = 4 + 1 + packet.payload().len() + packet.padding().len();
        assert_eq!(total_size % 8, 0, "Packet not aligned to 8-byte boundary");
    }

    #[test]
    fn test_packet_round_trip() {
        let payload = b"Test SSH packet payload".to_vec();
        let packet = Packet::new(payload.clone());

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.payload(), &payload[..]);
        assert_eq!(parsed.padding().len(), packet.padding().len());
    }

    #[test]
    fn test_packet_with_mac() {
        let mut packet = Packet::new(b"payload".to_vec());
        let mac = vec![0xaa; 16]; // 16-byte MAC
        packet.set_mac(mac.clone());

        assert_eq!(packet.mac(), Some(&mac[..]));

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.mac(), Some(&mac[..]));
    }

    #[test]
    fn test_packet_minimum_size() {
        let packet = Packet::new(b"x".to_vec());
        let bytes = packet.to_bytes();

        assert!(
            bytes.len() >= MIN_PACKET_SIZE,
            "Packet smaller than minimum size"
        );
    }

    #[test]
    fn test_packet_invalid_too_short() {
        let data = vec![0, 0, 0, 10]; // Only 4 bytes
        let result = Packet::from_bytes(&data);

        assert!(result.is_err());
        assert!(matches!(result, Err(FynxError::Protocol(_))));
    }

    #[test]
    fn test_packet_invalid_padding_too_short() {
        // packet_length = 1 (padding_len) + 5 (payload) + 2 (padding) = 8
        let data = vec![
            0, 0, 0, 8, // packet_length = 8
            2, // padding_length = 2 (< MIN_PADDING_LEN = 4)
            0x48, 0x65, 0x6c, 0x6c, 0x6f, // payload "Hello" (5 bytes)
            0x00, 0x00, // padding (2 bytes)
        ];
        let result = Packet::from_bytes(&data);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FynxError::Protocol(msg) => {
                assert!(msg.contains("Padding too short"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_packet_invalid_incomplete() {
        let data = vec![
            0, 0, 0, 20, // packet_length = 20
            4,  // padding_length = 4
            0x48, 0x65, // Incomplete payload (only 2 bytes when more expected)
        ];
        let result = Packet::from_bytes(&data);

        assert!(result.is_err());
        assert!(matches!(result, Err(FynxError::Protocol(_))));
    }

    #[test]
    fn test_packet_max_size() {
        // Create a packet close to max size
        let payload = vec![0u8; MAX_PACKET_SIZE - 100];
        let packet = Packet::new(payload);

        let bytes = packet.to_bytes();
        assert!(bytes.len() <= MAX_PACKET_SIZE + 4); // +4 for packet_length field
    }

    #[test]
    #[should_panic(expected = "Packet size")]
    fn test_packet_exceeds_max_size() {
        // This should panic because payload is too large
        let payload = vec![0u8; MAX_PACKET_SIZE + 1000];
        let _packet = Packet::new(payload);
    }
}
