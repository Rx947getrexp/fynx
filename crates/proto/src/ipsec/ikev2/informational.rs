//! INFORMATIONAL Exchange Implementation
//!
//! Implements INFORMATIONAL exchange as defined in RFC 7296 Section 1.4.
//!
//! # Overview
//!
//! The INFORMATIONAL exchange is used for:
//! - Deleting Security Associations (IKE SA or Child SA)
//! - Sending status notifications
//! - Error reporting
//! - Liveness checks (Dead Peer Detection)
//!
//! # Message Flow
//!
//! ```text
//! Initiator                    Responder
//! ---------                    ---------
//! HDR, SK {[N+], [D+]}  -->
//!                        <--  HDR, SK {[N+], [D+]}
//! ```
//!
//! Where:
//! - N = NOTIFY payload (optional, multiple allowed)
//! - D = DELETE payload (optional, multiple allowed)
//!
//! # Examples
//!
//! ## Delete Child SA
//!
//! ```rust,ignore
//! use fynx_proto::ipsec::ikev2::informational::InformationalExchange;
//!
//! let msg = InformationalExchange::create_delete_child_sa_request(
//!     &mut context,
//!     vec![child_spi_1, child_spi_2],
//! )?;
//! ```
//!
//! ## Send Error Notification
//!
//! ```rust,ignore
//! let msg = InformationalExchange::create_notify_request(
//!     &mut context,
//!     NotifyType::NoProposalChosen,
//!     Vec::new(),
//! )?;
//! ```

use super::exchange::IkeSaContext;
use super::message::{IkeHeader, IkeMessage};
use super::payload::{DeletePayload, IkePayload, NotifyPayload, NotifyProtocolId, NotifyType};
use crate::ipsec::{Error, Result};

/// INFORMATIONAL Exchange Handler
///
/// Provides methods for creating and processing INFORMATIONAL exchange messages.
pub struct InformationalExchange;

impl InformationalExchange {
    /// Create INFORMATIONAL request to delete IKE SA
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    ///
    /// # Returns
    ///
    /// Returns the INFORMATIONAL request message with DELETE payload for IKE SA.
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    pub fn create_delete_ike_sa_request(context: &mut IkeSaContext) -> Result<IkeMessage> {
        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established before sending INFORMATIONAL".into(),
            ));
        }

        // Create header
        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            super::constants::PayloadType::SK, // Encrypted payload
            super::constants::ExchangeType::Informational,
            super::constants::IkeFlags::request(context.is_initiator),
            context.next_message_id(),
            0, // Length will be calculated during serialization
        );

        // Create DELETE payload for IKE SA
        let delete_payload = DeletePayload::delete_ike_sa();

        // Build encrypted payload list
        let payloads = vec![IkePayload::D(delete_payload)];

        // Encrypt payloads
        let encrypted_payloads = Self::encrypt_payloads(
            context,
            &header,
            &payloads,
            super::constants::PayloadType::D,
        )?;

        Ok(IkeMessage {
            header,
            payloads: encrypted_payloads,
        })
    }

    /// Create INFORMATIONAL request to delete Child SA(s)
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `spis` - List of Child SA SPIs to delete
    ///
    /// # Returns
    ///
    /// Returns the INFORMATIONAL request message with DELETE payload for Child SA(s).
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    /// - `InvalidParameter` if spis list is empty
    pub fn create_delete_child_sa_request(
        context: &mut IkeSaContext,
        spis: Vec<Vec<u8>>,
    ) -> Result<IkeMessage> {
        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established before sending INFORMATIONAL".into(),
            ));
        }

        // Validate SPIs
        if spis.is_empty() {
            return Err(Error::InvalidParameter("SPI list cannot be empty".into()));
        }

        let spi_size = spis[0].len() as u8;

        // Create header
        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            super::constants::PayloadType::SK, // Encrypted payload
            super::constants::ExchangeType::Informational,
            super::constants::IkeFlags::request(context.is_initiator),
            context.next_message_id(),
            0, // Length will be calculated during serialization
        );

        // Create DELETE payload for Child SA(s)
        let delete_payload = DeletePayload::new(NotifyProtocolId::Esp, spi_size, spis);

        // Build encrypted payload list
        let payloads = vec![IkePayload::D(delete_payload)];

        // Encrypt payloads
        let encrypted_payloads = Self::encrypt_payloads(
            context,
            &header,
            &payloads,
            super::constants::PayloadType::D,
        )?;

        Ok(IkeMessage {
            header,
            payloads: encrypted_payloads,
        })
    }

    /// Create INFORMATIONAL request with NOTIFY payload
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `notify_type` - Type of notification
    /// * `notification_data` - Optional notification data
    ///
    /// # Returns
    ///
    /// Returns the INFORMATIONAL request message with NOTIFY payload.
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    pub fn create_notify_request(
        context: &mut IkeSaContext,
        notify_type: NotifyType,
        notification_data: Vec<u8>,
    ) -> Result<IkeMessage> {
        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established before sending INFORMATIONAL".into(),
            ));
        }

        // Create header
        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            super::constants::PayloadType::SK, // Encrypted payload
            super::constants::ExchangeType::Informational,
            super::constants::IkeFlags::request(context.is_initiator),
            context.next_message_id(),
            0, // Length will be calculated during serialization
        );

        // Create NOTIFY payload
        let notify_payload = if notify_type.is_error() {
            NotifyPayload::error(notify_type)
        } else {
            NotifyPayload::status(notify_type, notification_data)
        };

        // Build encrypted payload list
        let payloads = vec![IkePayload::N(notify_payload)];

        // Encrypt payloads
        let encrypted_payloads = Self::encrypt_payloads(
            context,
            &header,
            &payloads,
            super::constants::PayloadType::N,
        )?;

        Ok(IkeMessage {
            header,
            payloads: encrypted_payloads,
        })
    }

    /// Create INFORMATIONAL response (empty acknowledgment)
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `request_header` - Header from the request message
    ///
    /// # Returns
    ///
    /// Returns an empty INFORMATIONAL response message.
    pub fn create_empty_response(
        context: &IkeSaContext,
        request_header: &IkeHeader,
    ) -> Result<IkeMessage> {
        // Create response header (same message ID as request)
        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            super::constants::PayloadType::SK, // Encrypted payload
            super::constants::ExchangeType::Informational,
            super::constants::IkeFlags::response(context.is_initiator),
            request_header.message_id,
            0, // Length will be calculated during serialization
        );

        // Empty encrypted payload
        let encrypted_payloads =
            Self::encrypt_payloads(context, &header, &[], super::constants::PayloadType::None)?;

        Ok(IkeMessage {
            header,
            payloads: encrypted_payloads,
        })
    }

    /// Process INFORMATIONAL request
    ///
    /// Extracts and processes DELETE and NOTIFY payloads from the request.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `message` - INFORMATIONAL request message
    ///
    /// # Returns
    ///
    /// Returns a tuple of (delete_payloads, notify_payloads) extracted from the message.
    ///
    /// # Errors
    ///
    /// - `DecryptionFailed` if payload decryption fails
    pub fn process_request(
        context: &IkeSaContext,
        message: &IkeMessage,
    ) -> Result<(Vec<DeletePayload>, Vec<NotifyPayload>)> {
        // Decrypt payloads
        let payloads = Self::decrypt_payloads(context, message)?;

        let mut delete_payloads = Vec::new();
        let mut notify_payloads = Vec::new();

        // Extract DELETE and NOTIFY payloads
        for payload in payloads {
            match payload {
                IkePayload::D(d) => delete_payloads.push(d),
                IkePayload::N(n) => notify_payloads.push(n),
                _ => {
                    // Ignore other payload types in INFORMATIONAL
                }
            }
        }

        Ok((delete_payloads, notify_payloads))
    }

    /// Process INFORMATIONAL response
    ///
    /// Validates the response and extracts any payloads.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `message` - INFORMATIONAL response message
    ///
    /// # Returns
    ///
    /// Returns extracted payloads (typically empty for acknowledgments).
    ///
    /// # Errors
    ///
    /// - `DecryptionFailed` if payload decryption fails
    pub fn process_response(
        context: &IkeSaContext,
        message: &IkeMessage,
    ) -> Result<Vec<IkePayload>> {
        // Decrypt payloads
        Self::decrypt_payloads(context, message)
    }

    /// Encrypt payloads for INFORMATIONAL message
    ///
    /// Serializes, pads, and encrypts inner payloads using the IKE SA context's
    /// encryption key. Uses AEAD cipher (AES-GCM or ChaCha20) with IKE header as AAD.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must have encryption keys derived)
    /// * `header` - IKE header (used as AAD)
    /// * `payloads` - Plaintext payloads to encrypt
    /// * `first_payload_type` - Type of the first payload
    ///
    /// # Returns
    ///
    /// Returns vector containing the encrypted SK payload.
    ///
    /// # Errors
    ///
    /// - `Internal` if encryption key not derived
    /// - `InvalidPayload` if unsupported payload type
    fn encrypt_payloads(
        context: &IkeSaContext,
        header: &IkeHeader,
        payloads: &[IkePayload],
        _first_payload_type: super::constants::PayloadType,
    ) -> Result<Vec<IkePayload>> {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use rand::Rng;

        // Get encryption key
        let encryption_key = context
            .get_send_encryption_key()
            .ok_or_else(|| Error::Internal("Encryption key not derived".into()))?;

        // Get cipher algorithm from selected proposal
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms
                    .iter()
                    .find(|t| t.transform_type == super::proposal::TransformType::Encr)
                    .map(|t| match t.transform_id {
                        20 => CipherAlgorithm::AesGcm128,
                        19 => CipherAlgorithm::AesGcm256,
                        28 => CipherAlgorithm::ChaCha20Poly1305,
                        _ => CipherAlgorithm::AesGcm128,
                    })
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Serialize and pad inner payloads
        let block_size = 16; // AES block size
        let plaintext = Self::serialize_and_pad(payloads, block_size)?;

        // Generate random IV
        let iv_len = cipher.iv_len();
        let mut iv = vec![0u8; iv_len];
        rand::thread_rng().fill(&mut iv[..]);

        // Serialize IKE header for AAD
        let ike_header_bytes = header.to_bytes();

        // Encrypt with AAD (IKE header)
        let ciphertext = cipher.encrypt(encryption_key, &iv, &plaintext, &ike_header_bytes)?;

        // Create SK payload (AEAD: tag is in ciphertext)
        let sk_payload = super::payload::EncryptedPayload::new_aead(iv, ciphertext);

        Ok(vec![IkePayload::SK(sk_payload)])
    }

    /// Decrypt payloads from INFORMATIONAL message
    ///
    /// Decrypts the SK payload using the IKE SA context's decryption key,
    /// removes padding, and parses the inner payloads.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must have encryption keys derived)
    /// * `message` - Message containing encrypted SK payload
    ///
    /// # Returns
    ///
    /// Returns decrypted and parsed inner payloads.
    ///
    /// # Errors
    ///
    /// - `Internal` if decryption key not derived
    /// - `InvalidPayload` if no SK payload found or invalid padding
    /// - `DecryptionFailed` if AEAD verification fails
    fn decrypt_payloads(context: &IkeSaContext, message: &IkeMessage) -> Result<Vec<IkePayload>> {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;

        // Extract SK payload
        let sk_payload = message
            .payloads
            .iter()
            .find_map(|p| match p {
                IkePayload::SK(sk) => Some(sk),
                _ => None,
            })
            .ok_or_else(|| Error::InvalidPayload("No SK payload found".into()))?;

        // Get decryption key
        let decryption_key = context
            .get_recv_encryption_key()
            .ok_or_else(|| Error::Internal("Decryption key not derived".into()))?;

        // Get cipher algorithm from selected proposal
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms
                    .iter()
                    .find(|t| t.transform_type == super::proposal::TransformType::Encr)
                    .map(|t| match t.transform_id {
                        20 => CipherAlgorithm::AesGcm128,
                        19 => CipherAlgorithm::AesGcm256,
                        28 => CipherAlgorithm::ChaCha20Poly1305,
                        _ => CipherAlgorithm::AesGcm128,
                    })
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Serialize IKE header for AAD
        let ike_header_bytes = message.header.to_bytes();

        // Decrypt with AAD (IKE header)
        let plaintext = cipher.decrypt(
            decryption_key,
            &sk_payload.iv,
            &sk_payload.encrypted_data,
            &ike_header_bytes,
        )?;

        // Handle empty plaintext (empty INFORMATIONAL response)
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        // Remove padding
        let pad_len = *plaintext.last().unwrap() as usize;
        if pad_len + 1 > plaintext.len() {
            return Err(Error::InvalidPayload("Invalid padding length".into()));
        }

        let payload_data = &plaintext[..plaintext.len() - pad_len - 1];

        // If no payload data after removing padding, return empty
        if payload_data.is_empty() {
            return Ok(Vec::new());
        }

        // Parse inner payloads using next_payload from header
        Self::parse_payload_chain(message.header.next_payload, payload_data)
    }

    /// Serialize and pad payloads for encryption
    ///
    /// # Arguments
    ///
    /// * `payloads` - Payloads to serialize
    /// * `block_size` - Cipher block size (8/16 bytes)
    ///
    /// # Returns
    ///
    /// Returns serialized and padded bytes
    fn serialize_and_pad(payloads: &[IkePayload], block_size: usize) -> Result<Vec<u8>> {
        use super::constants::PayloadType;

        // Handle empty payload list
        if payloads.is_empty() {
            // Just padding for empty payload
            let current_len = 1; // Just pad length byte
            let pad_len = (block_size - (current_len % block_size)) % block_size;
            let mut data = vec![0u8; pad_len];
            data.push(pad_len as u8);
            return Ok(data);
        }

        // Serialize payloads (only payload bytes, no IKE header)
        let mut data = Vec::new();
        for (i, payload) in payloads.iter().enumerate() {
            let next_payload = if i + 1 < payloads.len() {
                payloads[i + 1].payload_type()
            } else {
                PayloadType::None
            };

            // Generic header: next payload (1) + critical (1) + length (2)
            data.push(next_payload as u8);
            data.push(0); // Not critical

            let payload_data = match payload {
                IkePayload::D(d) => d.to_payload_data(),
                IkePayload::N(n) => n.to_payload_data(),
                IkePayload::SA(sa) => sa.to_payload_data(),
                IkePayload::IDi(id) | IkePayload::IDr(id) => id.to_payload_data(),
                IkePayload::AUTH(auth) => auth.to_payload_data(),
                IkePayload::TSi(ts) | IkePayload::TSr(ts) => ts.to_payload_data(),
                _ => {
                    return Err(Error::Internal(
                        "Unsupported payload type for INFORMATIONAL encryption".into(),
                    ))
                }
            };

            let length = 4 + payload_data.len();
            data.extend_from_slice(&(length as u16).to_be_bytes());
            data.extend_from_slice(&payload_data);
        }

        // Calculate padding needed
        let current_len = data.len() + 1; // +1 for pad length byte
        let pad_len = (block_size - (current_len % block_size)) % block_size;

        // Add padding (zeros)
        data.extend(vec![0u8; pad_len]);

        // Add pad length byte
        data.push(pad_len as u8);

        Ok(data)
    }

    /// Parse a chain of payloads from bytes
    ///
    /// Parses a linked list of IKE payloads where each payload header
    /// contains the type of the next payload.
    ///
    /// # Arguments
    ///
    /// * `first_payload_type` - Type of the first payload in the chain
    /// * `data` - Byte slice containing payload chain
    ///
    /// # Returns
    ///
    /// Returns vector of parsed payloads
    fn parse_payload_chain(
        mut current_type: super::constants::PayloadType,
        data: &[u8],
    ) -> Result<Vec<IkePayload>> {
        use super::message::IkeMessage;
        use super::payload::PayloadHeader;

        let mut payloads = Vec::new();
        let mut offset = 0;

        // Keep parsing until we hit the end or NoNextPayload
        while current_type != super::constants::PayloadType::None && offset < data.len() {
            // Parse header to get next_payload and length
            let header = PayloadHeader::from_bytes(&data[offset..])?;

            if offset + header.length as usize > data.len() {
                return Err(Error::BufferTooShort {
                    required: header.length as usize,
                    available: data.len() - offset,
                });
            }

            // Parse the current payload using its type
            let payload = IkeMessage::parse_payload(
                current_type,
                &data[offset..offset + header.length as usize],
            )?;

            payloads.push(payload);
            offset += header.length as usize;

            // Move to next payload type
            current_type = header.next_payload;
        }

        Ok(payloads)
    }
}

#[cfg(test)]
mod tests {
    use super::super::state::IkeState;
    use super::*;

    fn create_test_context() -> IkeSaContext {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.responder_spi = [0x22; 8];
        ctx.state = IkeState::Established;
        ctx.message_id = 1;
        ctx
    }

    #[test]
    fn test_create_delete_ike_sa_request() {
        let mut context = create_test_context();

        let result = InformationalExchange::create_delete_ike_sa_request(&mut context);

        // Should fail because encryption keys not set in test context
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[test]
    fn test_create_delete_child_sa_request() {
        let mut context = create_test_context();
        let spis = vec![vec![0xAA, 0xBB, 0xCC, 0xDD]];

        let result = InformationalExchange::create_delete_child_sa_request(&mut context, spis);

        // Should fail because encryption keys not set in test context
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[test]
    fn test_create_delete_child_sa_request_empty_spis() {
        let mut context = create_test_context();
        let spis = vec![];

        let result = InformationalExchange::create_delete_child_sa_request(&mut context, spis);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidParameter(_)));
    }

    #[test]
    fn test_create_delete_ike_sa_request_invalid_state() {
        let mut context = IkeSaContext::new_initiator([0x11; 8]);
        context.state = IkeState::Idle;

        let result = InformationalExchange::create_delete_ike_sa_request(&mut context);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidState(_)));
    }

    #[test]
    fn test_create_notify_request_error() {
        let mut context = create_test_context();

        let result = InformationalExchange::create_notify_request(
            &mut context,
            NotifyType::NoProposalChosen,
            Vec::new(),
        );

        // Should fail because encryption keys not set in test context
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[test]
    fn test_create_notify_request_status() {
        let mut context = create_test_context();
        let data = vec![0x01, 0x02, 0x03];

        let result = InformationalExchange::create_notify_request(
            &mut context,
            NotifyType::InitialContact,
            data,
        );

        // Should fail because encryption keys not set in test context
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }

    #[test]
    fn test_create_notify_request_invalid_state() {
        let mut context = IkeSaContext::new_initiator([0x11; 8]);
        context.state = IkeState::Idle;

        let result = InformationalExchange::create_notify_request(
            &mut context,
            NotifyType::InitialContact,
            Vec::new(),
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidState(_)));
    }

    #[test]
    fn test_create_empty_response() {
        let context = create_test_context();
        let request_header = IkeHeader::new(
            [0x11; 8],
            [0x22; 8],
            super::super::constants::PayloadType::SK,
            super::super::constants::ExchangeType::Informational,
            super::super::constants::IkeFlags::request(true),
            1,
            0,
        );

        let result = InformationalExchange::create_empty_response(&context, &request_header);

        // Should fail because encryption keys not set in test context
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Internal(_)));
    }
}
