//! IKEv2 Exchange Handlers
//!
//! Implements the core exchange logic for IKEv2 as defined in RFC 7296.
//!
//! # Exchange Types
//!
//! - **IKE_SA_INIT**: Initial exchange to establish IKE SA and negotiate crypto algorithms
//! - **IKE_AUTH**: Authentication exchange to authenticate peers and create first Child SA
//! - **CREATE_CHILD_SA**: Create additional Child SAs or rekey existing SAs
//! - **INFORMATIONAL**: Exchange status or error information
//!
//! # IKE_SA_INIT Exchange
//!
//! ```text
//! Initiator                         Responder
//! -----------                       -----------
//! HDR, SAi1, KEi, Ni  -->
//!                     <--  HDR, SAr1, KEr, Nr, [CERTREQ]
//!
//! Payloads:
//! - HDR: IKE header (SPIs, message ID, exchange type)
//! - SA: Security Association proposals
//! - KE: Key Exchange (DH public value)
//! - N: Nonce
//! - CERTREQ (optional): Certificate request
//! ```
//!
//! # IKE_AUTH Exchange
//!
//! ```text
//! Initiator                         Responder
//! -----------                       -----------
//! HDR, SK {IDi, [CERT,] [CERTREQ,]
//!     [IDr,] AUTH, SAi2, TSi, TSr}  -->
//!                     <--  HDR, SK {IDr, [CERT,] AUTH,
//!                              SAr2, TSi, TSr}
//!
//! Payloads:
//! - SK: Encrypted and authenticated payload container
//! - ID: Identification
//! - CERT (optional): Certificate
//! - CERTREQ (optional): Certificate request
//! - AUTH: Authentication data
//! - SA: Child SA proposals
//! - TS: Traffic Selectors
//! ```

use super::constants::{ExchangeType, IkeFlags, PayloadType};
use super::message::{IkeHeader, IkeMessage};
use super::payload::{
    AuthPayload, IdPayload, IkePayload, KePayload, NoncePayload, NotifyPayload, SaPayload,
};
use super::proposal::{select_proposal, Proposal};
use super::state::IkeState;
use crate::ipsec::{Error, Result};

/// IKE SA context
///
/// Maintains the state and cryptographic material for an IKE SA.
#[derive(Debug, Clone)]
pub struct IkeSaContext {
    /// Current state
    pub state: IkeState,

    /// Is this the initiator?
    pub is_initiator: bool,

    /// Initiator SPI
    pub initiator_spi: [u8; 8],

    /// Responder SPI
    pub responder_spi: [u8; 8],

    /// Message ID for next request
    pub message_id: u32,

    /// Selected proposal (after IKE_SA_INIT)
    pub selected_proposal: Option<Proposal>,

    /// Initiator nonce
    pub nonce_i: Option<Vec<u8>>,

    /// Responder nonce
    pub nonce_r: Option<Vec<u8>>,

    /// Initiator's DH public key
    pub ke_i: Option<Vec<u8>>,

    /// Responder's DH public key
    pub ke_r: Option<Vec<u8>>,

    /// Shared DH secret (computed after key exchange)
    pub shared_secret: Option<Vec<u8>>,

    /// SK_d - Key derivation key (for deriving child SA keys)
    pub sk_d: Option<Vec<u8>>,

    /// SK_ai - Initiator's authentication key
    pub sk_ai: Option<Vec<u8>>,

    /// SK_ar - Responder's authentication key
    pub sk_ar: Option<Vec<u8>>,

    /// SK_ei - Initiator's encryption key
    pub sk_ei: Option<Vec<u8>>,

    /// SK_er - Responder's encryption key
    pub sk_er: Option<Vec<u8>>,

    /// SK_pi - Initiator's SK_p key (for PSK auth)
    pub sk_pi: Option<Vec<u8>>,

    /// SK_pr - Responder's SK_p key (for PSK auth)
    pub sk_pr: Option<Vec<u8>>,
}

impl IkeSaContext {
    /// Create new IKE SA context as initiator
    pub fn new_initiator(initiator_spi: [u8; 8]) -> Self {
        IkeSaContext {
            state: IkeState::Idle,
            is_initiator: true,
            initiator_spi,
            responder_spi: [0u8; 8],
            message_id: 0,
            selected_proposal: None,
            nonce_i: None,
            nonce_r: None,
            ke_i: None,
            ke_r: None,
            shared_secret: None,
            sk_d: None,
            sk_ai: None,
            sk_ar: None,
            sk_ei: None,
            sk_er: None,
            sk_pi: None,
            sk_pr: None,
        }
    }

    /// Create new IKE SA context as responder
    pub fn new_responder(initiator_spi: [u8; 8], responder_spi: [u8; 8]) -> Self {
        IkeSaContext {
            state: IkeState::Idle,
            is_initiator: false,
            initiator_spi,
            responder_spi,
            message_id: 0,
            selected_proposal: None,
            nonce_i: None,
            nonce_r: None,
            ke_i: None,
            ke_r: None,
            shared_secret: None,
            sk_d: None,
            sk_ai: None,
            sk_ar: None,
            sk_ei: None,
            sk_er: None,
            sk_pi: None,
            sk_pr: None,
        }
    }

    /// Transition to new state
    pub fn transition_to(&mut self, new_state: IkeState) -> Result<()> {
        if !self.state.can_transition_to(new_state) {
            return Err(Error::InvalidState(format!(
                "Invalid state transition from {:?} to {:?}",
                self.state, new_state
            )));
        }
        self.state = new_state;
        Ok(())
    }

    /// Get next message ID and increment
    pub fn next_message_id(&mut self) -> u32 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }

    /// Validate message ID for received message
    pub fn validate_message_id(&self, received_id: u32, is_response: bool) -> Result<()> {
        if is_response {
            // Response should match the last request we sent
            if received_id != self.message_id.saturating_sub(1) {
                return Err(Error::InvalidMessageId {
                    expected: self.message_id.saturating_sub(1),
                    received: received_id,
                });
            }
        } else {
            // Request should match our current message ID
            if received_id != self.message_id {
                return Err(Error::InvalidMessageId {
                    expected: self.message_id,
                    received: received_id,
                });
            }
        }
        Ok(())
    }

    /// Derive encryption and authentication keys from DH shared secret
    ///
    /// Implements RFC 7296 Section 2.14 key derivation:
    /// ```text
    /// SKEYSEED = prf(Ni | Nr, g^ir)
    /// {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
    ///     = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `prf_alg` - PRF algorithm from selected proposal
    /// * `encr_key_len` - Encryption key length (from selected cipher)
    /// * `integ_key_len` - Integrity key length (0 for AEAD ciphers)
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if keys derived successfully, or error if preconditions not met
    pub fn derive_keys(
        &mut self,
        prf_alg: crate::ipsec::crypto::PrfAlgorithm,
        encr_key_len: usize,
        integ_key_len: usize,
    ) -> Result<()> {
        // Validate preconditions
        let nonce_i = self
            .nonce_i
            .as_ref()
            .ok_or_else(|| Error::Internal("Initiator nonce not set".into()))?;
        let nonce_r = self
            .nonce_r
            .as_ref()
            .ok_or_else(|| Error::Internal("Responder nonce not set".into()))?;
        let shared_secret = self
            .shared_secret
            .as_ref()
            .ok_or_else(|| Error::Internal("DH shared secret not computed".into()))?;

        // Derive all keys using KeyMaterial::derive
        let key_material = crate::ipsec::crypto::KeyMaterial::derive(
            prf_alg,
            nonce_i,
            nonce_r,
            shared_secret,
            &self.initiator_spi,
            &self.responder_spi,
            encr_key_len,
            integ_key_len,
        )?;

        // Store derived keys in context
        self.sk_d = Some(key_material.sk_d);
        self.sk_ai = Some(key_material.sk_ai);
        self.sk_ar = Some(key_material.sk_ar);
        self.sk_ei = Some(key_material.sk_ei);
        self.sk_er = Some(key_material.sk_er);
        self.sk_pi = Some(key_material.sk_pi);
        self.sk_pr = Some(key_material.sk_pr);

        Ok(())
    }

    /// Get encryption key for sending messages
    ///
    /// Returns SK_ei for initiator, SK_er for responder
    pub fn get_send_encryption_key(&self) -> Option<&[u8]> {
        if self.is_initiator {
            self.sk_ei.as_deref()
        } else {
            self.sk_er.as_deref()
        }
    }

    /// Get encryption key for receiving messages
    ///
    /// Returns SK_er for initiator, SK_ei for responder
    pub fn get_recv_encryption_key(&self) -> Option<&[u8]> {
        if self.is_initiator {
            self.sk_er.as_deref()
        } else {
            self.sk_ei.as_deref()
        }
    }

    /// Get authentication key for sending messages
    ///
    /// Returns SK_ai for initiator, SK_ar for responder
    pub fn get_send_auth_key(&self) -> Option<&[u8]> {
        if self.is_initiator {
            self.sk_ai.as_deref()
        } else {
            self.sk_ar.as_deref()
        }
    }

    /// Get authentication key for receiving messages
    ///
    /// Returns SK_ar for initiator, SK_ai for responder
    pub fn get_recv_auth_key(&self) -> Option<&[u8]> {
        if self.is_initiator {
            self.sk_ar.as_deref()
        } else {
            self.sk_ai.as_deref()
        }
    }

    /// Get PSK authentication key for this peer
    ///
    /// Returns SK_pi for initiator, SK_pr for responder
    pub fn get_psk_auth_key(&self) -> Option<&[u8]> {
        if self.is_initiator {
            self.sk_pi.as_deref()
        } else {
            self.sk_pr.as_deref()
        }
    }
}

/// IKE_SA_INIT exchange handler
pub struct IkeSaInitExchange;

impl IkeSaInitExchange {
    /// Create IKE_SA_INIT request (initiator)
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `proposals` - List of proposals to offer
    /// * `dh_public` - Diffie-Hellman public key
    /// * `nonce` - Random nonce value
    ///
    /// # Returns
    ///
    /// Returns the IKE_SA_INIT request message
    pub fn create_request(
        context: &mut IkeSaContext,
        proposals: Vec<Proposal>,
        dh_public: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<IkeMessage> {
        // Validate state
        if context.state != IkeState::Idle {
            return Err(Error::InvalidState(format!(
                "Cannot create IKE_SA_INIT request in state {:?}",
                context.state
            )));
        }

        // Store our nonce and DH public key
        context.nonce_i = Some(nonce.clone());
        context.ke_i = Some(dh_public.clone());

        // Create message ID
        let message_id = context.next_message_id();

        // Create header
        let header = IkeHeader {
            initiator_spi: context.initiator_spi,
            responder_spi: [0u8; 8], // Not yet assigned
            next_payload: super::constants::PayloadType::SA,
            version: super::constants::IKE_VERSION,
            exchange_type: ExchangeType::IkeSaInit,
            flags: IkeFlags::request(true),
            message_id,
            length: 0, // Will be calculated by to_bytes()
        };

        // Create payloads
        let sa_payload = SaPayload::new(proposals);
        let ke_payload = KePayload::new(KePayload::DH_GROUP_14, dh_public);
        let nonce_payload = NoncePayload::new(nonce)?;

        let message = IkeMessage {
            header,
            payloads: vec![
                IkePayload::SA(sa_payload),
                IkePayload::KE(ke_payload),
                IkePayload::Nonce(nonce_payload),
            ],
        };

        // Transition state
        context.transition_to(IkeState::InitSent)?;

        Ok(message)
    }

    /// Process IKE_SA_INIT request (responder)
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `request` - Received IKE_SA_INIT request
    /// * `configured_proposals` - Locally configured acceptable proposals
    ///
    /// # Returns
    ///
    /// Returns tuple of (selected_proposal, peer_dh_public, peer_nonce)
    pub fn process_request(
        context: &mut IkeSaContext,
        request: &IkeMessage,
        configured_proposals: &[Proposal],
    ) -> Result<(Proposal, Vec<u8>, Vec<u8>)> {
        // Validate exchange type
        if request.header.exchange_type != ExchangeType::IkeSaInit {
            return Err(Error::InvalidExchangeType);
        }

        // Validate state
        if context.state != IkeState::Idle {
            return Err(Error::InvalidState(format!(
                "Cannot process IKE_SA_INIT request in state {:?}",
                context.state
            )));
        }

        // Extract payloads
        let mut sa_payload = None;
        let mut ke_payload = None;
        let mut nonce_payload = None;

        for payload in &request.payloads {
            match payload {
                IkePayload::SA(sa) => sa_payload = Some(sa),
                IkePayload::KE(ke) => ke_payload = Some(ke),
                IkePayload::Nonce(nonce) => nonce_payload = Some(nonce),
                _ => {} // Ignore other payloads for now
            }
        }

        // Validate required payloads are present
        let sa = sa_payload.ok_or_else(|| Error::MissingPayload("SA".to_string()))?;
        let ke = ke_payload.ok_or_else(|| Error::MissingPayload("KE".to_string()))?;
        let nonce = nonce_payload.ok_or_else(|| Error::MissingPayload("Nonce".to_string()))?;

        // Select proposal
        let selected = select_proposal(&sa.proposals, configured_proposals)?;

        // Store peer's nonce and DH public key
        context.nonce_i = Some(nonce.nonce.clone());
        context.ke_i = Some(ke.key_data.clone());
        context.selected_proposal = Some(selected.clone());

        // Transition state
        context.transition_to(IkeState::InitDone)?;

        Ok((selected.clone(), ke.key_data.clone(), nonce.nonce.clone()))
    }

    /// Create IKE_SA_INIT response (responder)
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `request_header` - Header from the request message
    /// * `selected_proposal` - Selected proposal
    /// * `dh_public` - Our Diffie-Hellman public key
    /// * `nonce` - Our nonce value
    ///
    /// # Returns
    ///
    /// Returns the IKE_SA_INIT response message
    pub fn create_response(
        context: &mut IkeSaContext,
        request_header: &IkeHeader,
        selected_proposal: Proposal,
        dh_public: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<IkeMessage> {
        // Validate state
        if context.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Cannot create IKE_SA_INIT response in state {:?}",
                context.state
            )));
        }

        // Store our nonce and DH public key
        context.nonce_r = Some(nonce.clone());
        context.ke_r = Some(dh_public.clone());

        // Create header
        let header = IkeHeader {
            initiator_spi: request_header.initiator_spi,
            responder_spi: context.responder_spi,
            next_payload: super::constants::PayloadType::SA,
            version: super::constants::IKE_VERSION,
            exchange_type: ExchangeType::IkeSaInit,
            flags: IkeFlags::response(false), // Responder sends response
            message_id: request_header.message_id,
            length: 0, // Will be calculated
        };

        // Create payloads
        let sa_payload = SaPayload::new(vec![selected_proposal]);
        let ke_payload = KePayload::new(KePayload::DH_GROUP_14, dh_public);
        let nonce_payload = NoncePayload::new(nonce)?;

        let message = IkeMessage {
            header,
            payloads: vec![
                IkePayload::SA(sa_payload),
                IkePayload::KE(ke_payload),
                IkePayload::Nonce(nonce_payload),
            ],
        };

        Ok(message)
    }

    /// Process IKE_SA_INIT response (initiator)
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `response` - Received IKE_SA_INIT response
    ///
    /// # Returns
    ///
    /// Returns tuple of (selected_proposal, peer_dh_public, peer_nonce)
    pub fn process_response(
        context: &mut IkeSaContext,
        response: &IkeMessage,
    ) -> Result<(Proposal, Vec<u8>, Vec<u8>)> {
        // Validate exchange type
        if response.header.exchange_type != ExchangeType::IkeSaInit {
            return Err(Error::InvalidExchangeType);
        }

        // Validate state
        if context.state != IkeState::InitSent {
            return Err(Error::InvalidState(format!(
                "Cannot process IKE_SA_INIT response in state {:?}",
                context.state
            )));
        }

        // Validate message ID
        context.validate_message_id(response.header.message_id, true)?;

        // Store responder SPI
        context.responder_spi = response.header.responder_spi;

        // Extract payloads
        let mut sa_payload = None;
        let mut ke_payload = None;
        let mut nonce_payload = None;

        for payload in &response.payloads {
            match payload {
                IkePayload::SA(sa) => sa_payload = Some(sa),
                IkePayload::KE(ke) => ke_payload = Some(ke),
                IkePayload::Nonce(nonce) => nonce_payload = Some(nonce),
                _ => {} // Ignore other payloads
            }
        }

        // Validate required payloads
        let sa = sa_payload.ok_or_else(|| Error::MissingPayload("SA".to_string()))?;
        let ke = ke_payload.ok_or_else(|| Error::MissingPayload("KE".to_string()))?;
        let nonce = nonce_payload.ok_or_else(|| Error::MissingPayload("Nonce".to_string()))?;

        // Get selected proposal (should be exactly one)
        if sa.proposals.is_empty() {
            return Err(Error::NoProposalChosen);
        }
        let selected = &sa.proposals[0];

        // Store peer's nonce and DH public key
        context.nonce_r = Some(nonce.nonce.clone());
        context.ke_r = Some(ke.key_data.clone());
        context.selected_proposal = Some(selected.clone());

        // Transition state
        context.transition_to(IkeState::InitDone)?;

        Ok((selected.clone(), ke.key_data.clone(), nonce.nonce.clone()))
    }
}

/// IKE_AUTH exchange handler
///
/// Handles the IKE_AUTH exchange which authenticates peers and creates the first Child SA.
///
/// # Exchange Flow (RFC 7296 Section 1.2)
///
/// ```text
/// Initiator                         Responder
/// -----------                       -----------
/// HDR, SK {IDi, [CERT,] [CERTREQ,]
///     [IDr,] AUTH, SAi2,
///     TSi, TSr}  -->
///                     <--  HDR, SK {IDr, [CERT,] AUTH,
///                              SAr2, TSi, TSr}
/// ```
///
/// All payloads after IKE_SA_INIT are encrypted and integrity-protected using SK payload.
pub struct IkeAuthExchange;

impl IkeAuthExchange {
    /// Serialize inner payloads and add padding
    ///
    /// Serializes a list of payloads into bytes and adds padding according to
    /// RFC 7296 Section 2.3:
    /// - Pad to cipher block size
    /// - Pad length byte at end (0-255)
    /// - Padding bytes can be any value (we use zeros)
    ///
    /// # Arguments
    ///
    /// * `payloads` - List of payloads to serialize
    /// * `block_size` - Cipher block size (8/16 bytes)
    ///
    /// # Returns
    ///
    /// Returns serialized and padded bytes
    fn serialize_and_pad(payloads: &[IkePayload], block_size: usize) -> Result<Vec<u8>> {
        use super::constants::PayloadType;

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
                IkePayload::SA(sa) => sa.to_payload_data(),
                IkePayload::IDi(id) | IkePayload::IDr(id) => id.to_payload_data(),
                IkePayload::AUTH(auth) => auth.to_payload_data(),
                IkePayload::TSi(ts) | IkePayload::TSr(ts) => ts.to_payload_data(),
                _ => return Err(Error::Internal("Unsupported payload type for encryption".into())),
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

    /// Encrypt inner payloads into SK payload
    ///
    /// Serializes, pads, and encrypts inner payloads using the IKE SA context's
    /// encryption key. Uses AEAD cipher (AES-GCM or ChaCha20) with IKE header as AAD.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must have encryption keys derived)
    /// * `ike_header` - IKE header bytes (used as AAD)
    /// * `inner_payloads` - Payloads to encrypt
    /// * `cipher` - Cipher algorithm to use
    ///
    /// # Returns
    ///
    /// Returns the encrypted SK payload
    fn encrypt_payloads(
        context: &IkeSaContext,
        ike_header: &[u8],
        inner_payloads: &[IkePayload],
        cipher: crate::ipsec::crypto::cipher::CipherAlgorithm,
    ) -> Result<super::payload::EncryptedPayload> {
        use rand::Rng;

        // Get encryption key
        let encryption_key = context
            .get_send_encryption_key()
            .ok_or_else(|| Error::Internal("Encryption key not derived".into()))?;

        // Serialize and pad inner payloads
        let block_size = 16; // AES block size (also works for ChaCha20)
        let plaintext = Self::serialize_and_pad(inner_payloads, block_size)?;

        // Generate random IV
        let iv_len = cipher.iv_len();
        let mut iv = vec![0u8; iv_len];
        rand::thread_rng().fill(&mut iv[..]);

        // Encrypt with AAD (IKE header)
        let ciphertext = cipher.encrypt(encryption_key, &iv, &plaintext, ike_header)?;

        // Create SK payload (AEAD: tag is in ciphertext)
        Ok(super::payload::EncryptedPayload::new_aead(iv, ciphertext))
    }

    /// Decrypt SK payload and parse inner payloads
    ///
    /// Decrypts the SK payload using the IKE SA context's decryption key,
    /// removes padding, and parses the inner payloads.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must have encryption keys derived)
    /// * `ike_header` - IKE header bytes (used as AAD)
    /// * `sk_payload` - Encrypted SK payload
    /// * `cipher` - Cipher algorithm to use
    /// * `first_payload_type` - Type of the first inner payload
    ///
    /// # Returns
    ///
    /// Returns the decrypted and parsed inner payloads
    fn decrypt_payloads(
        context: &IkeSaContext,
        ike_header: &[u8],
        sk_payload: &super::payload::EncryptedPayload,
        cipher: crate::ipsec::crypto::cipher::CipherAlgorithm,
        first_payload_type: PayloadType,
    ) -> Result<Vec<IkePayload>> {
        // Get decryption key
        let decryption_key = context
            .get_recv_encryption_key()
            .ok_or_else(|| Error::Internal("Decryption key not derived".into()))?;

        // Decrypt with AAD (IKE header)
        let plaintext = cipher.decrypt(
            decryption_key,
            &sk_payload.iv,
            &sk_payload.encrypted_data,
            ike_header,
        )?;

        // Remove padding
        if plaintext.is_empty() {
            return Err(Error::InvalidPayload("Empty plaintext after decryption".into()));
        }

        let pad_len = *plaintext.last().unwrap() as usize;
        if pad_len + 1 > plaintext.len() {
            return Err(Error::InvalidPayload("Invalid padding length".into()));
        }

        let payload_data = &plaintext[..plaintext.len() - pad_len - 1];

        // Parse inner payloads using the provided first payload type
        Self::parse_payload_chain(first_payload_type, payload_data)
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
        mut current_type: PayloadType,
        data: &[u8],
    ) -> Result<Vec<IkePayload>> {
        use super::message::IkeMessage;
        use super::payload::PayloadHeader;

        let mut payloads = Vec::new();
        let mut offset = 0;

        // Keep parsing until we hit the end or NoNextPayload
        while current_type != PayloadType::None && offset < data.len() {
            // Parse header to get next_payload and length
            let header = PayloadHeader::from_bytes(&data[offset..])?;

            if offset + header.length as usize > data.len() {
                return Err(Error::BufferTooShort {
                    required: header.length as usize,
                    available: data.len() - offset,
                });
            }

            // Parse the current payload using its type
            let payload =
                IkeMessage::parse_payload(current_type, &data[offset..offset + header.length as usize])?;

            payloads.push(payload);
            offset += header.length as usize;

            // Move to next payload type
            current_type = header.next_payload;
        }

        Ok(payloads)
    }

    /// Create IKE_AUTH request (initiator)
    ///
    /// Creates an encrypted IKE_AUTH request containing:
    /// - IDi: Initiator identification
    /// - AUTH: Authentication data (PSK-based)
    /// - SAi2: Child SA proposals
    /// - TSi: Initiator's traffic selectors
    /// - TSr: Responder's traffic selectors
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be in InitDone state)
    /// * `id_payload` - Initiator's identification
    /// * `psk` - Pre-shared key for authentication
    /// * `child_proposals` - Child SA proposals
    /// * `ts_i` - Initiator's traffic selectors
    /// * `ts_r` - Responder's traffic selectors
    ///
    /// # Returns
    ///
    /// Returns the encrypted IKE_AUTH request message
    ///
    /// # State Transition
    ///
    /// InitDone → AuthSent
    pub fn create_request(
        context: &mut IkeSaContext,
        ike_sa_init_request: &[u8],
        id_payload: IdPayload,
        psk: &[u8],
        child_proposals: Vec<Proposal>,
        ts_i: super::payload::TrafficSelectorsPayload,
        ts_r: super::payload::TrafficSelectorsPayload,
    ) -> Result<IkeMessage> {
        use super::auth;
        use super::constants::{ExchangeType, IkeFlags, PayloadType};
        use super::message::{IkeHeader, IkeMessage};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

        // Validate state
        if context.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Cannot create IKE_AUTH request in state {:?}",
                context.state
            )));
        }

        // Get the selected proposal from IKE_SA_INIT
        let selected_proposal = context
            .selected_proposal
            .as_ref()
            .ok_or_else(|| Error::Internal("No proposal selected".into()))?;

        // Get PRF algorithm from selected proposal
        let prf_alg = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Prf)
            .map(|t| {
                // Map transform ID to PrfAlgorithm
                match t.transform_id {
                    2 => PrfAlgorithm::HmacSha256,
                    3 => PrfAlgorithm::HmacSha384,
                    4 => PrfAlgorithm::HmacSha512,
                    _ => PrfAlgorithm::HmacSha256, // Default
                }
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm from selected proposal
        let cipher = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| {
                // Map transform ID to CipherAlgorithm
                match t.transform_id {
                    20 => CipherAlgorithm::AesGcm128, // ENCR_AES_GCM_16 with 128-bit key
                    19 => CipherAlgorithm::AesGcm256, // ENCR_AES_GCM_16 with 256-bit key (non-standard)
                    28 => CipherAlgorithm::ChaCha20Poly1305, // ENCR_CHACHA20_POLY1305
                    _ => CipherAlgorithm::AesGcm128, // Default
                }
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Get nonce_r
        let nonce_r = context
            .nonce_r
            .as_ref()
            .ok_or_else(|| Error::Internal("Responder nonce not set".into()))?;

        // Get SK_pi for AUTH computation
        let sk_pi = context
            .get_psk_auth_key()
            .ok_or_else(|| Error::Internal("SK_pi not derived".into()))?;

        // Construct signed octets for AUTH computation
        let signed_octets = auth::construct_initiator_signed_octets(
            prf_alg,
            ike_sa_init_request,
            nonce_r,
            sk_pi,
            &id_payload.data,
        );

        // Compute AUTH payload
        let auth_payload = auth::compute_psk_auth(prf_alg, sk_pi, &signed_octets);

        // Build Child SA proposal payload
        let sa_payload = super::payload::SaPayload {
            proposals: child_proposals,
        };

        // Build inner payloads: IDi, AUTH, SAi2, TSi, TSr
        let inner_payloads = vec![
            IkePayload::IDi(id_payload),
            IkePayload::AUTH(auth_payload),
            IkePayload::SA(sa_payload),
            IkePayload::TSi(ts_i),
            IkePayload::TSr(ts_r),
        ];

        // Create IKE header for this message
        let message_id = context.next_message_id();
        let flags = IkeFlags::request(true); // Initiator request

        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            PayloadType::SK,
            ExchangeType::IkeAuth,
            flags,
            message_id,
            0, // Length will be computed during serialization
        );

        // Serialize IKE header to use as AAD
        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload = Self::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

        // Build final message with SK payload
        let message = IkeMessage::new(header, vec![IkePayload::SK(sk_payload)]);

        // Transition to AuthSent state
        context.transition_to(IkeState::AuthSent)?;

        Ok(message)
    }

    /// Process IKE_AUTH request (responder)
    ///
    /// Processes an encrypted IKE_AUTH request:
    /// - Decrypt SK payload
    /// - Parse inner payloads
    /// - Validate AUTH payload
    /// - Select Child SA proposal
    /// - Negotiate traffic selectors
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be in InitDone state)
    /// * `request` - IKE_AUTH request message
    /// * `psk` - Pre-shared key for authentication
    /// * `configured_proposals` - Configured Child SA proposals
    ///
    /// # Returns
    ///
    /// Returns tuple of (peer_id, selected_proposal, negotiated_tsi, negotiated_tsr)
    pub fn process_request(
        context: &mut IkeSaContext,
        ike_sa_init_response: &[u8],
        request: &IkeMessage,
        psk: &[u8],
        configured_proposals: &[Proposal],
    ) -> Result<(IdPayload, Proposal, super::payload::TrafficSelectorsPayload, super::payload::TrafficSelectorsPayload)> {
        use super::auth;
        use super::constants::ExchangeType;
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

        // Validate state
        if context.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Cannot process IKE_AUTH request in state {:?}",
                context.state
            )));
        }

        // Validate exchange type
        if request.header.exchange_type != ExchangeType::IkeAuth {
            return Err(Error::InvalidExchangeType);
        }

        // Validate this is from initiator
        if !request.header.flags.is_initiator() {
            return Err(Error::InvalidMessage("IKE_AUTH request must be from initiator".into()));
        }

        // Get the selected proposal
        let selected_proposal = context
            .selected_proposal
            .as_ref()
            .ok_or_else(|| Error::Internal("No proposal selected".into()))?;

        // Get PRF algorithm
        let prf_alg = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Prf)
            .map(|t| {
                match t.transform_id {
                    2 => PrfAlgorithm::HmacSha256,
                    3 => PrfAlgorithm::HmacSha384,
                    4 => PrfAlgorithm::HmacSha512,
                    _ => PrfAlgorithm::HmacSha256,
                }
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm
        let cipher = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| {
                match t.transform_id {
                    20 => CipherAlgorithm::AesGcm128,
                    19 => CipherAlgorithm::AesGcm256,
                    28 => CipherAlgorithm::ChaCha20Poly1305,
                    _ => CipherAlgorithm::AesGcm128,
                }
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Extract SK payload
        let sk_payload = request
            .payloads
            .iter()
            .find_map(|p| match p {
                IkePayload::SK(sk) => Some(sk),
                _ => None,
            })
            .ok_or_else(|| Error::InvalidMessage("No SK payload in IKE_AUTH request".into()))?;

        // Serialize IKE header for AAD
        let ike_header_bytes = request.header.to_bytes();

        // Decrypt SK payload
        // In IKE_AUTH request, first payload is IDi
        let inner_payloads = Self::decrypt_payloads(
            context,
            &ike_header_bytes,
            sk_payload,
            cipher,
            PayloadType::IDi,
        )?;

        // Extract payloads from inner_payloads
        let mut peer_id: Option<IdPayload> = None;
        let mut auth_payload: Option<super::payload::AuthPayload> = None;
        let mut child_sa: Option<super::payload::SaPayload> = None;
        let mut ts_i: Option<super::payload::TrafficSelectorsPayload> = None;
        let mut ts_r: Option<super::payload::TrafficSelectorsPayload> = None;

        for payload in &inner_payloads {
            match payload {
                IkePayload::IDi(id) => peer_id = Some(id.clone()),
                IkePayload::AUTH(auth) => auth_payload = Some(auth.clone()),
                IkePayload::SA(sa) => child_sa = Some(sa.clone()),
                IkePayload::TSi(ts) => ts_i = Some(ts.clone()),
                IkePayload::TSr(ts) => ts_r = Some(ts.clone()),
                _ => {}, // Ignore other payloads (CERT, CERTREQ, etc.)
            }
        }

        // Validate required payloads are present
        let peer_id = peer_id.ok_or_else(|| Error::InvalidMessage("Missing IDi payload".into()))?;
        let auth_payload = auth_payload.ok_or_else(|| Error::InvalidMessage("Missing AUTH payload".into()))?;
        let child_sa = child_sa.ok_or_else(|| Error::InvalidMessage("Missing SA payload".into()))?;
        let ts_i = ts_i.ok_or_else(|| Error::InvalidMessage("Missing TSi payload".into()))?;
        let ts_r = ts_r.ok_or_else(|| Error::InvalidMessage("Missing TSr payload".into()))?;

        // Verify AUTH payload
        let nonce_i = context
            .nonce_i
            .as_ref()
            .ok_or_else(|| Error::Internal("Initiator nonce not set".into()))?;

        let sk_pi = context
            .get_psk_auth_key()
            .ok_or_else(|| Error::Internal("SK_pi not derived".into()))?;

        // Construct signed octets for AUTH verification
        let signed_octets = auth::construct_initiator_signed_octets(
            prf_alg,
            ike_sa_init_response,
            nonce_i,
            sk_pi,
            &peer_id.data,
        );

        // Compute expected AUTH
        let expected_auth = auth::compute_psk_auth(prf_alg, sk_pi, &signed_octets);

        // Verify AUTH matches
        if auth_payload.auth_method != expected_auth.auth_method {
            return Err(Error::AuthenticationFailed("AUTH method mismatch".into()));
        }
        if auth_payload.auth_data != expected_auth.auth_data {
            return Err(Error::AuthenticationFailed("AUTH data mismatch".into()));
        }

        // Select Child SA proposal
        let selected_child_proposal = select_proposal(&child_sa.proposals, configured_proposals)?.clone();

        Ok((peer_id, selected_child_proposal, ts_i, ts_r))
    }

    /// Create IKE_AUTH response (responder)
    ///
    /// Creates an encrypted IKE_AUTH response containing:
    /// - IDr: Responder identification
    /// - AUTH: Authentication data
    /// - SAr2: Selected Child SA proposal
    /// - TSi: Negotiated initiator traffic selectors
    /// - TSr: Negotiated responder traffic selectors
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `request` - Original request message (for message ID)
    /// * `id_payload` - Responder's identification
    /// * `psk` - Pre-shared key
    /// * `selected_proposal` - Selected Child SA proposal
    /// * `ts_i` - Negotiated initiator traffic selectors
    /// * `ts_r` - Negotiated responder traffic selectors
    ///
    /// # Returns
    ///
    /// Returns the encrypted IKE_AUTH response message
    ///
    /// # State Transition
    ///
    /// InitDone → Established
    pub fn create_response(
        context: &mut IkeSaContext,
        ike_sa_init_response: &[u8],
        request: &IkeMessage,
        id_payload: IdPayload,
        _psk: &[u8],
        selected_proposal: Proposal,
        ts_i: super::payload::TrafficSelectorsPayload,
        ts_r: super::payload::TrafficSelectorsPayload,
    ) -> Result<IkeMessage> {
        use super::auth;
        use super::constants::{ExchangeType, IkeFlags, PayloadType};
        use super::message::{IkeHeader, IkeMessage};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

        // Validate state
        if context.state != IkeState::InitDone {
            return Err(Error::InvalidState(format!(
                "Cannot create IKE_AUTH response in state {:?}",
                context.state
            )));
        }

        // Get the selected IKE SA proposal
        let ike_proposal = context
            .selected_proposal
            .as_ref()
            .ok_or_else(|| Error::Internal("No proposal selected".into()))?;

        // Get PRF algorithm
        let prf_alg = ike_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Prf)
            .map(|t| {
                match t.transform_id {
                    2 => PrfAlgorithm::HmacSha256,
                    3 => PrfAlgorithm::HmacSha384,
                    4 => PrfAlgorithm::HmacSha512,
                    _ => PrfAlgorithm::HmacSha256,
                }
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm
        let cipher = ike_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| {
                match t.transform_id {
                    20 => CipherAlgorithm::AesGcm128,
                    19 => CipherAlgorithm::AesGcm256,
                    28 => CipherAlgorithm::ChaCha20Poly1305,
                    _ => CipherAlgorithm::AesGcm128,
                }
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Get nonce_i
        let nonce_i = context
            .nonce_i
            .as_ref()
            .ok_or_else(|| Error::Internal("Initiator nonce not set".into()))?;

        // Get SK_pr for AUTH computation
        let sk_pr = context
            .get_psk_auth_key()
            .ok_or_else(|| Error::Internal("SK_pr not derived".into()))?;

        // Construct responder signed octets
        let signed_octets = auth::construct_responder_signed_octets(
            prf_alg,
            ike_sa_init_response,
            nonce_i,
            sk_pr,
            &id_payload.data,
        );

        // Compute AUTH payload
        let auth_payload = auth::compute_psk_auth(prf_alg, sk_pr, &signed_octets);

        // Build Child SA proposal payload
        let sa_payload = super::payload::SaPayload {
            proposals: vec![selected_proposal],
        };

        // Build inner payloads: IDr, AUTH, SAr2, TSi, TSr
        let inner_payloads = vec![
            IkePayload::IDr(id_payload),
            IkePayload::AUTH(auth_payload),
            IkePayload::SA(sa_payload),
            IkePayload::TSi(ts_i),
            IkePayload::TSr(ts_r),
        ];

        // Create IKE header for response
        let flags = IkeFlags::response(false); // Responder response
        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            PayloadType::SK,
            ExchangeType::IkeAuth,
            flags,
            request.header.message_id, // Same message ID as request
            0, // Length computed during serialization
        );

        // Serialize IKE header for AAD
        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload = Self::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

        // Build final message
        let message = IkeMessage::new(header, vec![IkePayload::SK(sk_payload)]);

        // Transition to Established state
        context.transition_to(IkeState::Established)?;

        Ok(message)
    }

    /// Process IKE_AUTH response (initiator)
    ///
    /// Processes an encrypted IKE_AUTH response:
    /// - Decrypt SK payload
    /// - Parse inner payloads
    /// - Validate AUTH payload
    /// - Store selected Child SA proposal
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be in AuthSent state)
    /// * `response` - IKE_AUTH response message
    /// * `psk` - Pre-shared key
    ///
    /// # Returns
    ///
    /// Returns tuple of (peer_id, selected_proposal, tsi, tsr)
    ///
    /// # State Transition
    ///
    /// AuthSent → Established
    pub fn process_response(
        context: &mut IkeSaContext,
        ike_sa_init_response: &[u8],
        response: &IkeMessage,
        _psk: &[u8],
    ) -> Result<(IdPayload, Proposal, super::payload::TrafficSelectorsPayload, super::payload::TrafficSelectorsPayload)> {
        use super::auth;
        use super::constants::ExchangeType;
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

        // Validate state
        if context.state != IkeState::AuthSent {
            return Err(Error::InvalidState(format!(
                "Cannot process IKE_AUTH response in state {:?}",
                context.state
            )));
        }

        // Validate exchange type
        if response.header.exchange_type != ExchangeType::IkeAuth {
            return Err(Error::InvalidExchangeType);
        }

        // Validate this is a response
        if !response.header.flags.is_response() {
            return Err(Error::InvalidMessage("Expected IKE_AUTH response".into()));
        }

        // Get the selected proposal
        let selected_proposal = context
            .selected_proposal
            .as_ref()
            .ok_or_else(|| Error::Internal("No proposal selected".into()))?;

        // Get PRF algorithm
        let prf_alg = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Prf)
            .map(|t| {
                match t.transform_id {
                    2 => PrfAlgorithm::HmacSha256,
                    3 => PrfAlgorithm::HmacSha384,
                    4 => PrfAlgorithm::HmacSha512,
                    _ => PrfAlgorithm::HmacSha256,
                }
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm
        let cipher = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| {
                match t.transform_id {
                    20 => CipherAlgorithm::AesGcm128,
                    19 => CipherAlgorithm::AesGcm256,
                    28 => CipherAlgorithm::ChaCha20Poly1305,
                    _ => CipherAlgorithm::AesGcm128,
                }
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Extract SK payload
        let sk_payload = response
            .payloads
            .iter()
            .find_map(|p| match p {
                IkePayload::SK(sk) => Some(sk),
                _ => None,
            })
            .ok_or_else(|| Error::InvalidMessage("No SK payload in IKE_AUTH response".into()))?;

        // Serialize IKE header for AAD
        let ike_header_bytes = response.header.to_bytes();

        // Decrypt SK payload
        // In IKE_AUTH response, first payload is IDr
        let inner_payloads = Self::decrypt_payloads(
            context,
            &ike_header_bytes,
            sk_payload,
            cipher,
            PayloadType::IDr,
        )?;

        // Extract payloads from inner_payloads
        let mut peer_id: Option<IdPayload> = None;
        let mut auth_payload: Option<super::payload::AuthPayload> = None;
        let mut child_sa: Option<super::payload::SaPayload> = None;
        let mut ts_i: Option<super::payload::TrafficSelectorsPayload> = None;
        let mut ts_r: Option<super::payload::TrafficSelectorsPayload> = None;

        for payload in &inner_payloads {
            match payload {
                IkePayload::IDr(id) => peer_id = Some(id.clone()),
                IkePayload::AUTH(auth) => auth_payload = Some(auth.clone()),
                IkePayload::SA(sa) => child_sa = Some(sa.clone()),
                IkePayload::TSi(ts) => ts_i = Some(ts.clone()),
                IkePayload::TSr(ts) => ts_r = Some(ts.clone()),
                _ => {}, // Ignore other payloads
            }
        }

        // Validate required payloads are present
        let peer_id = peer_id.ok_or_else(|| Error::InvalidMessage("Missing IDr payload".into()))?;
        let auth_payload = auth_payload.ok_or_else(|| Error::InvalidMessage("Missing AUTH payload".into()))?;
        let child_sa = child_sa.ok_or_else(|| Error::InvalidMessage("Missing SA payload".into()))?;
        let ts_i = ts_i.ok_or_else(|| Error::InvalidMessage("Missing TSi payload".into()))?;
        let ts_r = ts_r.ok_or_else(|| Error::InvalidMessage("Missing TSr payload".into()))?;

        // Verify AUTH payload
        let nonce_r = context
            .nonce_r
            .as_ref()
            .ok_or_else(|| Error::Internal("Responder nonce not set".into()))?;

        let sk_pr = context
            .get_psk_auth_key()
            .ok_or_else(|| Error::Internal("SK_pr not derived".into()))?;

        // Construct signed octets for AUTH verification
        let signed_octets = auth::construct_responder_signed_octets(
            prf_alg,
            ike_sa_init_response,
            nonce_r,
            sk_pr,
            &peer_id.data,
        );

        // Compute expected AUTH
        let expected_auth = auth::compute_psk_auth(prf_alg, sk_pr, &signed_octets);

        // Verify AUTH matches
        if auth_payload.auth_method != expected_auth.auth_method {
            return Err(Error::AuthenticationFailed("AUTH method mismatch".into()));
        }
        if auth_payload.auth_data != expected_auth.auth_data {
            return Err(Error::AuthenticationFailed("AUTH data mismatch".into()));
        }

        // Extract the selected Child SA proposal (should be one that we proposed)
        let child_proposal = child_sa
            .proposals
            .first()
            .ok_or_else(|| Error::InvalidMessage("No Child SA proposal in response".into()))?
            .clone();

        // Transition to Established state
        context.transition_to(IkeState::Established)?;

        Ok((peer_id, child_proposal, ts_i, ts_r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::ikev2::proposal::{
        DhTransformId, EncrTransformId, IntegTransformId, PrfTransformId, ProtocolId, Transform,
    };

    fn create_test_proposal() -> Proposal {
        Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm128))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14))
    }

    #[test]
    fn test_ike_sa_context_new_initiator() {
        let spi = [1u8; 8];
        let ctx = IkeSaContext::new_initiator(spi);

        assert_eq!(ctx.state, IkeState::Idle);
        assert!(ctx.is_initiator);
        assert_eq!(ctx.initiator_spi, spi);
        assert_eq!(ctx.message_id, 0);
    }

    #[test]
    fn test_ike_sa_context_new_responder() {
        let init_spi = [1u8; 8];
        let resp_spi = [2u8; 8];
        let ctx = IkeSaContext::new_responder(init_spi, resp_spi);

        assert_eq!(ctx.state, IkeState::Idle);
        assert!(!ctx.is_initiator);
        assert_eq!(ctx.initiator_spi, init_spi);
        assert_eq!(ctx.responder_spi, resp_spi);
    }

    #[test]
    fn test_ike_sa_context_transition() {
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);

        assert!(ctx.transition_to(IkeState::InitSent).is_ok());
        assert_eq!(ctx.state, IkeState::InitSent);

        // Invalid transition
        assert!(ctx.transition_to(IkeState::Established).is_err());
    }

    #[test]
    fn test_ike_sa_context_message_id() {
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);

        assert_eq!(ctx.next_message_id(), 0);
        assert_eq!(ctx.next_message_id(), 1);
        assert_eq!(ctx.next_message_id(), 2);
    }

    #[test]
    fn test_create_ike_sa_init_request() {
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        let proposals = vec![create_test_proposal()];
        let dh_public = vec![0xAA; 256];
        let nonce = vec![0xBB; 32];

        let msg = IkeSaInitExchange::create_request(&mut ctx, proposals, dh_public, nonce)
            .expect("Failed to create request");

        assert_eq!(msg.header.exchange_type, ExchangeType::IkeSaInit);
        assert!(msg.header.flags.is_initiator());
        assert!(!msg.header.flags.is_response());
        assert_eq!(msg.payloads.len(), 3);
        assert_eq!(ctx.state, IkeState::InitSent);
    }

    #[test]
    fn test_create_request_invalid_state() {
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        ctx.state = IkeState::InitSent;

        let result = IkeSaInitExchange::create_request(
            &mut ctx,
            vec![create_test_proposal()],
            vec![0xAA; 256],
            vec![0xBB; 32],
        );

        assert!(result.is_err());
    }

    // IKE_AUTH encryption/decryption tests

    #[test]
    fn test_serialize_and_pad_empty() {
        let payloads: Vec<IkePayload> = vec![];
        let result = IkeAuthExchange::serialize_and_pad(&payloads, 16);
        assert!(result.is_ok());

        let data = result.unwrap();
        // Empty payloads: just padding to block size
        // 1 byte (pad length) + padding = 16 bytes
        assert_eq!(data.len(), 16);
        assert_eq!(data[15], 15); // Pad length = 15
    }

    #[test]
    fn test_serialize_and_pad_single_payload() {
        use super::super::payload::{AuthMethod, AuthPayload};

        let auth = AuthPayload {
            auth_method: AuthMethod::SharedKeyMic,
            auth_data: vec![0xAA; 32],
        };
        let payloads = vec![IkePayload::AUTH(auth)];

        let result = IkeAuthExchange::serialize_and_pad(&payloads, 16);
        assert!(result.is_ok());

        let data = result.unwrap();
        // Generic header (4) + auth method (1) + reserved (3) + auth data (32) = 40 bytes
        // 40 + 1 (pad length) = 41 bytes
        // Pad to 48 bytes (next multiple of 16)
        // Padding = 7 bytes
        assert_eq!(data.len(), 48);
        assert_eq!(data[47], 7); // Pad length = 7
    }

    #[test]
    fn test_serialize_and_pad_multiple_payloads() {
        use super::super::payload::{AuthMethod, AuthPayload, IdPayload, IdType};

        let id = IdPayload {
            id_type: IdType::Ipv4Addr,
            data: vec![192, 168, 1, 1],
        };
        let auth = AuthPayload {
            auth_method: AuthMethod::SharedKeyMic,
            auth_data: vec![0xBB; 32],
        };

        let payloads = vec![IkePayload::IDi(id), IkePayload::AUTH(auth)];

        let result = IkeAuthExchange::serialize_and_pad(&payloads, 16);
        assert!(result.is_ok());

        let data = result.unwrap();
        // IDi: header (4) + type (1) + reserved (3) + data (4) = 12
        // AUTH: header (4) + method (1) + reserved (3) + data (32) = 40
        // Total: 52 + 1 (pad length) = 53 bytes
        // Pad to 64 bytes (next multiple of 16)
        // Padding = 11 bytes
        assert_eq!(data.len(), 64);
        assert_eq!(data[63], 11); // Pad length = 11
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;
        use super::super::payload::{AuthMethod, AuthPayload};

        // Setup initiator context
        let mut ctx_i = IkeSaContext::new_initiator([1u8; 8]);
        ctx_i.responder_spi = [2u8; 8];
        ctx_i.nonce_i = Some(vec![0x01; 32]);
        ctx_i.nonce_r = Some(vec![0x02; 32]);
        ctx_i.shared_secret = Some(vec![0x03; 256]);

        // Derive keys (AES-GCM-128: 16-byte key, 16-byte integ)
        ctx_i.derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Key derivation failed");

        // Setup responder context (same keys, different role)
        let mut ctx_r = IkeSaContext::new_responder([1u8; 8], [2u8; 8]);
        ctx_r.nonce_i = Some(vec![0x01; 32]);
        ctx_r.nonce_r = Some(vec![0x02; 32]);
        ctx_r.shared_secret = Some(vec![0x03; 256]);
        ctx_r.derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Key derivation failed");

        // Create test payload
        let auth = AuthPayload {
            auth_method: AuthMethod::SharedKeyMic,
            auth_data: vec![0xAA; 32],
        };
        let payloads = vec![IkePayload::AUTH(auth)];

        // Fake IKE header (28 bytes)
        let ike_header = vec![0x00; 28];

        // Encrypt (initiator sends)
        let cipher = CipherAlgorithm::AesGcm128;
        let sk_payload = IkeAuthExchange::encrypt_payloads(&ctx_i, &ike_header, &payloads, cipher)
            .expect("Encryption failed");

        // Verify SK payload structure
        assert_eq!(sk_payload.iv.len(), 8); // AES-GCM IV
        assert!(!sk_payload.encrypted_data.is_empty());
        assert!(sk_payload.is_aead()); // ICV should be empty for AEAD

        // Decrypt (responder receives)
        let decrypted = IkeAuthExchange::decrypt_payloads(
            &ctx_r,
            &ike_header,
            &sk_payload,
            cipher,
            PayloadType::AUTH, // First inner payload is AUTH
        )
        .expect("Decryption failed");

        // Verify parsed payloads
        assert_eq!(decrypted.len(), 1, "Should have parsed 1 payload");

        // Debug: print actual payload type
        match &decrypted[0] {
            IkePayload::AUTH(auth) => {
                assert_eq!(auth.auth_method, AuthMethod::SharedKeyMic);
                assert_eq!(auth.auth_data, vec![0xAA; 32]);
            }
            other => panic!("Expected AUTH payload, got {:?}", other.payload_type()),
        }
    }

    #[test]
    fn test_encrypt_without_keys() {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;

        let ctx = IkeSaContext::new_initiator([1u8; 8]);
        let payloads: Vec<IkePayload> = vec![];
        let ike_header = vec![0x00; 28];

        let result = IkeAuthExchange::encrypt_payloads(&ctx, &ike_header, &payloads, CipherAlgorithm::AesGcm128);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Encryption key not derived"));
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;
        use super::super::payload::{AuthMethod, AuthPayload};

        // Setup context with derived keys
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        ctx.responder_spi = [2u8; 8];
        ctx.nonce_i = Some(vec![0x01; 32]);
        ctx.nonce_r = Some(vec![0x02; 32]);
        ctx.shared_secret = Some(vec![0x03; 256]);
        ctx.derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Key derivation failed");

        // Encrypt with correct AAD
        let auth = AuthPayload {
            auth_method: AuthMethod::SharedKeyMic,
            auth_data: vec![0xAA; 32],
        };
        let payloads = vec![IkePayload::AUTH(auth)];
        let correct_header = vec![0x00; 28];

        let cipher = CipherAlgorithm::AesGcm128;
        let sk_payload = IkeAuthExchange::encrypt_payloads(&ctx, &correct_header, &payloads, cipher)
            .expect("Encryption failed");

        // Try to decrypt with wrong AAD
        let wrong_header = vec![0xFF; 28];
        let result = IkeAuthExchange::decrypt_payloads(
            &ctx,
            &wrong_header,
            &sk_payload,
            cipher,
            PayloadType::AUTH,
        );

        // Should fail due to authentication tag mismatch
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_corrupted_ciphertext() {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;
        use super::super::payload::{AuthMethod, AuthPayload, EncryptedPayload};

        // Setup context with derived keys
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        ctx.responder_spi = [2u8; 8];
        ctx.nonce_i = Some(vec![0x01; 32]);
        ctx.nonce_r = Some(vec![0x02; 32]);
        ctx.shared_secret = Some(vec![0x03; 256]);
        ctx.derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Key derivation failed");

        // Encrypt
        let auth = AuthPayload {
            auth_method: AuthMethod::SharedKeyMic,
            auth_data: vec![0xAA; 32],
        };
        let payloads = vec![IkePayload::AUTH(auth)];
        let ike_header = vec![0x00; 28];

        let cipher = CipherAlgorithm::AesGcm128;
        let sk_payload = IkeAuthExchange::encrypt_payloads(&ctx, &ike_header, &payloads, cipher)
            .expect("Encryption failed");

        // Corrupt the ciphertext
        let mut corrupted_data = sk_payload.encrypted_data.clone();
        corrupted_data[0] ^= 0xFF;
        let corrupted_payload = EncryptedPayload::new_aead(sk_payload.iv.clone(), corrupted_data);

        // Try to decrypt corrupted data
        let result = IkeAuthExchange::decrypt_payloads(
            &ctx,
            &ike_header,
            &corrupted_payload,
            cipher,
            PayloadType::AUTH,
        );

        // Should fail due to authentication tag mismatch
        assert!(result.is_err());
    }

    // IKE_AUTH create_request tests

    #[test]
    fn test_ike_auth_create_request() {
        use crate::ipsec::crypto::PrfAlgorithm;
        use super::super::constants::ExchangeType;
        use super::super::payload::{IdPayload, IdType, TrafficSelector, TrafficSelectorsPayload, TsType};
        use super::super::proposal::{ProtocolId, Transform, TransformType};

        // Setup initiator context with derived keys
        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        ctx.responder_spi = [2u8; 8];
        ctx.nonce_i = Some(vec![0x01; 32]);
        ctx.nonce_r = Some(vec![0x02; 32]);
        ctx.shared_secret = Some(vec![0x03; 256]);
        ctx.state = IkeState::InitDone;

        // Set selected proposal with PRF and encryption
        let proposal = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::new(TransformType::Prf, 2)) // HMAC-SHA256
            .add_transform(Transform::new(TransformType::Encr, 20)); // AES-GCM-128
        ctx.selected_proposal = Some(proposal);

        // Derive keys
        ctx.derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Key derivation failed");

        // Create test parameters
        let ike_sa_init_request = vec![0xAA; 100]; // Fake IKE_SA_INIT request
        let id_payload = IdPayload {
            id_type: IdType::Ipv4Addr,
            data: vec![192, 168, 1, 1],
        };
        let psk = b"test_psk";

        // Child SA proposal
        let child_proposal = Proposal::new(1, ProtocolId::Esp)
            .add_transform(Transform::new(TransformType::Encr, 20)); // AES-GCM-128
        let child_proposals = vec![child_proposal];

        // Traffic selectors
        let ts_i = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        };
        let ts_r = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        };

        // Create request
        let message = IkeAuthExchange::create_request(
            &mut ctx,
            &ike_sa_init_request,
            id_payload,
            psk,
            child_proposals,
            ts_i,
            ts_r,
        )
        .expect("Failed to create IKE_AUTH request");

        // Verify message structure
        assert_eq!(message.header.exchange_type, ExchangeType::IkeAuth);
        assert!(message.header.flags.is_initiator());
        assert!(!message.header.flags.is_response());
        assert_eq!(message.header.message_id, 0); // First message after IKE_SA_INIT
        assert_eq!(message.payloads.len(), 1); // Should contain SK payload

        // Verify SK payload
        match &message.payloads[0] {
            IkePayload::SK(sk) => {
                assert_eq!(sk.iv.len(), 8); // AES-GCM IV
                assert!(!sk.encrypted_data.is_empty());
                assert!(sk.is_aead());
            }
            _ => panic!("Expected SK payload"),
        }

        // Verify state transition
        assert_eq!(ctx.state, IkeState::AuthSent);
    }

    #[test]
    fn test_ike_auth_create_request_wrong_state() {
        use super::super::payload::{IdPayload, IdType, TrafficSelectorsPayload};

        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        ctx.state = IkeState::Idle; // Wrong state

        let ike_sa_init_request = vec![0xAA; 100];
        let id_payload = IdPayload {
            id_type: IdType::Ipv4Addr,
            data: vec![192, 168, 1, 1],
        };
        let ts = TrafficSelectorsPayload { selectors: vec![] };

        let result = IkeAuthExchange::create_request(
            &mut ctx,
            &ike_sa_init_request,
            id_payload,
            b"test_psk",
            vec![],
            ts.clone(),
            ts,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid state"));
    }

    #[test]
    fn test_ike_auth_create_request_no_proposal() {
        use super::super::payload::{IdPayload, IdType, TrafficSelectorsPayload};

        let mut ctx = IkeSaContext::new_initiator([1u8; 8]);
        ctx.state = IkeState::InitDone;
        // No selected_proposal set

        let ike_sa_init_request = vec![0xAA; 100];
        let id_payload = IdPayload {
            id_type: IdType::Ipv4Addr,
            data: vec![192, 168, 1, 1],
        };
        let ts = TrafficSelectorsPayload { selectors: vec![] };

        let result = IkeAuthExchange::create_request(
            &mut ctx,
            &ike_sa_init_request,
            id_payload,
            b"test_psk",
            vec![],
            ts.clone(),
            ts,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No proposal selected"));
    }
}
