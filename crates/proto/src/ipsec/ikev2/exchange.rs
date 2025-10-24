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

use super::constants::{ExchangeType, IkeFlags};
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
}
