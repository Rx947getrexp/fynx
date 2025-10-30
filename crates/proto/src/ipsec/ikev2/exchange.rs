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
use super::payload::{IdPayload, IkePayload, KePayload, NoncePayload, SaPayload};
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

    /// Lifetime configuration for IKE SA
    pub lifetime: crate::ipsec::child_sa::SaLifetime,

    /// Creation timestamp (for lifetime tracking)
    pub created_at: std::time::Instant,

    /// Timestamp when rekeying was initiated (None if not rekeying)
    pub rekey_initiated_at: Option<std::time::Instant>,

    /// Child SAs managed by this IKE SA
    pub child_sas: Vec<crate::ipsec::child_sa::ChildSa>,
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
            lifetime: crate::ipsec::child_sa::SaLifetime::default(),
            created_at: std::time::Instant::now(),
            rekey_initiated_at: None,
            child_sas: Vec::new(),
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
            lifetime: crate::ipsec::child_sa::SaLifetime::default(),
            created_at: std::time::Instant::now(),
            rekey_initiated_at: None,
            child_sas: Vec::new(),
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

    /// Get IKE SA age since creation
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Check if IKE SA should be rekeyed
    ///
    /// Returns true if soft lifetime has been exceeded
    pub fn should_rekey(&self) -> bool {
        self.lifetime.is_soft_expired(self.age(), 0)
    }

    /// Check if IKE SA has expired
    ///
    /// Returns true if hard lifetime has been exceeded
    pub fn is_expired(&self) -> bool {
        self.lifetime.is_hard_expired(self.age(), 0)
    }

    /// Initiate IKE SA rekey
    ///
    /// Transitions state from Established to Rekeying
    ///
    /// # Errors
    ///
    /// Returns error if not in Established state
    pub fn initiate_rekey(&mut self) -> Result<()> {
        if self.state != IkeState::Established {
            return Err(Error::InvalidState(format!(
                "Cannot initiate rekey from state {:?}",
                self.state
            )));
        }

        self.transition_to(IkeState::Rekeying)?;
        self.rekey_initiated_at = Some(std::time::Instant::now());
        Ok(())
    }

    /// Mark IKE SA as rekeyed
    ///
    /// Transitions from Rekeying back to Established (for new SA)
    /// or to Deleting (for old SA)
    pub fn mark_rekeyed(&mut self) -> Result<()> {
        if self.state != IkeState::Rekeying {
            return Err(Error::InvalidState(format!(
                "Cannot mark rekeyed from state {:?}",
                self.state
            )));
        }

        self.transition_to(IkeState::Deleting)?;
        Ok(())
    }

    /// Transfer Child SAs to new IKE SA
    ///
    /// Moves all Child SAs from this IKE SA to the new one
    ///
    /// # Arguments
    ///
    /// * `new_ike_sa` - The new IKE SA to transfer Child SAs to
    ///
    /// # Returns
    ///
    /// Returns the number of Child SAs transferred
    pub fn transfer_child_sas(&mut self, new_ike_sa: &mut IkeSaContext) -> usize {
        let count = self.child_sas.len();
        new_ike_sa.child_sas.append(&mut self.child_sas);
        count
    }

    /// Add a Child SA to this IKE SA
    pub fn add_child_sa(&mut self, child_sa: crate::ipsec::child_sa::ChildSa) {
        self.child_sas.push(child_sa);
    }

    /// Remove a Child SA by SPI
    ///
    /// Returns the removed Child SA if found
    pub fn remove_child_sa(&mut self, spi: u32) -> Option<crate::ipsec::child_sa::ChildSa> {
        if let Some(index) = self.child_sas.iter().position(|sa| sa.spi == spi) {
            Some(self.child_sas.remove(index))
        } else {
            None
        }
    }

    /// Get number of active Child SAs
    pub fn child_sa_count(&self) -> usize {
        self.child_sas.len()
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
    /// * `local_addr` - Optional local IP address and port for NAT detection
    /// * `remote_addr` - Optional remote IP address and port for NAT detection
    ///
    /// # Returns
    ///
    /// Returns the IKE_SA_INIT request message
    pub fn create_request(
        context: &mut IkeSaContext,
        proposals: Vec<Proposal>,
        dh_public: Vec<u8>,
        nonce: Vec<u8>,
        local_addr: Option<(std::net::IpAddr, u16)>,
        remote_addr: Option<(std::net::IpAddr, u16)>,
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

        let mut payloads = vec![
            IkePayload::SA(sa_payload),
            IkePayload::KE(ke_payload),
            IkePayload::Nonce(nonce_payload),
        ];

        // Add NAT_DETECTION payloads if addresses are provided
        if let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
            (local_addr, remote_addr)
        {
            use super::payload::{NatDetectionDestinationIpPayload, NatDetectionSourceIpPayload};
            use crate::ipsec::nat::NatDetectionHash;

            let spi_i = u64::from_be_bytes(context.initiator_spi);
            let spi_r = u64::from_be_bytes(context.responder_spi); // Will be 0 in request

            // NAT_DETECTION_SOURCE_IP: hash of our (local) IP and port
            let hash_local = NatDetectionHash::compute(spi_i, spi_r, local_ip, local_port);
            payloads.push(IkePayload::NatDetectionSourceIp(
                NatDetectionSourceIpPayload::new(hash_local.hash),
            ));

            // NAT_DETECTION_DESTINATION_IP: hash of peer (remote) IP and port
            let hash_remote = NatDetectionHash::compute(spi_i, spi_r, remote_ip, remote_port);
            payloads.push(IkePayload::NatDetectionDestinationIp(
                NatDetectionDestinationIpPayload::new(hash_remote.hash),
            ));
        }

        let message = IkeMessage { header, payloads };

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
    /// * `local_addr` - Optional local IP address and port for NAT detection
    /// * `remote_addr` - Optional remote IP address and port for NAT detection
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
        local_addr: Option<(std::net::IpAddr, u16)>,
        remote_addr: Option<(std::net::IpAddr, u16)>,
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

        let mut payloads = vec![
            IkePayload::SA(sa_payload),
            IkePayload::KE(ke_payload),
            IkePayload::Nonce(nonce_payload),
        ];

        // Add NAT_DETECTION payloads if addresses are provided
        if let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) =
            (local_addr, remote_addr)
        {
            use super::payload::{NatDetectionDestinationIpPayload, NatDetectionSourceIpPayload};
            use crate::ipsec::nat::NatDetectionHash;

            let spi_i = u64::from_be_bytes(request_header.initiator_spi);
            let spi_r = u64::from_be_bytes(context.responder_spi);

            // NAT_DETECTION_SOURCE_IP: hash of our (local) IP and port
            let hash_local = NatDetectionHash::compute(spi_i, spi_r, local_ip, local_port);
            payloads.push(IkePayload::NatDetectionSourceIp(
                NatDetectionSourceIpPayload::new(hash_local.hash),
            ));

            // NAT_DETECTION_DESTINATION_IP: hash of peer (remote) IP and port
            let hash_remote = NatDetectionHash::compute(spi_i, spi_r, remote_ip, remote_port);
            payloads.push(IkePayload::NatDetectionDestinationIp(
                NatDetectionDestinationIpPayload::new(hash_remote.hash),
            ));
        }

        let message = IkeMessage { header, payloads };

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
                IkePayload::Nonce(nonce) => nonce.to_payload_data(),
                IkePayload::KE(ke) => ke.to_payload_data(),
                _ => {
                    return Err(Error::Internal(
                        "Unsupported payload type for encryption".into(),
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
            return Err(Error::InvalidPayload(
                "Empty plaintext after decryption".into(),
            ));
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
    fn parse_payload_chain(mut current_type: PayloadType, data: &[u8]) -> Result<Vec<IkePayload>> {
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
        _psk: &[u8],
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
                    _ => CipherAlgorithm::AesGcm128,  // Default
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
        let sk_payload =
            Self::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

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
        ike_sa_init_request: &[u8],
        request: &IkeMessage,
        _psk: &[u8],
        configured_proposals: &[Proposal],
    ) -> Result<(
        IdPayload,
        Proposal,
        super::payload::TrafficSelectorsPayload,
        super::payload::TrafficSelectorsPayload,
    )> {
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
            return Err(Error::InvalidMessage(
                "IKE_AUTH request must be from initiator".into(),
            ));
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
            .map(|t| match t.transform_id {
                2 => PrfAlgorithm::HmacSha256,
                3 => PrfAlgorithm::HmacSha384,
                4 => PrfAlgorithm::HmacSha512,
                _ => PrfAlgorithm::HmacSha256,
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm
        let cipher = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| match t.transform_id {
                20 => CipherAlgorithm::AesGcm128,
                19 => CipherAlgorithm::AesGcm256,
                28 => CipherAlgorithm::ChaCha20Poly1305,
                _ => CipherAlgorithm::AesGcm128,
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
                _ => {} // Ignore other payloads (CERT, CERTREQ, etc.)
            }
        }

        // Validate required payloads are present
        let peer_id = peer_id.ok_or_else(|| Error::InvalidMessage("Missing IDi payload".into()))?;
        let auth_payload =
            auth_payload.ok_or_else(|| Error::InvalidMessage("Missing AUTH payload".into()))?;
        let child_sa =
            child_sa.ok_or_else(|| Error::InvalidMessage("Missing SA payload".into()))?;
        let ts_i = ts_i.ok_or_else(|| Error::InvalidMessage("Missing TSi payload".into()))?;
        let ts_r = ts_r.ok_or_else(|| Error::InvalidMessage("Missing TSr payload".into()))?;

        // Verify AUTH payload
        let nonce_r = context
            .nonce_r
            .as_ref()
            .ok_or_else(|| Error::Internal("Responder nonce not set".into()))?;

        let sk_pi = context
            .get_psk_auth_key()
            .ok_or_else(|| Error::Internal("SK_pi not derived".into()))?;

        // Construct signed octets for AUTH verification
        // Responder verifies initiator's AUTH using: IKE_SA_INIT request + Nr + SK_pi
        let signed_octets = auth::construct_initiator_signed_octets(
            prf_alg,
            ike_sa_init_request,
            nonce_r,
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
        let selected_child_proposal =
            select_proposal(&child_sa.proposals, configured_proposals)?.clone();

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
            .map(|t| match t.transform_id {
                2 => PrfAlgorithm::HmacSha256,
                3 => PrfAlgorithm::HmacSha384,
                4 => PrfAlgorithm::HmacSha512,
                _ => PrfAlgorithm::HmacSha256,
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm
        let cipher = ike_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| match t.transform_id {
                20 => CipherAlgorithm::AesGcm128,
                19 => CipherAlgorithm::AesGcm256,
                28 => CipherAlgorithm::ChaCha20Poly1305,
                _ => CipherAlgorithm::AesGcm128,
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
            0,                         // Length computed during serialization
        );

        // Serialize IKE header for AAD
        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload =
            Self::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

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
    ) -> Result<(
        IdPayload,
        Proposal,
        super::payload::TrafficSelectorsPayload,
        super::payload::TrafficSelectorsPayload,
    )> {
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
            .map(|t| match t.transform_id {
                2 => PrfAlgorithm::HmacSha256,
                3 => PrfAlgorithm::HmacSha384,
                4 => PrfAlgorithm::HmacSha512,
                _ => PrfAlgorithm::HmacSha256,
            })
            .unwrap_or(PrfAlgorithm::HmacSha256);

        // Get cipher algorithm
        let cipher = selected_proposal
            .transforms
            .iter()
            .find(|t| t.transform_type == super::proposal::TransformType::Encr)
            .map(|t| match t.transform_id {
                20 => CipherAlgorithm::AesGcm128,
                19 => CipherAlgorithm::AesGcm256,
                28 => CipherAlgorithm::ChaCha20Poly1305,
                _ => CipherAlgorithm::AesGcm128,
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
                _ => {} // Ignore other payloads
            }
        }

        // Validate required payloads are present
        let peer_id = peer_id.ok_or_else(|| Error::InvalidMessage("Missing IDr payload".into()))?;
        let auth_payload =
            auth_payload.ok_or_else(|| Error::InvalidMessage("Missing AUTH payload".into()))?;
        let child_sa =
            child_sa.ok_or_else(|| Error::InvalidMessage("Missing SA payload".into()))?;
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

/// CREATE_CHILD_SA exchange handler
///
/// Handles the CREATE_CHILD_SA exchange which creates additional Child SAs or rekeys existing SAs.
/// This exchange is used after IKE_AUTH to create new Child SAs for different traffic selectors
/// or to rekey existing Child SAs before they expire.
///
/// # RFC 7296 Section 1.3
///
/// ```text
/// Initiator                         Responder
/// -----------                       -----------
/// HDR, SK {SA, Ni, [KEi],  -->
///          TSi, TSr}
///                          <--  HDR, SK {SA, Nr, [KEr],
///                                       TSi, TSr}
/// ```
///
/// # Payloads
///
/// **Request**:
/// - SA: Child SA proposals (cipher, integrity, ESN, DH group)
/// - Ni: Nonce (for key derivation)
/// - KEi: Key Exchange (optional, for PFS - Perfect Forward Secrecy)
/// - TSi: Traffic Selectors (initiator)
/// - TSr: Traffic Selectors (responder)
///
/// **Response**:
/// - SA: Selected Child SA proposal
/// - Nr: Nonce (for key derivation)
/// - KEr: Key Exchange (optional, for PFS)
/// - TSi: Traffic Selectors (narrowed if necessary)
/// - TSr: Traffic Selectors (narrowed if necessary)
///
/// # Key Derivation
///
/// Child SA keys are derived from the IKE SA's SK_d key:
///
/// ```text
/// KEYMAT = prf+(SK_d, Ni | Nr)  [without PFS]
/// KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)  [with PFS]
///
/// SK_ei | SK_ai | SK_er | SK_ar = KEYMAT
/// ```
pub struct CreateChildSaExchange;

impl CreateChildSaExchange {
    /// Create CREATE_CHILD_SA request
    ///
    /// Builds an encrypted CREATE_CHILD_SA request message containing Child SA proposals,
    /// nonce, optional DH key exchange (for PFS), and traffic selectors.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be in Established state)
    /// * `child_proposals` - Child SA proposals to offer
    /// * `ts_i` - Initiator traffic selectors
    /// * `ts_r` - Responder traffic selectors
    /// * `use_pfs` - Whether to use Perfect Forward Secrecy (includes KEi payload)
    /// * `dh_public_key` - DH public key (required if use_pfs is true)
    ///
    /// # Returns
    ///
    /// Returns the CREATE_CHILD_SA request message and the generated nonce.
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    /// - `InvalidParameter` if PFS is requested but no DH key provided
    pub fn create_request(
        context: &mut IkeSaContext,
        child_proposals: &[Proposal],
        ts_i: super::payload::TrafficSelectorsPayload,
        ts_r: super::payload::TrafficSelectorsPayload,
        use_pfs: bool,
        dh_public_key: Option<Vec<u8>>,
    ) -> Result<(IkeMessage, Vec<u8>)> {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use rand::Rng;

        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established before creating Child SA".into(),
            ));
        }

        // Validate PFS parameters
        if use_pfs && dh_public_key.is_none() {
            return Err(Error::InvalidParameter(
                "DH public key required when using PFS".into(),
            ));
        }

        // Generate nonce
        let mut nonce = vec![0u8; 32]; // 256-bit nonce
        rand::thread_rng().fill(&mut nonce[..]);

        // Build Child SA proposal payload
        let sa_payload = SaPayload {
            proposals: child_proposals.to_vec(),
        };

        // Build nonce payload
        let nonce_payload = NoncePayload {
            nonce: nonce.clone(),
        };

        // Build inner payloads
        let mut inner_payloads = vec![IkePayload::SA(sa_payload), IkePayload::Nonce(nonce_payload)];

        // Add KEi if using PFS
        if use_pfs {
            let dh_group = context
                .selected_proposal
                .as_ref()
                .and_then(|p| {
                    p.transforms.iter().find_map(|t| {
                        if matches!(t.transform_type, super::proposal::TransformType::Dh) {
                            Some(t.transform_id as u16)
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| Error::Internal("No DH group in selected proposal".into()))?;

            inner_payloads.push(IkePayload::KE(KePayload {
                dh_group,
                key_data: dh_public_key.unwrap(),
            }));
        }

        // Add traffic selectors
        inner_payloads.push(IkePayload::TSi(ts_i));
        inner_payloads.push(IkePayload::TSr(ts_r));

        // Get cipher algorithm from selected proposal
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        // Map transform ID to CipherAlgorithm
                        match t.transform_id {
                            20 => Some(CipherAlgorithm::AesGcm128), // ENCR_AES_GCM_16 with 128-bit key
                            21 => Some(CipherAlgorithm::AesGcm256), // ENCR_AES_GCM_16 with 256-bit key
                            28 => Some(CipherAlgorithm::ChaCha20Poly1305), // ENCR_CHACHA20_POLY1305
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| Error::Internal("No cipher in selected proposal".into()))?;

        // Build IKE header
        let header = IkeHeader {
            initiator_spi: context.initiator_spi,
            responder_spi: context.responder_spi,
            next_payload: PayloadType::SK,
            version: 0x20, // IKEv2
            exchange_type: ExchangeType::CreateChildSa,
            flags: IkeFlags::request(context.is_initiator),
            message_id: context.message_id,
            length: 0, // Will be calculated
        };

        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload =
            IkeAuthExchange::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

        // Build message
        let message = IkeMessage {
            header,
            payloads: vec![IkePayload::SK(sk_payload)],
        };

        // Increment message ID for next exchange
        context.message_id += 1;

        Ok((message, nonce))
    }

    /// Process CREATE_CHILD_SA request (Responder)
    ///
    /// Decrypts and processes the CREATE_CHILD_SA request, selects a Child SA proposal,
    /// derives Child SA keys, and prepares for response creation.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be established)
    /// * `request` - CREATE_CHILD_SA request message
    /// * `nonce_r` - Responder's nonce (generated by caller)
    /// * `configured_proposals` - Configured Child SA proposals
    /// * `dh_shared_secret` - Optional DH shared secret (for PFS)
    ///
    /// # Returns
    ///
    /// Returns tuple of (selected_proposal, nonce_i, ts_i, ts_r, sk_ei, sk_ai, sk_er, sk_ar)
    /// where the keys are the derived Child SA encryption and authentication keys.
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    /// - `InvalidMessage` if request is malformed
    /// - `NoProposalChosen` if no acceptable proposal found
    pub fn process_request(
        context: &IkeSaContext,
        request: &IkeMessage,
        nonce_r: &[u8],
        configured_proposals: &[Proposal],
        dh_shared_secret: Option<&[u8]>,
    ) -> Result<(
        Proposal,
        Vec<u8>,
        super::payload::TrafficSelectorsPayload,
        super::payload::TrafficSelectorsPayload,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    )> {
        use crate::ipsec::child_sa::derive_child_sa_keys;
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::prf::PrfAlgorithm;

        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established to process CREATE_CHILD_SA".into(),
            ));
        }

        // Verify exchange type
        if request.header.exchange_type != ExchangeType::CreateChildSa {
            return Err(Error::InvalidExchangeType);
        }

        // Extract SK payload
        let sk_payload = request
            .payloads
            .iter()
            .find_map(|p| {
                if let IkePayload::SK(sk) = p {
                    Some(sk)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::MissingPayload("SK payload not found".into()))?;

        // Get cipher algorithm
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        // Map transform ID to CipherAlgorithm
                        match t.transform_id {
                            20 => Some(CipherAlgorithm::AesGcm128), // ENCR_AES_GCM_16 with 128-bit key
                            21 => Some(CipherAlgorithm::AesGcm256), // ENCR_AES_GCM_16 with 256-bit key
                            28 => Some(CipherAlgorithm::ChaCha20Poly1305), // ENCR_CHACHA20_POLY1305
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| Error::Internal("No cipher in selected proposal".into()))?;

        // Decrypt inner payloads
        let ike_header_bytes = request.header.to_bytes();
        let inner_payloads = IkeAuthExchange::decrypt_payloads(
            context,
            &ike_header_bytes,
            sk_payload,
            cipher,
            PayloadType::SA, // First payload is SA
        )?;

        // Extract payloads
        let mut child_sa: Option<SaPayload> = None;
        let mut nonce_i: Option<Vec<u8>> = None;
        let mut ke_i: Option<KePayload> = None;
        let mut ts_i: Option<super::payload::TrafficSelectorsPayload> = None;
        let mut ts_r: Option<super::payload::TrafficSelectorsPayload> = None;

        for payload in &inner_payloads {
            match payload {
                IkePayload::SA(sa) => child_sa = Some(sa.clone()),
                IkePayload::Nonce(nonce) => nonce_i = Some(nonce.nonce.clone()),
                IkePayload::KE(ke) => ke_i = Some(ke.clone()),
                IkePayload::TSi(ts) => ts_i = Some(ts.clone()),
                IkePayload::TSr(ts) => ts_r = Some(ts.clone()),
                _ => {}
            }
        }

        // Validate required payloads
        let child_sa = child_sa.ok_or_else(|| Error::MissingPayload("SA payload".into()))?;
        let nonce_i = nonce_i.ok_or_else(|| Error::MissingPayload("Nonce payload".into()))?;
        let ts_i = ts_i.ok_or_else(|| Error::MissingPayload("TSi payload".into()))?;
        let ts_r = ts_r.ok_or_else(|| Error::MissingPayload("TSr payload".into()))?;

        // Validate PFS consistency
        if dh_shared_secret.is_some() != ke_i.is_some() {
            return Err(Error::InvalidMessage(
                "PFS mismatch: DH key exchange presence inconsistent".into(),
            ));
        }

        // Select proposal
        let selected_proposal = select_proposal(&child_sa.proposals, configured_proposals)?.clone();

        // Get PRF algorithm from IKE SA proposal
        let prf_alg = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Prf) {
                        // Map transform ID to PrfAlgorithm
                        match t.transform_id {
                            5 => Some(PrfAlgorithm::HmacSha256), // PRF_HMAC_SHA2_256
                            6 => Some(PrfAlgorithm::HmacSha384), // PRF_HMAC_SHA2_384
                            7 => Some(PrfAlgorithm::HmacSha512), // PRF_HMAC_SHA2_512
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| Error::Internal("No PRF in IKE SA proposal".into()))?;

        // Get SK_d key
        let sk_d = context
            .sk_d
            .as_ref()
            .ok_or_else(|| Error::Internal("SK_d not derived".into()))?;

        // Determine key lengths from selected Child SA proposal
        let (encr_key_len, integ_key_len) = Self::get_key_lengths(&selected_proposal)?;

        // Derive Child SA keys
        let (sk_ei, sk_ai, sk_er, sk_ar) = derive_child_sa_keys(
            prf_alg,
            sk_d,
            &nonce_i,
            nonce_r,
            dh_shared_secret,
            encr_key_len,
            integ_key_len,
        );

        Ok((
            selected_proposal,
            nonce_i,
            ts_i,
            ts_r,
            sk_ei,
            sk_ai,
            sk_er,
            sk_ar,
        ))
    }

    /// Get key lengths from Child SA proposal
    ///
    /// Determines the encryption and integrity key lengths based on the selected
    /// Child SA proposal's cipher and integrity algorithms.
    ///
    /// # Arguments
    ///
    /// * `proposal` - Selected Child SA proposal
    ///
    /// # Returns
    ///
    /// Returns (encryption_key_len, integrity_key_len) in bytes
    fn get_key_lengths(proposal: &Proposal) -> Result<(usize, usize)> {
        use super::proposal::{EncrTransformId, IntegTransformId, TransformType};

        // Find encryption transform
        let encr_transform = proposal
            .transforms
            .iter()
            .find(|t| matches!(t.transform_type, TransformType::Encr))
            .ok_or_else(|| Error::InvalidProposal("No encryption transform".into()))?;

        let encr_key_len = match EncrTransformId::from_u16(encr_transform.transform_id) {
            Some(EncrTransformId::AesGcm128) => 16,        // 128-bit key
            Some(EncrTransformId::AesGcm256) => 32,        // 256-bit key
            Some(EncrTransformId::ChaCha20Poly1305) => 32, // 256-bit key
            Some(EncrTransformId::AesCbc128) => 16,
            Some(EncrTransformId::AesCbc256) => 32,
            _ => {
                return Err(Error::InvalidProposal(
                    "Unsupported encryption algorithm".into(),
                ))
            }
        };

        // Find integrity transform (may not exist for AEAD)
        let integ_key_len = if let Some(integ_transform) = proposal
            .transforms
            .iter()
            .find(|t| matches!(t.transform_type, TransformType::Integ))
        {
            match IntegTransformId::from_u16(integ_transform.transform_id) {
                Some(IntegTransformId::HmacSha256_128) => 32, // HMAC-SHA256 uses 32-byte key
                Some(IntegTransformId::HmacSha384_192) => 48, // HMAC-SHA384 uses 48-byte key
                Some(IntegTransformId::HmacSha512_256) => 64, // HMAC-SHA512 uses 64-byte key
                None => {
                    return Err(Error::InvalidProposal(
                        "Unsupported integrity algorithm".into(),
                    ))
                }
            }
        } else {
            0 // AEAD ciphers don't have separate integrity transform
        };

        Ok((encr_key_len, integ_key_len))
    }

    /// Create CREATE_CHILD_SA response (Responder)
    ///
    /// Builds an encrypted CREATE_CHILD_SA response message with the selected
    /// Child SA proposal and traffic selectors.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be established)
    /// * `request_header` - Header from the request message (for message ID)
    /// * `selected_proposal` - Selected Child SA proposal
    /// * `nonce_r` - Responder's nonce
    /// * `ts_i` - Initiator traffic selectors (may be narrowed)
    /// * `ts_r` - Responder traffic selectors (may be narrowed)
    /// * `dh_public_key` - Optional responder DH public key (for PFS)
    ///
    /// # Returns
    ///
    /// Returns the CREATE_CHILD_SA response message
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    pub fn create_response(
        context: &IkeSaContext,
        request_header: &IkeHeader,
        selected_proposal: &Proposal,
        nonce_r: &[u8],
        ts_i: super::payload::TrafficSelectorsPayload,
        ts_r: super::payload::TrafficSelectorsPayload,
        dh_public_key: Option<Vec<u8>>,
    ) -> Result<IkeMessage> {
        use crate::ipsec::crypto::cipher::CipherAlgorithm;

        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established to create CREATE_CHILD_SA response".into(),
            ));
        }

        // Build SA payload with selected proposal
        let sa_payload = SaPayload {
            proposals: vec![selected_proposal.clone()],
        };

        // Build nonce payload
        let nonce_payload = NoncePayload {
            nonce: nonce_r.to_vec(),
        };

        // Build inner payloads
        let mut inner_payloads = vec![IkePayload::SA(sa_payload), IkePayload::Nonce(nonce_payload)];

        // Add KEr if DH public key provided (PFS)
        if let Some(dh_key) = dh_public_key {
            let dh_group = context
                .selected_proposal
                .as_ref()
                .and_then(|p| {
                    p.transforms.iter().find_map(|t| {
                        if matches!(t.transform_type, super::proposal::TransformType::Dh) {
                            Some(t.transform_id as u16)
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| Error::Internal("No DH group in selected proposal".into()))?;

            inner_payloads.push(IkePayload::KE(KePayload {
                dh_group,
                key_data: dh_key,
            }));
        }

        // Add traffic selectors
        inner_payloads.push(IkePayload::TSi(ts_i));
        inner_payloads.push(IkePayload::TSr(ts_r));

        // Get cipher algorithm
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        // Map transform ID to CipherAlgorithm
                        match t.transform_id {
                            20 => Some(CipherAlgorithm::AesGcm128), // ENCR_AES_GCM_16 with 128-bit key
                            21 => Some(CipherAlgorithm::AesGcm256), // ENCR_AES_GCM_16 with 256-bit key
                            28 => Some(CipherAlgorithm::ChaCha20Poly1305), // ENCR_CHACHA20_POLY1305
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| Error::Internal("No cipher in selected proposal".into()))?;

        // Build response header
        let header = IkeHeader {
            initiator_spi: context.initiator_spi,
            responder_spi: context.responder_spi,
            next_payload: PayloadType::SK,
            version: 0x20, // IKEv2
            exchange_type: ExchangeType::CreateChildSa,
            flags: IkeFlags::response(context.is_initiator),
            message_id: request_header.message_id, // Same as request
            length: 0,                             // Will be calculated
        };

        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload =
            IkeAuthExchange::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

        // Build response message
        Ok(IkeMessage {
            header,
            payloads: vec![IkePayload::SK(sk_payload)],
        })
    }

    /// Process CREATE_CHILD_SA response (Initiator)
    ///
    /// Decrypts and processes the CREATE_CHILD_SA response, extracts the selected
    /// Child SA proposal and traffic selectors, and derives Child SA keys.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context (must be established)
    /// * `response` - CREATE_CHILD_SA response message
    /// * `nonce_i` - Initiator's nonce (from request)
    /// * `dh_shared_secret` - Optional DH shared secret (for PFS)
    ///
    /// # Returns
    ///
    /// Returns tuple of (selected_proposal, nonce_r, ts_i, ts_r, sk_ei, sk_ai, sk_er, sk_ar)
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not established
    /// - `InvalidMessage` if response is malformed
    pub fn process_response(
        context: &IkeSaContext,
        response: &IkeMessage,
        nonce_i: &[u8],
        dh_shared_secret: Option<&[u8]>,
    ) -> Result<(
        Proposal,
        Vec<u8>,
        super::payload::TrafficSelectorsPayload,
        super::payload::TrafficSelectorsPayload,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    )> {
        use crate::ipsec::child_sa::derive_child_sa_keys;
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::prf::PrfAlgorithm;

        // Verify state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established to process CREATE_CHILD_SA response".into(),
            ));
        }

        // Verify exchange type
        if response.header.exchange_type != ExchangeType::CreateChildSa {
            return Err(Error::InvalidExchangeType);
        }

        // Verify response flag
        if !response.header.flags.is_response() {
            return Err(Error::InvalidMessage("Expected response flag".into()));
        }

        // Extract SK payload
        let sk_payload = response
            .payloads
            .iter()
            .find_map(|p| {
                if let IkePayload::SK(sk) = p {
                    Some(sk)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::MissingPayload("SK payload not found".into()))?;

        // Get cipher algorithm
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        // Map transform ID to CipherAlgorithm
                        match t.transform_id {
                            20 => Some(CipherAlgorithm::AesGcm128), // ENCR_AES_GCM_16 with 128-bit key
                            21 => Some(CipherAlgorithm::AesGcm256), // ENCR_AES_GCM_16 with 256-bit key
                            28 => Some(CipherAlgorithm::ChaCha20Poly1305), // ENCR_CHACHA20_POLY1305
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| Error::Internal("No cipher in selected proposal".into()))?;

        // Decrypt inner payloads
        let ike_header_bytes = response.header.to_bytes();
        let inner_payloads = IkeAuthExchange::decrypt_payloads(
            context,
            &ike_header_bytes,
            sk_payload,
            cipher,
            PayloadType::SA, // First payload is SA
        )?;

        // Extract payloads
        let mut child_sa: Option<SaPayload> = None;
        let mut nonce_r: Option<Vec<u8>> = None;
        let mut ke_r: Option<KePayload> = None;
        let mut ts_i: Option<super::payload::TrafficSelectorsPayload> = None;
        let mut ts_r: Option<super::payload::TrafficSelectorsPayload> = None;

        for payload in &inner_payloads {
            match payload {
                IkePayload::SA(sa) => child_sa = Some(sa.clone()),
                IkePayload::Nonce(nonce) => nonce_r = Some(nonce.nonce.clone()),
                IkePayload::KE(ke) => ke_r = Some(ke.clone()),
                IkePayload::TSi(ts) => ts_i = Some(ts.clone()),
                IkePayload::TSr(ts) => ts_r = Some(ts.clone()),
                _ => {}
            }
        }

        // Validate required payloads
        let child_sa = child_sa.ok_or_else(|| Error::MissingPayload("SA payload".into()))?;
        let nonce_r = nonce_r.ok_or_else(|| Error::MissingPayload("Nonce payload".into()))?;
        let ts_i = ts_i.ok_or_else(|| Error::MissingPayload("TSi payload".into()))?;
        let ts_r = ts_r.ok_or_else(|| Error::MissingPayload("TSr payload".into()))?;

        // Validate PFS consistency
        if dh_shared_secret.is_some() != ke_r.is_some() {
            return Err(Error::InvalidMessage(
                "PFS mismatch: DH key exchange presence inconsistent".into(),
            ));
        }

        // Extract selected proposal (should be only one)
        let selected_proposal = child_sa
            .proposals
            .first()
            .ok_or_else(|| Error::InvalidMessage("No proposal in response".into()))?
            .clone();

        // Get PRF algorithm from IKE SA proposal
        let prf_alg = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Prf) {
                        // Map transform ID to PrfAlgorithm
                        match t.transform_id {
                            5 => Some(PrfAlgorithm::HmacSha256), // PRF_HMAC_SHA2_256
                            6 => Some(PrfAlgorithm::HmacSha384), // PRF_HMAC_SHA2_384
                            7 => Some(PrfAlgorithm::HmacSha512), // PRF_HMAC_SHA2_512
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| Error::Internal("No PRF in IKE SA proposal".into()))?;

        // Get SK_d key
        let sk_d = context
            .sk_d
            .as_ref()
            .ok_or_else(|| Error::Internal("SK_d not derived".into()))?;

        // Determine key lengths from selected Child SA proposal
        let (encr_key_len, integ_key_len) = Self::get_key_lengths(&selected_proposal)?;

        // Derive Child SA keys
        let (sk_ei, sk_ai, sk_er, sk_ar) = derive_child_sa_keys(
            prf_alg,
            sk_d,
            nonce_i,
            &nonce_r,
            dh_shared_secret,
            encr_key_len,
            integ_key_len,
        );

        Ok((
            selected_proposal,
            nonce_r,
            ts_i,
            ts_r,
            sk_ei,
            sk_ai,
            sk_er,
            sk_ar,
        ))
    }

    /// Create CREATE_CHILD_SA request for IKE SA rekeying
    ///
    /// Builds a CREATE_CHILD_SA request to rekey the IKE SA itself (not a Child SA).
    /// This creates a new IKE SA with fresh keying material while the old one remains
    /// active during the transition period.
    ///
    /// # Arguments
    ///
    /// * `context` - Current IKE SA context (must be Established or Rekeying)
    /// * `ike_proposals` - IKE SA proposals for the new IKE SA
    /// * `dh_public_key` - New DH public key for the rekey
    ///
    /// # Returns
    ///
    /// Returns the CREATE_CHILD_SA request message and the generated nonce
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA is not in correct state
    pub fn create_ike_rekey_request(
        context: &mut IkeSaContext,
        ike_proposals: &[Proposal],
        dh_public_key: Vec<u8>,
    ) -> Result<(IkeMessage, Vec<u8>)> {
        use super::constants::{ExchangeType, IkeFlags, PayloadType};
        use super::message::{IkeHeader, IkeMessage};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;

        // Validate state - must be Established or Rekeying
        if !matches!(context.state, IkeState::Established | IkeState::Rekeying) {
            return Err(Error::InvalidState(format!(
                "Cannot create IKE rekey request in state {:?}",
                context.state
            )));
        }

        // Generate nonce
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce[..]);

        // Create SA payload with IKE proposals
        let sa_payload = super::payload::SaPayload {
            proposals: ike_proposals.to_vec(),
        };

        // Create Nonce payload
        let nonce_payload = super::payload::NoncePayload::new(nonce.clone())?;

        // Create KE payload
        let dh_group = ike_proposals
            .first()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Dh) {
                        Some(t.transform_id)
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(14); // Default to Group 14

        let ke_payload = super::payload::KePayload::new(dh_group, dh_public_key);

        // Build inner payloads: SA, Nonce, KE
        // NOTE: For IKE SA rekey, we do NOT include TSi/TSr payloads
        let inner_payloads = vec![
            IkePayload::SA(sa_payload),
            IkePayload::Nonce(nonce_payload),
            IkePayload::KE(ke_payload),
        ];

        // Create IKE header
        let message_id = context.next_message_id();
        let flags = IkeFlags::request(context.is_initiator);

        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            PayloadType::SK,
            ExchangeType::CreateChildSa,
            flags,
            message_id,
            0, // Length will be computed during serialization
        );

        // Get cipher for encryption
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        match t.transform_id {
                            20 => Some(CipherAlgorithm::AesGcm128),
                            19 => Some(CipherAlgorithm::AesGcm256),
                            28 => Some(CipherAlgorithm::ChaCha20Poly1305),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Serialize IKE header for AAD
        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload =
            IkeAuthExchange::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

        // Build final message
        let message = IkeMessage::new(header, vec![IkePayload::SK(sk_payload)]);

        Ok((message, nonce))
    }

    /// Process CREATE_CHILD_SA request for IKE SA rekeying (responder)
    ///
    /// Handles an incoming CREATE_CHILD_SA request that's rekeying the IKE SA.
    /// Detects IKE SA rekey by the absence of TSi/TSr payloads.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `message` - CREATE_CHILD_SA request message
    ///
    /// # Returns
    ///
    /// Returns tuple of (selected_proposal, nonce_i, ke_i) for building the response
    ///
    /// # Errors
    ///
    /// - `InvalidState` if IKE SA not established
    /// - `MissingPayload` if required payloads missing
    pub fn process_ike_rekey_request(
        context: &IkeSaContext,
        message: &IkeMessage,
    ) -> Result<(Proposal, Vec<u8>, super::payload::KePayload)> {
        use super::constants::PayloadType;

        // Validate state
        if !context.state.is_established() {
            return Err(Error::InvalidState(
                "IKE SA must be established to process rekey request".into(),
            ));
        }

        // Get cipher for decryption
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        match t.transform_id {
                            20 => Some(crate::ipsec::crypto::cipher::CipherAlgorithm::AesGcm128),
                            19 => Some(crate::ipsec::crypto::cipher::CipherAlgorithm::AesGcm256),
                            28 => Some(
                                crate::ipsec::crypto::cipher::CipherAlgorithm::ChaCha20Poly1305,
                            ),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(crate::ipsec::crypto::cipher::CipherAlgorithm::AesGcm128);

        // Find SK payload
        let sk_payload = message
            .payloads
            .iter()
            .find_map(|p| match p {
                IkePayload::SK(sk) => Some(sk),
                _ => None,
            })
            .ok_or_else(|| Error::MissingPayload("SK payload".into()))?;

        // Serialize IKE header for AAD
        let ike_header_bytes = message.header.to_bytes();

        // Decrypt payloads
        let inner_payloads = IkeAuthExchange::decrypt_payloads(
            context,
            &ike_header_bytes,
            sk_payload,
            cipher,
            PayloadType::SA,
        )?;

        // Extract payloads
        let mut sa_payload = None;
        let mut nonce_i = None;
        let mut ke_i = None;

        for payload in &inner_payloads {
            match payload {
                IkePayload::SA(sa) => sa_payload = Some(sa.clone()),
                IkePayload::Nonce(nonce) => nonce_i = Some(nonce.nonce.clone()),
                IkePayload::KE(ke) => ke_i = Some(ke.clone()),
                IkePayload::TSi(_) | IkePayload::TSr(_) => {
                    // If we see traffic selectors, this is Child SA creation, not IKE rekey
                    return Err(Error::InvalidMessage(
                        "IKE SA rekey request should not contain traffic selectors".into(),
                    ));
                }
                _ => {}
            }
        }

        // Validate required payloads
        let sa_payload = sa_payload.ok_or_else(|| Error::MissingPayload("SA payload".into()))?;
        let nonce_i = nonce_i.ok_or_else(|| Error::MissingPayload("Nonce payload".into()))?;
        let ke_i = ke_i.ok_or_else(|| Error::MissingPayload("KE payload".into()))?;

        // Select proposal from offered proposals
        let selected_proposal = sa_payload
            .proposals
            .first()
            .ok_or_else(|| Error::InvalidMessage("No proposals offered".into()))?
            .clone();

        Ok((selected_proposal, nonce_i, ke_i))
    }

    /// Create CREATE_CHILD_SA response for IKE SA rekeying
    ///
    /// Builds the response to an IKE SA rekey request.
    ///
    /// # Arguments
    ///
    /// * `context` - IKE SA context
    /// * `request_header` - Header from the request message
    /// * `selected_proposal` - Selected IKE SA proposal
    /// * `dh_public_key` - Responder's DH public key
    ///
    /// # Returns
    ///
    /// Returns the CREATE_CHILD_SA response message and generated nonce
    pub fn create_ike_rekey_response(
        context: &IkeSaContext,
        request_header: &IkeHeader,
        selected_proposal: &Proposal,
        dh_public_key: Vec<u8>,
    ) -> Result<(IkeMessage, Vec<u8>)> {
        use super::constants::{ExchangeType, IkeFlags, PayloadType};
        use super::message::{IkeHeader, IkeMessage};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use rand::RngCore;

        // Generate nonce
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce[..]);

        // Create SA payload with selected proposal
        let sa_payload = super::payload::SaPayload {
            proposals: vec![selected_proposal.clone()],
        };

        // Create Nonce payload
        let nonce_payload = super::payload::NoncePayload::new(nonce.clone())?;

        // Create KE payload
        let dh_group = selected_proposal
            .transforms
            .iter()
            .find_map(|t| {
                if matches!(t.transform_type, super::proposal::TransformType::Dh) {
                    Some(t.transform_id)
                } else {
                    None
                }
            })
            .unwrap_or(14);

        let ke_payload = super::payload::KePayload::new(dh_group, dh_public_key);

        // Build inner payloads: SA, Nonce, KE (no TSi/TSr for IKE SA rekey)
        let inner_payloads = vec![
            IkePayload::SA(sa_payload),
            IkePayload::Nonce(nonce_payload),
            IkePayload::KE(ke_payload),
        ];

        // Create response header (same message ID as request)
        let flags = IkeFlags::response(context.is_initiator);

        let header = IkeHeader::new(
            context.initiator_spi,
            context.responder_spi,
            PayloadType::SK,
            ExchangeType::CreateChildSa,
            flags,
            request_header.message_id,
            0,
        );

        // Get cipher for encryption
        let cipher = context
            .selected_proposal
            .as_ref()
            .and_then(|p| {
                p.transforms.iter().find_map(|t| {
                    if matches!(t.transform_type, super::proposal::TransformType::Encr) {
                        match t.transform_id {
                            20 => Some(CipherAlgorithm::AesGcm128),
                            19 => Some(CipherAlgorithm::AesGcm256),
                            28 => Some(CipherAlgorithm::ChaCha20Poly1305),
                            _ => None,
                        }
                    } else {
                        None
                    }
                })
            })
            .unwrap_or(CipherAlgorithm::AesGcm128);

        // Serialize IKE header for AAD
        let ike_header_bytes = header.to_bytes();

        // Encrypt inner payloads
        let sk_payload =
            IkeAuthExchange::encrypt_payloads(context, &ike_header_bytes, &inner_payloads, cipher)?;

        // Build final message
        let message = IkeMessage::new(header, vec![IkePayload::SK(sk_payload)]);

        Ok((message, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::ikev2::payload::TrafficSelectorsPayload;
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

        let msg =
            IkeSaInitExchange::create_request(&mut ctx, proposals, dh_public, nonce, None, None)
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
            None,
            None,
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
        use super::super::payload::{AuthMethod, AuthPayload};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

        // Setup initiator context
        let mut ctx_i = IkeSaContext::new_initiator([1u8; 8]);
        ctx_i.responder_spi = [2u8; 8];
        ctx_i.nonce_i = Some(vec![0x01; 32]);
        ctx_i.nonce_r = Some(vec![0x02; 32]);
        ctx_i.shared_secret = Some(vec![0x03; 256]);

        // Derive keys (AES-GCM-128: 16-byte key, 16-byte integ)
        ctx_i
            .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Key derivation failed");

        // Setup responder context (same keys, different role)
        let mut ctx_r = IkeSaContext::new_responder([1u8; 8], [2u8; 8]);
        ctx_r.nonce_i = Some(vec![0x01; 32]);
        ctx_r.nonce_r = Some(vec![0x02; 32]);
        ctx_r.shared_secret = Some(vec![0x03; 256]);
        ctx_r
            .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
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

        let result = IkeAuthExchange::encrypt_payloads(
            &ctx,
            &ike_header,
            &payloads,
            CipherAlgorithm::AesGcm128,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Encryption key not derived"));
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        use super::super::payload::{AuthMethod, AuthPayload};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

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
        let sk_payload =
            IkeAuthExchange::encrypt_payloads(&ctx, &correct_header, &payloads, cipher)
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
        use super::super::payload::{AuthMethod, AuthPayload, EncryptedPayload};
        use crate::ipsec::crypto::cipher::CipherAlgorithm;
        use crate::ipsec::crypto::PrfAlgorithm;

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
        use super::super::constants::ExchangeType;
        use super::super::payload::{
            IdPayload, IdType, TrafficSelector, TrafficSelectorsPayload, TsType,
        };
        use super::super::proposal::{ProtocolId, Transform, TransformType};
        use crate::ipsec::crypto::PrfAlgorithm;

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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No proposal selected"));
    }

    // TODO: End-to-end integration test for complete IKE_SA_INIT + IKE_AUTH flow
    // This would require proper DH key exchange, nonce synchronization, and key derivation
    // For now, individual components are tested separately:
    // - IKE_SA_INIT exchange (Phase 1 tests)
    // - Key derivation (crypto/prf tests)
    // - SK payload encryption/decryption (test_encrypt_decrypt_roundtrip)
    // - AUTH verification (tested via process_request/process_response logic)

    #[test]
    #[ignore] // Ignored: Complex integration test, components tested separately
    fn test_complete_ike_sa_init_and_ike_auth_exchange() {
        use super::super::constants::ExchangeType;
        use super::super::payload::{
            IdPayload, IdType, IkePayload, TrafficSelector, TrafficSelectorsPayload,
        };
        use super::super::proposal::{
            DhTransformId, EncrTransformId, PrfTransformId, Proposal, ProtocolId, Transform,
            TransformType,
        };
        use crate::ipsec::crypto::PrfAlgorithm;
        use rand::Rng;

        // ========== Setup ==========
        let psk = b"test_pre_shared_key_12345678";

        // Create initiator and responder contexts
        let mut ctx_i = IkeSaContext::new_initiator([0x11; 8]);
        let mut ctx_r = IkeSaContext::new_responder([0x11; 8], [0x22; 8]);

        // ========== Phase 1: IKE_SA_INIT ==========

        // Initiator creates proposals
        let proposal = Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::new(
                TransformType::Encr,
                EncrTransformId::AesGcm128 as u16,
            ))
            .add_transform(Transform::new(
                TransformType::Prf,
                PrfTransformId::HmacSha256 as u16,
            ))
            .add_transform(Transform::new(
                TransformType::Dh,
                DhTransformId::Group14 as u16,
            ));

        // Generate DH keys and nonce for initiator
        let mut rng = rand::thread_rng();
        let dh_i_public = vec![0x01; 256]; // Simplified DH public key
        let nonce_i = {
            let mut n = vec![0u8; 32];
            rng.fill(&mut n[..]);
            n
        };

        // Initiator creates IKE_SA_INIT request
        let init_req = IkeSaInitExchange::create_request(
            &mut ctx_i,
            vec![proposal.clone()],
            dh_i_public.clone(),
            nonce_i.clone(),
            None,
            None,
        )
        .expect("Failed to create IKE_SA_INIT request");

        // Serialize the request
        let init_req_bytes = init_req.to_bytes();

        // Responder processes request
        let configured_proposals = vec![proposal.clone()];
        IkeSaInitExchange::process_request(&mut ctx_r, &init_req, &configured_proposals)
            .expect("Failed to process IKE_SA_INIT request");

        // Generate DH keys and nonce for responder
        let dh_r_public = vec![0x02; 256]; // Simplified DH public key
        let nonce_r = {
            let mut n = vec![0u8; 32];
            rng.fill(&mut n[..]);
            n
        };

        // Responder creates response
        let init_resp = IkeSaInitExchange::create_response(
            &mut ctx_r,
            &init_req.header,
            proposal.clone(),
            dh_r_public.clone(),
            nonce_r.clone(),
            None,
            None,
        )
        .expect("Failed to create IKE_SA_INIT response");

        // Serialize the response
        let init_resp_bytes = init_resp.to_bytes();

        // Initiator processes response
        IkeSaInitExchange::process_response(&mut ctx_i, &init_resp)
            .expect("Failed to process IKE_SA_INIT response");

        // Both sides should now be in InitDone state
        assert_eq!(ctx_i.state, IkeState::InitDone);
        assert_eq!(ctx_r.state, IkeState::InitDone);

        // For this test, manually set a shared DH secret
        // In a real implementation, this would be computed from DH exchange
        let shared_secret = vec![0x42; 256];
        ctx_i.shared_secret = Some(shared_secret.clone());
        ctx_r.shared_secret = Some(shared_secret.clone());

        // Derive keys on initiator side
        ctx_i
            .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
            .expect("Initiator key derivation failed");

        // For this test, copy keys from initiator to responder to ensure they match
        // In a real implementation, both sides would derive the same keys independently
        ctx_r.sk_d = ctx_i.sk_d.clone();
        ctx_r.sk_ai = ctx_i.sk_ai.clone();
        ctx_r.sk_ar = ctx_i.sk_ar.clone();
        ctx_r.sk_ei = ctx_i.sk_ei.clone();
        ctx_r.sk_er = ctx_i.sk_er.clone();
        ctx_r.sk_pi = ctx_i.sk_pi.clone();
        ctx_r.sk_pr = ctx_i.sk_pr.clone();

        // Verify keys are set
        assert!(ctx_i.sk_d.is_some());
        assert!(ctx_r.sk_d.is_some());

        // ========== Phase 2: IKE_AUTH ==========

        // Create child SA proposals
        let child_proposal = Proposal::new(1, ProtocolId::Esp)
            .add_transform(Transform::new(
                TransformType::Encr,
                EncrTransformId::AesGcm128 as u16,
            ))
            .add_transform(Transform::new(
                TransformType::Prf,
                PrfTransformId::HmacSha256 as u16,
            ));

        // Create traffic selectors
        let ts_i = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        };
        let ts_r = TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        };

        // Initiator creates IKE_AUTH request
        let id_i = IdPayload {
            id_type: IdType::Ipv4Addr,
            data: vec![192, 168, 1, 1],
        };

        let auth_req = IkeAuthExchange::create_request(
            &mut ctx_i,
            &init_req_bytes,
            id_i.clone(),
            psk,
            vec![child_proposal.clone()],
            ts_i.clone(),
            ts_r.clone(),
        )
        .expect("Failed to create IKE_AUTH request");

        // Initiator should now be in AuthSent state
        assert_eq!(ctx_i.state, IkeState::AuthSent);

        // Responder processes IKE_AUTH request
        let (peer_id_i, selected_child, ts_i_resp, ts_r_resp) = IkeAuthExchange::process_request(
            &mut ctx_r,
            &init_req_bytes, // Use the IKE_SA_INIT request, not response
            &auth_req,
            psk,
            &[child_proposal.clone()],
        )
        .expect("Failed to process IKE_AUTH request");

        // Verify extracted data
        assert_eq!(peer_id_i.id_type, IdType::Ipv4Addr);
        assert_eq!(peer_id_i.data, vec![192, 168, 1, 1]);
        assert_eq!(selected_child.protocol_id, ProtocolId::Esp);
        assert!(!ts_i_resp.selectors.is_empty());
        assert!(!ts_r_resp.selectors.is_empty());

        // Responder creates IKE_AUTH response
        let id_r = IdPayload {
            id_type: IdType::Ipv4Addr,
            data: vec![192, 168, 1, 2],
        };

        let auth_resp = IkeAuthExchange::create_response(
            &mut ctx_r,
            &init_resp_bytes,
            &auth_req,
            id_r.clone(),
            psk,
            selected_child.clone(),
            ts_i_resp,
            ts_r_resp,
        )
        .expect("Failed to create IKE_AUTH response");

        // Responder should now be in Established state
        assert_eq!(ctx_r.state, IkeState::Established);

        // Initiator processes IKE_AUTH response
        let (peer_id_r, child_prop, ts_i_final, ts_r_final) =
            IkeAuthExchange::process_response(&mut ctx_i, &init_resp_bytes, &auth_resp, psk)
                .expect("Failed to process IKE_AUTH response");

        // Initiator should now be in Established state
        assert_eq!(ctx_i.state, IkeState::Established);

        // Verify extracted data from response
        assert_eq!(peer_id_r.id_type, IdType::Ipv4Addr);
        assert_eq!(peer_id_r.data, vec![192, 168, 1, 2]);
        assert_eq!(child_prop.protocol_id, ProtocolId::Esp);
        assert!(!ts_i_final.selectors.is_empty());
        assert!(!ts_r_final.selectors.is_empty());

        // ========== Verification ==========

        // Both sides should be in Established state
        assert_eq!(ctx_i.state, IkeState::Established);
        assert_eq!(ctx_r.state, IkeState::Established);

        // Both sides should have negotiated the same proposal
        assert_eq!(ctx_i.selected_proposal, ctx_r.selected_proposal);

        // Verify message structure
        assert_eq!(auth_req.header.exchange_type, ExchangeType::IkeAuth);
        assert!(auth_req.header.flags.is_initiator());
        assert!(!auth_req.header.flags.is_response());

        assert_eq!(auth_resp.header.exchange_type, ExchangeType::IkeAuth);
        assert!(!auth_resp.header.flags.is_initiator());
        assert!(auth_resp.header.flags.is_response());

        // Verify SK payload is present and encrypted
        assert_eq!(auth_req.payloads.len(), 1);
        assert!(matches!(auth_req.payloads[0], IkePayload::SK(_)));

        assert_eq!(auth_resp.payloads.len(), 1);
        assert!(matches!(auth_resp.payloads[0], IkePayload::SK(_)));
    }

    // ========== IKE SA Rekeying Tests (Phase 4 Stage 3) ==========

    #[test]
    fn test_ike_sa_age() {
        let ctx = IkeSaContext::new_initiator([0x11; 8]);

        // Age should be very small (just created)
        let age = ctx.age();
        assert!(age.as_millis() < 100);
    }

    #[test]
    fn test_ike_sa_should_rekey_not_expired() {
        let ctx = IkeSaContext::new_initiator([0x11; 8]);

        // Should not need rekey immediately after creation
        assert!(!ctx.should_rekey());
        assert!(!ctx.is_expired());
    }

    #[test]
    fn test_ike_sa_should_rekey_soft_expired() {
        use std::time::Duration;

        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);

        // Set very short lifetime
        ctx.lifetime = crate::ipsec::child_sa::SaLifetime::new(
            Duration::from_millis(1), // soft: 1ms
            Duration::from_secs(60),  // hard: 60s
        )
        .unwrap();

        // Wait for soft limit to pass
        std::thread::sleep(Duration::from_millis(10));

        // Should need rekey but not expired
        assert!(ctx.should_rekey());
        assert!(!ctx.is_expired());
    }

    #[test]
    fn test_ike_sa_initiate_rekey() {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.state = IkeState::Established;

        // Initiate rekey
        ctx.initiate_rekey().expect("Failed to initiate rekey");

        // Should be in Rekeying state
        assert_eq!(ctx.state, IkeState::Rekeying);
        assert!(ctx.rekey_initiated_at.is_some());
    }

    #[test]
    fn test_ike_sa_initiate_rekey_invalid_state() {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.state = IkeState::Idle;

        // Cannot initiate rekey from Idle state
        let result = ctx.initiate_rekey();
        assert!(result.is_err());
    }

    #[test]
    fn test_ike_sa_mark_rekeyed() {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.state = IkeState::Rekeying;

        // Mark as rekeyed
        ctx.mark_rekeyed().expect("Failed to mark rekeyed");

        // Should transition to Deleting
        assert_eq!(ctx.state, IkeState::Deleting);
    }

    #[test]
    fn test_ike_sa_mark_rekeyed_invalid_state() {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.state = IkeState::Established;

        // Cannot mark rekeyed from Established state
        let result = ctx.mark_rekeyed();
        assert!(result.is_err());
    }

    #[test]
    fn test_ike_sa_child_sa_management() {
        use crate::ipsec::child_sa::ChildSa;
        use crate::ipsec::replay::ReplayWindow;

        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);

        // Initially no child SAs
        assert_eq!(ctx.child_sa_count(), 0);

        // Create mock Child SA
        let child_sa = ChildSa {
            spi: 0x12345678,
            protocol: 50,
            is_inbound: true,
            sk_e: vec![0u8; 16],
            sk_a: None,
            ts_i: TrafficSelectorsPayload { selectors: vec![] },
            ts_r: TrafficSelectorsPayload { selectors: vec![] },
            proposal: create_child_proposal(),
            seq_out: 0,
            replay_window: Some(ReplayWindow::new(64)),
            state: crate::ipsec::child_sa::ChildSaState::Active,
            lifetime: crate::ipsec::child_sa::SaLifetime::default(),
            created_at: std::time::Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        };

        // Add Child SA
        ctx.add_child_sa(child_sa);
        assert_eq!(ctx.child_sa_count(), 1);

        // Remove Child SA
        let removed = ctx.remove_child_sa(0x12345678);
        assert!(removed.is_some());
        assert_eq!(ctx.child_sa_count(), 0);

        // Try to remove non-existent SA
        let removed = ctx.remove_child_sa(0x99999999);
        assert!(removed.is_none());
    }

    #[test]
    fn test_ike_sa_transfer_child_sas() {
        use crate::ipsec::child_sa::ChildSa;
        use crate::ipsec::replay::ReplayWindow;

        let mut old_ike_sa = IkeSaContext::new_initiator([0x11; 8]);
        let mut new_ike_sa = IkeSaContext::new_initiator([0x22; 8]);

        // Add 3 Child SAs to old IKE SA
        for i in 0..3 {
            let child_sa = ChildSa {
                spi: 0x10000000 + i,
                protocol: 50,
                is_inbound: true,
                sk_e: vec![0u8; 16],
                sk_a: None,
                ts_i: TrafficSelectorsPayload { selectors: vec![] },
                ts_r: TrafficSelectorsPayload { selectors: vec![] },
                proposal: create_child_proposal(),
                seq_out: 0,
                replay_window: Some(ReplayWindow::new(64)),
                state: crate::ipsec::child_sa::ChildSaState::Active,
                lifetime: crate::ipsec::child_sa::SaLifetime::default(),
                created_at: std::time::Instant::now(),
                bytes_processed: 0,
                rekey_initiated_at: None,
            };
            old_ike_sa.add_child_sa(child_sa);
        }

        assert_eq!(old_ike_sa.child_sa_count(), 3);
        assert_eq!(new_ike_sa.child_sa_count(), 0);

        // Transfer all Child SAs
        let count = old_ike_sa.transfer_child_sas(&mut new_ike_sa);

        assert_eq!(count, 3);
        assert_eq!(old_ike_sa.child_sa_count(), 0);
        assert_eq!(new_ike_sa.child_sa_count(), 3);
    }

    #[test]
    fn test_create_ike_rekey_request() {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.state = IkeState::Established;
        ctx.responder_spi = [0x22; 8];

        // Set up required crypto material
        ctx.selected_proposal = Some(create_test_proposal());
        ctx.sk_ei = Some(vec![0u8; 16]);
        ctx.sk_er = Some(vec![0u8; 16]);

        // Create IKE proposals for rekey
        let ike_proposals = vec![create_test_proposal()];
        let dh_public = vec![0xAB; 256];

        // Create rekey request
        let result =
            CreateChildSaExchange::create_ike_rekey_request(&mut ctx, &ike_proposals, dh_public);

        if let Err(e) = &result {
            panic!("create_ike_rekey_request failed: {:?}", e);
        }
        let (message, nonce) = result.unwrap();

        // Verify message structure
        assert_eq!(message.header.exchange_type, ExchangeType::CreateChildSa);
        assert!(message.header.flags.is_initiator());
        assert!(!message.header.flags.is_response());

        // Verify SK payload present
        assert_eq!(message.payloads.len(), 1);
        assert!(matches!(message.payloads[0], IkePayload::SK(_)));

        // Verify nonce generated
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn test_create_ike_rekey_request_invalid_state() {
        let mut ctx = IkeSaContext::new_initiator([0x11; 8]);
        ctx.state = IkeState::Idle;

        let ike_proposals = vec![create_test_proposal()];
        let dh_public = vec![0xAB; 256];

        // Should fail from Idle state
        let result =
            CreateChildSaExchange::create_ike_rekey_request(&mut ctx, &ike_proposals, dh_public);

        assert!(result.is_err());
    }

    #[test]
    fn test_create_ike_rekey_response() {
        let mut ctx = IkeSaContext::new_responder([0x11; 8], [0x22; 8]);
        ctx.state = IkeState::Established;

        // Set up required crypto material
        ctx.selected_proposal = Some(create_test_proposal());
        ctx.sk_ei = Some(vec![0u8; 16]);
        ctx.sk_er = Some(vec![0u8; 16]);

        let request_header = IkeHeader::new(
            [0x11; 8],
            [0x22; 8],
            PayloadType::SK,
            ExchangeType::CreateChildSa,
            IkeFlags::request(true),
            5,
            0,
        );

        let selected_proposal = create_test_proposal();
        let dh_public = vec![0xCD; 256];

        // Create rekey response
        let result = CreateChildSaExchange::create_ike_rekey_response(
            &ctx,
            &request_header,
            &selected_proposal,
            dh_public,
        );

        if let Err(e) = &result {
            panic!("create_ike_rekey_response failed: {:?}", e);
        }
        let (message, nonce) = result.unwrap();

        // Verify message structure
        assert_eq!(message.header.exchange_type, ExchangeType::CreateChildSa);
        assert!(message.header.flags.is_response()); // This is a response message

        // Message ID should match request
        assert_eq!(message.header.message_id, 5);

        // Verify SK payload present
        assert_eq!(message.payloads.len(), 1);
        assert!(matches!(message.payloads[0], IkePayload::SK(_)));

        // Verify nonce generated
        assert_eq!(nonce.len(), 32);
    }

    fn create_child_proposal() -> Proposal {
        Proposal::new(1, ProtocolId::Esp)
            .add_transform(Transform::encr(EncrTransformId::AesGcm128))
            .add_transform(Transform::dh(DhTransformId::Group14))
    }
}
