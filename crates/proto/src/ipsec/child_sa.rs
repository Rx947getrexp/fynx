//! Child SA (Security Association) management
//!
//! Implements Child SA structures and lifecycle management as defined in RFC 7296.
//!
//! # Child SA Overview
//!
//! Child SAs are created by the CREATE_CHILD_SA exchange and are used to protect
//! actual data traffic with ESP (Encapsulating Security Payload). Each Child SA
//! represents a unidirectional security association with its own:
//!
//! - SPI (Security Parameters Index)
//! - Encryption and authentication keys
//! - Traffic selectors (which traffic this SA protects)
//! - Sequence number tracking (for anti-replay)
//! - Lifetime limits (time and byte-based)
//!
//! # Key Derivation
//!
//! Child SA keys are derived from the IKE SA's SK_d key using the formula:
//!
//! ```text
//! KEYMAT = prf+(SK_d, Ni | Nr)
//!
//! For PFS (Perfect Forward Secrecy):
//! KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)
//!
//! Key split:
//! SK_ei | SK_ai | SK_er | SK_ar = KEYMAT
//! ```

use crate::ipsec::{
    crypto::prf::PrfAlgorithm,
    ikev2::{payload::TrafficSelectorsPayload, proposal::Proposal},
    replay::ReplayWindow,
    Error, Result,
};
use std::time::{Duration, Instant};

/// Child SA State
///
/// Tracks the current state of a Child SA in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildSaState {
    /// SA is active and can be used for traffic
    Active,

    /// SA is being rekeyed (new SA is being created)
    ///
    /// During rekeying, both old and new SAs can be used simultaneously
    /// for a brief overlap period to ensure seamless transition.
    Rekeying,

    /// SA has been rekeyed and should be deleted
    ///
    /// The new SA is now active, and this old SA is waiting for
    /// graceful deletion after ensuring no more packets are in flight.
    Rekeyed,

    /// SA has expired and must be deleted immediately
    Expired,

    /// SA has been deleted
    Deleted,
}

/// Child Security Association
///
/// Represents a unidirectional ESP Security Association used to protect
/// data traffic. Each Child SA pair (inbound + outbound) is created by
/// a CREATE_CHILD_SA exchange.
#[derive(Debug, Clone)]
pub struct ChildSa {
    /// Security Parameters Index (SPI)
    ///
    /// 32-bit unique identifier for this SA. Used in ESP packet header
    /// to identify which SA should be used for decryption.
    pub spi: u32,

    /// Protocol (always 50 for ESP)
    pub protocol: u8,

    /// Is this an inbound SA (receiving) or outbound SA (sending)?
    pub is_inbound: bool,

    /// Encryption key (SK_e)
    pub sk_e: Vec<u8>,

    /// Authentication key (SK_a) - None for AEAD ciphers
    pub sk_a: Option<Vec<u8>>,

    /// Traffic selectors (initiator)
    ///
    /// Specifies which source addresses/ports this SA protects
    pub ts_i: TrafficSelectorsPayload,

    /// Traffic selectors (responder)
    ///
    /// Specifies which destination addresses/ports this SA protects
    pub ts_r: TrafficSelectorsPayload,

    /// Selected proposal
    ///
    /// Contains the negotiated cipher, integrity, and DH group
    pub proposal: Proposal,

    /// Sequence number (outbound only)
    ///
    /// Incremented for each outbound packet. Used for anti-replay protection.
    pub seq_out: u64,

    /// Anti-replay window (inbound only)
    ///
    /// Tracks received sequence numbers to detect and reject replay attacks.
    /// Only used for inbound SAs. None for outbound SAs.
    pub replay_window: Option<ReplayWindow>,

    /// Current state of this SA
    pub state: ChildSaState,

    /// Lifetime configuration
    pub lifetime: SaLifetime,

    /// Creation timestamp
    pub created_at: Instant,

    /// Byte count (for byte-based lifetime limits)
    pub bytes_processed: u64,

    /// Timestamp when rekeying was initiated (None if not rekeying)
    pub rekey_initiated_at: Option<Instant>,
}

/// SA Lifetime limits
///
/// Defines when an SA should be rekeyed (soft limit) and when it must
/// be deleted (hard limit). Both time-based and byte-based limits are supported.
#[derive(Debug, Clone, Copy)]
pub struct SaLifetime {
    /// Soft time limit - initiate rekey when reached
    ///
    /// Typical value: 75% of hard limit (e.g., 75 minutes for 100 minute hard limit)
    pub soft_time: Duration,

    /// Hard time limit - delete SA when reached
    ///
    /// Typical values: 60-120 minutes
    pub hard_time: Duration,

    /// Soft byte limit - initiate rekey when reached (optional)
    ///
    /// Typical value: 75% of hard limit (e.g., 750 MB for 1 GB hard limit)
    pub soft_bytes: Option<u64>,

    /// Hard byte limit - delete SA when reached (optional)
    ///
    /// Typical values: 100 MB - 1 GB
    pub hard_bytes: Option<u64>,
}

impl Default for SaLifetime {
    /// Create default lifetime (1 hour hard, 45 minutes soft)
    fn default() -> Self {
        SaLifetime {
            soft_time: Duration::from_secs(45 * 60), // 45 minutes
            hard_time: Duration::from_secs(60 * 60), // 60 minutes
            soft_bytes: None,
            hard_bytes: None,
        }
    }
}

impl SaLifetime {
    /// Create custom lifetime with time limits
    pub fn new(soft_time: Duration, hard_time: Duration) -> Result<Self> {
        if soft_time >= hard_time {
            return Err(Error::InvalidParameter(
                "Soft lifetime must be less than hard lifetime".into(),
            ));
        }

        Ok(SaLifetime {
            soft_time,
            hard_time,
            soft_bytes: None,
            hard_bytes: None,
        })
    }

    /// Add byte-based lifetime limits
    pub fn with_byte_limits(mut self, soft_bytes: u64, hard_bytes: u64) -> Result<Self> {
        if soft_bytes >= hard_bytes {
            return Err(Error::InvalidParameter(
                "Soft byte limit must be less than hard byte limit".into(),
            ));
        }

        self.soft_bytes = Some(soft_bytes);
        self.hard_bytes = Some(hard_bytes);
        Ok(self)
    }

    /// Check if soft lifetime has been exceeded
    pub fn is_soft_expired(&self, age: Duration, bytes: u64) -> bool {
        // Time-based check
        if age >= self.soft_time {
            return true;
        }

        // Byte-based check
        if let Some(soft_bytes) = self.soft_bytes {
            if bytes >= soft_bytes {
                return true;
            }
        }

        false
    }

    /// Check if hard lifetime has been exceeded
    pub fn is_hard_expired(&self, age: Duration, bytes: u64) -> bool {
        // Time-based check
        if age >= self.hard_time {
            return true;
        }

        // Byte-based check
        if let Some(hard_bytes) = self.hard_bytes {
            if bytes >= hard_bytes {
                return true;
            }
        }

        false
    }
}

impl ChildSa {
    /// Create new Child SA
    ///
    /// # Arguments
    ///
    /// * `spi` - Security Parameters Index (unique identifier)
    /// * `is_inbound` - True for inbound (receiving), false for outbound (sending)
    /// * `sk_e` - Encryption key
    /// * `sk_a` - Authentication key (None for AEAD ciphers)
    /// * `ts_i` - Initiator traffic selectors
    /// * `ts_r` - Responder traffic selectors
    /// * `proposal` - Selected proposal (cipher, integrity, DH group)
    /// * `lifetime` - SA lifetime limits
    pub fn new(
        spi: u32,
        is_inbound: bool,
        sk_e: Vec<u8>,
        sk_a: Option<Vec<u8>>,
        ts_i: TrafficSelectorsPayload,
        ts_r: TrafficSelectorsPayload,
        proposal: Proposal,
        lifetime: SaLifetime,
    ) -> Self {
        // Create replay window for inbound SAs only
        let replay_window = if is_inbound {
            Some(ReplayWindow::default())
        } else {
            None
        };

        ChildSa {
            spi,
            protocol: 50, // ESP
            is_inbound,
            sk_e,
            sk_a,
            ts_i,
            ts_r,
            proposal,
            seq_out: 0,
            replay_window,
            state: ChildSaState::Active,
            lifetime,
            created_at: Instant::now(),
            bytes_processed: 0,
            rekey_initiated_at: None,
        }
    }

    /// Get current age of this SA
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Check if soft lifetime has been exceeded (time to rekey)
    pub fn should_rekey(&self) -> bool {
        self.lifetime
            .is_soft_expired(self.age(), self.bytes_processed)
    }

    /// Check if hard lifetime has been exceeded (must delete)
    pub fn is_expired(&self) -> bool {
        self.lifetime
            .is_hard_expired(self.age(), self.bytes_processed)
    }

    /// Increment sequence number (outbound only)
    ///
    /// Returns an error if sequence number would overflow (2^64 - 1).
    /// In practice, this should never happen as SAs should be rekeyed
    /// long before reaching this limit.
    pub fn next_sequence_number(&mut self) -> Result<u64> {
        if self.is_inbound {
            return Err(Error::Internal(
                "Cannot increment sequence number for inbound SA".into(),
            ));
        }

        if self.seq_out == u64::MAX {
            return Err(Error::Internal(
                "Sequence number overflow - SA must be rekeyed".into(),
            ));
        }

        self.seq_out += 1;
        Ok(self.seq_out)
    }

    /// Record bytes processed (for byte-based lifetime)
    pub fn add_bytes(&mut self, bytes: u64) {
        self.bytes_processed = self.bytes_processed.saturating_add(bytes);
    }

    /// Check if SA can be used for traffic
    ///
    /// Returns true if SA is in Active or Rekeying state.
    /// Returns false if SA is Rekeyed, Expired, or Deleted.
    pub fn can_use(&self) -> bool {
        matches!(self.state, ChildSaState::Active | ChildSaState::Rekeying)
    }

    /// Initiate rekeying process
    ///
    /// Transitions SA from Active to Rekeying state.
    /// Records the timestamp when rekeying was initiated.
    ///
    /// # Errors
    ///
    /// Returns error if SA is not in Active state.
    pub fn initiate_rekey(&mut self) -> Result<()> {
        if self.state != ChildSaState::Active {
            return Err(Error::InvalidState(format!(
                "Cannot initiate rekey from state {:?}",
                self.state
            )));
        }

        self.state = ChildSaState::Rekeying;
        self.rekey_initiated_at = Some(Instant::now());
        Ok(())
    }

    /// Mark SA as rekeyed (new SA is now active)
    ///
    /// Transitions SA from Rekeying to Rekeyed state.
    /// The SA can still be used for a brief period to handle in-flight packets,
    /// but new traffic should use the new SA.
    ///
    /// # Errors
    ///
    /// Returns error if SA is not in Rekeying state.
    pub fn mark_rekeyed(&mut self) -> Result<()> {
        if self.state != ChildSaState::Rekeying {
            return Err(Error::InvalidState(format!(
                "Cannot mark as rekeyed from state {:?}",
                self.state
            )));
        }

        self.state = ChildSaState::Rekeyed;
        Ok(())
    }

    /// Mark SA as expired (hard lifetime exceeded)
    ///
    /// Can be called from any state except Deleted.
    /// SA must be deleted immediately.
    pub fn mark_expired(&mut self) -> Result<()> {
        if self.state == ChildSaState::Deleted {
            return Err(Error::InvalidState(
                "Cannot mark deleted SA as expired".into(),
            ));
        }

        self.state = ChildSaState::Expired;
        Ok(())
    }

    /// Mark SA as deleted
    ///
    /// Can be called from Rekeyed or Expired state.
    /// This is the terminal state.
    pub fn mark_deleted(&mut self) -> Result<()> {
        if !matches!(self.state, ChildSaState::Rekeyed | ChildSaState::Expired) {
            return Err(Error::InvalidState(format!(
                "Cannot delete SA from state {:?}",
                self.state
            )));
        }

        self.state = ChildSaState::Deleted;
        Ok(())
    }

    /// Check if SA should be deleted
    ///
    /// Returns true if:
    /// - SA is in Expired state (hard lifetime exceeded), OR
    /// - SA is in Rekeyed state and grace period has passed
    ///
    /// Grace period for Rekeyed SAs is 30 seconds after rekeying completed,
    /// allowing in-flight packets to be processed.
    pub fn should_delete(&self) -> bool {
        match self.state {
            ChildSaState::Expired => true,
            ChildSaState::Rekeyed => {
                // Wait for grace period before deleting rekeyed SA
                const REKEY_GRACE_PERIOD: Duration = Duration::from_secs(30);

                if let Some(rekey_time) = self.rekey_initiated_at {
                    Instant::now().duration_since(rekey_time) >= REKEY_GRACE_PERIOD
                } else {
                    // No rekey timestamp, delete immediately
                    true
                }
            }
            _ => false,
        }
    }

    /// Get time remaining before soft lifetime expires
    ///
    /// Returns None if already expired or no time-based lifetime configured.
    pub fn time_until_rekey(&self) -> Option<Duration> {
        let age = self.age();
        if age >= self.lifetime.soft_time {
            None
        } else {
            Some(self.lifetime.soft_time - age)
        }
    }

    /// Get time remaining before hard lifetime expires
    ///
    /// Returns None if already expired or no time-based lifetime configured.
    pub fn time_until_expiry(&self) -> Option<Duration> {
        let age = self.age();
        if age >= self.lifetime.hard_time {
            None
        } else {
            Some(self.lifetime.hard_time - age)
        }
    }
}

/// Derive Child SA keying material from IKE SA's SK_d key
///
/// Implements RFC 7296 Section 2.17: Generating Keying Material for Child SAs
///
/// # Formula
///
/// ```text
/// KEYMAT = prf+(SK_d, Ni | Nr)
///
/// For PFS (Perfect Forward Secrecy):
/// KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)
///
/// Key split:
/// SK_ei | SK_ai | SK_er | SK_ar = KEYMAT
/// ```
///
/// # Arguments
///
/// * `prf_alg` - PRF algorithm to use
/// * `sk_d` - Key derivation key from IKE SA
/// * `nonce_i` - Initiator's nonce from CREATE_CHILD_SA
/// * `nonce_r` - Responder's nonce from CREATE_CHILD_SA
/// * `shared_secret` - Optional new DH shared secret (for PFS)
/// * `encr_key_len` - Encryption key length in bytes
/// * `integ_key_len` - Integrity key length in bytes (0 for AEAD)
///
/// # Returns
///
/// Tuple of (SK_ei, SK_ai, SK_er, SK_ar)
/// - SK_ei: Initiator's encryption key
/// - SK_ai: Initiator's integrity key (empty for AEAD)
/// - SK_er: Responder's encryption key
/// - SK_ar: Responder's integrity key (empty for AEAD)
pub fn derive_child_sa_keys(
    prf_alg: PrfAlgorithm,
    sk_d: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    shared_secret: Option<&[u8]>,
    encr_key_len: usize,
    integ_key_len: usize,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // Build seed for prf+
    let seed = if let Some(secret) = shared_secret {
        // PFS: Include new DH shared secret first
        [secret, nonce_i, nonce_r].concat()
    } else {
        // No PFS: Use nonces only
        [nonce_i, nonce_r].concat()
    };

    // Calculate total length needed
    let total_len = 2 * encr_key_len + 2 * integ_key_len;

    // Derive KEYMAT using prf+
    let keymat = prf_alg.prf_plus(sk_d, &seed, total_len);

    // Split KEYMAT into keys: SK_ei | SK_ai | SK_er | SK_ar
    let mut offset = 0;

    let sk_ei = keymat[offset..offset + encr_key_len].to_vec();
    offset += encr_key_len;

    let sk_ai = if integ_key_len > 0 {
        let key = keymat[offset..offset + integ_key_len].to_vec();
        offset += integ_key_len;
        key
    } else {
        Vec::new()
    };

    let sk_er = keymat[offset..offset + encr_key_len].to_vec();
    offset += encr_key_len;

    let sk_ar = if integ_key_len > 0 {
        keymat[offset..offset + integ_key_len].to_vec()
    } else {
        Vec::new()
    };

    (sk_ei, sk_ai, sk_er, sk_ar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::ikev2::{
        payload::{TrafficSelector, TsType},
        proposal::{Proposal, ProtocolId, Transform, TransformType},
    };

    fn create_test_proposal() -> Proposal {
        Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: vec![0x12, 0x34, 0x56, 0x78],
            transforms: vec![
                Transform {
                    transform_type: TransformType::Encr,
                    transform_id: 20, // AES-GCM-16 with 128-bit key
                    attributes: vec![],
                },
                Transform {
                    transform_type: TransformType::Esn,
                    transform_id: 0, // No ESN
                    attributes: vec![],
                },
            ],
        }
    }

    fn create_test_traffic_selectors() -> TrafficSelectorsPayload {
        TrafficSelectorsPayload {
            selectors: vec![TrafficSelector::ipv4_any()],
        }
    }

    #[test]
    fn test_sa_lifetime_default() {
        let lifetime = SaLifetime::default();
        assert_eq!(lifetime.soft_time, Duration::from_secs(45 * 60));
        assert_eq!(lifetime.hard_time, Duration::from_secs(60 * 60));
        assert!(lifetime.soft_bytes.is_none());
        assert!(lifetime.hard_bytes.is_none());
    }

    #[test]
    fn test_sa_lifetime_custom() {
        let lifetime =
            SaLifetime::new(Duration::from_secs(30 * 60), Duration::from_secs(40 * 60)).unwrap();

        assert_eq!(lifetime.soft_time, Duration::from_secs(30 * 60));
        assert_eq!(lifetime.hard_time, Duration::from_secs(40 * 60));
    }

    #[test]
    fn test_sa_lifetime_invalid() {
        // Soft >= Hard should fail
        let result = SaLifetime::new(Duration::from_secs(60 * 60), Duration::from_secs(60 * 60));
        assert!(result.is_err());

        let result = SaLifetime::new(Duration::from_secs(70 * 60), Duration::from_secs(60 * 60));
        assert!(result.is_err());
    }

    #[test]
    fn test_sa_lifetime_with_byte_limits() {
        let lifetime = SaLifetime::default()
            .with_byte_limits(750_000_000, 1_000_000_000)
            .unwrap();

        assert_eq!(lifetime.soft_bytes, Some(750_000_000));
        assert_eq!(lifetime.hard_bytes, Some(1_000_000_000));
    }

    #[test]
    fn test_sa_lifetime_invalid_byte_limits() {
        let result = SaLifetime::default().with_byte_limits(1_000_000_000, 1_000_000_000);
        assert!(result.is_err());

        let result = SaLifetime::default().with_byte_limits(2_000_000_000, 1_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_child_sa_creation() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16]; // 128-bit key
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let child_sa = ChildSa::new(
            spi,
            false, // outbound
            sk_e.clone(),
            None,
            ts_i.clone(),
            ts_r.clone(),
            proposal.clone(),
            lifetime,
        );

        assert_eq!(child_sa.spi, spi);
        assert_eq!(child_sa.protocol, 50);
        assert!(!child_sa.is_inbound);
        assert_eq!(child_sa.sk_e, sk_e);
        assert!(child_sa.sk_a.is_none());
        assert_eq!(child_sa.seq_out, 0);
        assert_eq!(child_sa.bytes_processed, 0);
    }

    #[test]
    fn test_child_sa_sequence_number() {
        let mut child_sa = ChildSa::new(
            0x12345678,
            false, // outbound
            vec![0u8; 16],
            None,
            create_test_traffic_selectors(),
            create_test_traffic_selectors(),
            create_test_proposal(),
            SaLifetime::default(),
        );

        assert_eq!(child_sa.seq_out, 0);

        let seq1 = child_sa.next_sequence_number().unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(child_sa.seq_out, 1);

        let seq2 = child_sa.next_sequence_number().unwrap();
        assert_eq!(seq2, 2);
        assert_eq!(child_sa.seq_out, 2);
    }

    #[test]
    fn test_child_sa_sequence_number_inbound_error() {
        let mut child_sa = ChildSa::new(
            0x12345678,
            true, // inbound
            vec![0u8; 16],
            None,
            create_test_traffic_selectors(),
            create_test_traffic_selectors(),
            create_test_proposal(),
            SaLifetime::default(),
        );

        let result = child_sa.next_sequence_number();
        assert!(result.is_err());
    }

    #[test]
    fn test_child_sa_bytes_processed() {
        let mut child_sa = ChildSa::new(
            0x12345678,
            false,
            vec![0u8; 16],
            None,
            create_test_traffic_selectors(),
            create_test_traffic_selectors(),
            create_test_proposal(),
            SaLifetime::default(),
        );

        assert_eq!(child_sa.bytes_processed, 0);

        child_sa.add_bytes(1400);
        assert_eq!(child_sa.bytes_processed, 1400);

        child_sa.add_bytes(1400);
        assert_eq!(child_sa.bytes_processed, 2800);
    }

    #[test]
    fn test_derive_child_sa_keys_no_pfs() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_d = vec![0xAA; 32];
        let nonce_i = vec![0x11; 32];
        let nonce_r = vec![0x22; 32];

        let (sk_ei, sk_ai, sk_er, sk_ar) =
            derive_child_sa_keys(prf_alg, &sk_d, &nonce_i, &nonce_r, None, 16, 16);

        // Check key lengths
        assert_eq!(sk_ei.len(), 16); // 128-bit encryption key
        assert_eq!(sk_ai.len(), 16); // 128-bit integrity key
        assert_eq!(sk_er.len(), 16);
        assert_eq!(sk_ar.len(), 16);

        // Keys should be different
        assert_ne!(sk_ei, sk_er);
        assert_ne!(sk_ai, sk_ar);
        assert_ne!(sk_ei, sk_ai);
    }

    #[test]
    fn test_derive_child_sa_keys_aead() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_d = vec![0xBB; 32];
        let nonce_i = vec![0x33; 32];
        let nonce_r = vec![0x44; 32];

        // AEAD: integ_key_len = 0
        let (sk_ei, sk_ai, sk_er, sk_ar) =
            derive_child_sa_keys(prf_alg, &sk_d, &nonce_i, &nonce_r, None, 16, 0);

        assert_eq!(sk_ei.len(), 16);
        assert_eq!(sk_ai.len(), 0); // No integrity key for AEAD
        assert_eq!(sk_er.len(), 16);
        assert_eq!(sk_ar.len(), 0);
    }

    #[test]
    fn test_derive_child_sa_keys_with_pfs() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_d = vec![0xCC; 32];
        let nonce_i = vec![0x55; 32];
        let nonce_r = vec![0x66; 32];
        let shared_secret = vec![0xFF; 32];

        let (sk_ei_pfs, _, sk_er_pfs, _) = derive_child_sa_keys(
            prf_alg,
            &sk_d,
            &nonce_i,
            &nonce_r,
            Some(&shared_secret),
            16,
            0,
        );

        let (sk_ei_no_pfs, _, sk_er_no_pfs, _) =
            derive_child_sa_keys(prf_alg, &sk_d, &nonce_i, &nonce_r, None, 16, 0);

        // Keys should be different with/without PFS
        assert_ne!(sk_ei_pfs, sk_ei_no_pfs);
        assert_ne!(sk_er_pfs, sk_er_no_pfs);
    }

    // ========================================
    // Rekeying Tests (Stage 5)
    // ========================================

    #[test]
    fn test_child_sa_state_default() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // New Child SA should be in Active state
        assert_eq!(child_sa.state, ChildSaState::Active);
        assert!(child_sa.rekey_initiated_at.is_none());
    }

    #[test]
    fn test_child_sa_can_use_active() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Active SA can be used
        assert!(child_sa.can_use());
    }

    #[test]
    fn test_child_sa_can_use_rekeying() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Initiate rekey
        child_sa.initiate_rekey().unwrap();

        // Rekeying SA can still be used
        assert!(child_sa.can_use());
    }

    #[test]
    fn test_child_sa_cannot_use_rekeyed() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Transition to Rekeyed state
        child_sa.initiate_rekey().unwrap();
        child_sa.mark_rekeyed().unwrap();

        // Rekeyed SA cannot be used
        assert!(!child_sa.can_use());
    }

    #[test]
    fn test_child_sa_cannot_use_expired() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Mark as expired
        child_sa.mark_expired().unwrap();

        // Expired SA cannot be used
        assert!(!child_sa.can_use());
    }

    #[test]
    fn test_initiate_rekey_from_active() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Should successfully initiate rekey
        assert!(child_sa.initiate_rekey().is_ok());
        assert_eq!(child_sa.state, ChildSaState::Rekeying);
        assert!(child_sa.rekey_initiated_at.is_some());
    }

    #[test]
    fn test_initiate_rekey_from_invalid_state() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Transition to Rekeying state
        child_sa.initiate_rekey().unwrap();

        // Cannot initiate rekey again from Rekeying state
        let result = child_sa.initiate_rekey();
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_rekeyed_from_rekeying() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Initiate rekey first
        child_sa.initiate_rekey().unwrap();

        // Should successfully mark as rekeyed
        assert!(child_sa.mark_rekeyed().is_ok());
        assert_eq!(child_sa.state, ChildSaState::Rekeyed);
    }

    #[test]
    fn test_mark_rekeyed_from_invalid_state() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Cannot mark as rekeyed from Active state
        let result = child_sa.mark_rekeyed();
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_expired_from_any_state() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Can mark as expired from Active state
        assert!(child_sa.mark_expired().is_ok());
        assert_eq!(child_sa.state, ChildSaState::Expired);
    }

    #[test]
    fn test_mark_deleted_from_rekeyed() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Transition to Rekeyed state
        child_sa.initiate_rekey().unwrap();
        child_sa.mark_rekeyed().unwrap();

        // Should successfully mark as deleted
        assert!(child_sa.mark_deleted().is_ok());
        assert_eq!(child_sa.state, ChildSaState::Deleted);
    }

    #[test]
    fn test_mark_deleted_from_expired() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Transition to Expired state
        child_sa.mark_expired().unwrap();

        // Should successfully mark as deleted
        assert!(child_sa.mark_deleted().is_ok());
        assert_eq!(child_sa.state, ChildSaState::Deleted);
    }

    #[test]
    fn test_mark_deleted_from_invalid_state() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Cannot mark as deleted from Active state
        let result = child_sa.mark_deleted();
        assert!(result.is_err());
    }

    #[test]
    fn test_should_delete_expired() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Mark as expired
        child_sa.mark_expired().unwrap();

        // Should be deleted immediately
        assert!(child_sa.should_delete());
    }

    #[test]
    fn test_should_delete_rekeyed_grace_period() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Transition to Rekeyed state
        child_sa.initiate_rekey().unwrap();
        child_sa.mark_rekeyed().unwrap();

        // Should not delete immediately (within grace period)
        assert!(!child_sa.should_delete());
    }

    #[test]
    fn test_should_not_delete_active() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Active SA should not be deleted
        assert!(!child_sa.should_delete());
    }

    #[test]
    fn test_time_until_rekey_active() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();

        // Short lifetime for testing
        let lifetime = SaLifetime::new(Duration::from_secs(10), Duration::from_secs(20)).unwrap();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Should have time until rekey
        let time_until = child_sa.time_until_rekey();
        assert!(time_until.is_some());
        assert!(time_until.unwrap() <= Duration::from_secs(10));
    }

    #[test]
    fn test_time_until_rekey_rekeying() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();
        let lifetime = SaLifetime::default();

        let mut child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Initiate rekey
        child_sa.initiate_rekey().unwrap();

        // time_until_rekey() is time-based, not state-based
        // It should still return time remaining even when rekeying
        let time_until = child_sa.time_until_rekey();
        assert!(time_until.is_some());
        assert!(time_until.unwrap() <= Duration::from_secs(45 * 60));
    }

    #[test]
    fn test_time_until_expiry_active() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();

        // Short lifetime for testing
        let lifetime = SaLifetime::new(Duration::from_secs(10), Duration::from_secs(20)).unwrap();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Should have time until expiry
        let time_until = child_sa.time_until_expiry();
        assert!(time_until.is_some());
        assert!(time_until.unwrap() <= Duration::from_secs(20));
    }

    #[test]
    fn test_time_until_expiry_after_hard_lifetime() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();

        // Very short hard lifetime (1ms)
        let lifetime = SaLifetime::new(Duration::from_millis(1), Duration::from_millis(2)).unwrap();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Wait for hard lifetime to expire
        std::thread::sleep(Duration::from_millis(5));

        // time_until_expiry() should return None after hard lifetime expires
        assert!(child_sa.time_until_expiry().is_none());
    }

    #[test]
    fn test_lifetime_expiration_detection() {
        let spi = 0x12345678;
        let sk_e = vec![0u8; 16];
        let ts_i = create_test_traffic_selectors();
        let ts_r = create_test_traffic_selectors();
        let proposal = create_test_proposal();

        // Very short lifetime (1ms soft, 2ms hard)
        let lifetime = SaLifetime::new(Duration::from_millis(1), Duration::from_millis(2)).unwrap();

        let child_sa = ChildSa::new(spi, false, sk_e, None, ts_i, ts_r, proposal, lifetime);

        // Wait for soft lifetime to expire
        std::thread::sleep(Duration::from_millis(5));

        // Time until rekey should be None or zero
        let time_until_rekey = child_sa.time_until_rekey();
        assert!(
            time_until_rekey.is_none() || time_until_rekey.unwrap() == Duration::ZERO,
            "Expected None or zero duration after soft lifetime expires"
        );
    }
}
