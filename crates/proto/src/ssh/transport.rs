//! SSH Transport Layer State Machine (RFC 4253).
//!
//! This module implements the SSH transport layer protocol state machine,
//! managing the connection lifecycle from version exchange through encrypted
//! communication.
//!
//! # Transport States
//!
//! The transport layer progresses through these states:
//!
//! 1. **VersionExchange** - Exchange SSH-2.0 version strings
//! 2. **KexInit** - Send/receive SSH_MSG_KEXINIT messages
//! 3. **KeyExchange** - Perform DH/ECDH key exchange
//! 4. **NewKeys** - Send/receive SSH_MSG_NEWKEYS, install new keys
//! 5. **Encrypted** - All communication encrypted and authenticated
//!
//! # Rekeying
//!
//! The transport layer supports rekeying (returning to KexInit state) based on:
//! - Data transferred (1 GB by default)
//! - Time elapsed (1 hour by default)
//! - Explicit request
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::transport::{State, TransportState, TransportConfig};
//!
//! // Create initial state
//! let mut state = TransportState::new(TransportConfig::default());
//!
//! // Progress through states
//! assert!(matches!(state.current(), State::VersionExchange));
//! ```

use crate::ssh::crypto::{CipherAlgorithm, DecryptionKey, EncryptionKey, MacAlgorithm, MacKey};
use crate::ssh::kex::KexInit;
use crate::ssh::version::Version;
use fynx_platform::{FynxError, FynxResult};

/// SSH transport layer state.
///
/// The state machine progresses through these states during connection establishment
/// and can return to KexInit for rekeying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Version exchange in progress.
    ///
    /// Both sides exchange "SSH-2.0-..." version strings.
    VersionExchange,

    /// Key exchange initialization.
    ///
    /// Both sides send SSH_MSG_KEXINIT with algorithm preferences.
    KexInit,

    /// Key exchange in progress.
    ///
    /// Performing Diffie-Hellman or Curve25519 key exchange.
    KeyExchange,

    /// New keys installation.
    ///
    /// Both sides send SSH_MSG_NEWKEYS and activate encryption.
    NewKeys,

    /// Encrypted communication.
    ///
    /// All packets encrypted and authenticated. This is the normal operating state.
    Encrypted,
}

/// Transport layer configuration.
///
/// Controls behavior of the transport state machine.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Our SSH version string.
    pub version: Version,

    /// Our algorithm preferences (KEXINIT).
    pub kex_init: KexInit,

    /// Maximum bytes before automatic rekey (default: 1 GB).
    pub rekey_bytes_limit: u64,

    /// Maximum seconds before automatic rekey (default: 3600 = 1 hour).
    pub rekey_time_limit: u64,

    /// Whether we are the client (true) or server (false).
    pub is_client: bool,
}

impl TransportConfig {
    /// Creates a new transport configuration.
    ///
    /// # Arguments
    ///
    /// * `is_client` - Whether this is a client (true) or server (false)
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::transport::TransportConfig;
    ///
    /// let config = TransportConfig::new(true); // Client configuration
    /// ```
    pub fn new(is_client: bool) -> Self {
        Self {
            version: Version::new("Fynx_0.1.0", None),
            kex_init: KexInit::new_default(),
            rekey_bytes_limit: 1_000_000_000, // 1 GB
            rekey_time_limit: 3600,           // 1 hour
            is_client,
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::new(true) // Default to client
    }
}

/// Negotiated encryption parameters.
///
/// After key exchange, these parameters are used for encrypted communication.
#[derive(Debug)]
pub struct EncryptionParams {
    /// Cipher algorithm for client-to-server encryption.
    pub cipher_c2s: CipherAlgorithm,

    /// Cipher algorithm for server-to-client encryption.
    pub cipher_s2c: CipherAlgorithm,

    /// MAC algorithm for client-to-server (None for AEAD ciphers).
    pub mac_c2s: Option<MacAlgorithm>,

    /// MAC algorithm for server-to-client (None for AEAD ciphers).
    pub mac_s2c: Option<MacAlgorithm>,

    /// Encryption key for outgoing packets.
    pub encryption_key: Option<EncryptionKey>,

    /// Decryption key for incoming packets.
    pub decryption_key: Option<DecryptionKey>,

    /// MAC key for outgoing packets (if needed).
    pub mac_key_out: Option<MacKey>,

    /// MAC key for incoming packets (if needed).
    pub mac_key_in: Option<MacKey>,
}

impl EncryptionParams {
    /// Creates a new encryption parameters structure with no keys installed.
    ///
    /// Keys must be installed after key exchange using `install_keys()`.
    pub fn new(
        cipher_c2s: CipherAlgorithm,
        cipher_s2c: CipherAlgorithm,
        mac_c2s: Option<MacAlgorithm>,
        mac_s2c: Option<MacAlgorithm>,
    ) -> Self {
        Self {
            cipher_c2s,
            cipher_s2c,
            mac_c2s,
            mac_s2c,
            encryption_key: None,
            decryption_key: None,
            mac_key_out: None,
            mac_key_in: None,
        }
    }

    /// Installs encryption and MAC keys.
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - Key for encrypting outgoing packets
    /// * `decryption_key` - Key for decrypting incoming packets
    /// * `mac_key_out` - MAC key for outgoing packets (if needed)
    /// * `mac_key_in` - MAC key for incoming packets (if needed)
    pub fn install_keys(
        &mut self,
        encryption_key: Option<EncryptionKey>,
        decryption_key: Option<DecryptionKey>,
        mac_key_out: Option<MacKey>,
        mac_key_in: Option<MacKey>,
    ) {
        self.encryption_key = encryption_key;
        self.decryption_key = decryption_key;
        self.mac_key_out = mac_key_out;
        self.mac_key_in = mac_key_in;
    }

    /// Returns whether encryption is active (keys installed).
    pub fn is_active(&self) -> bool {
        self.encryption_key.is_some() && self.decryption_key.is_some()
    }
}

/// SSH Transport Layer state machine.
///
/// Manages the connection state and encryption parameters.
#[derive(Debug)]
pub struct TransportState {
    /// Current state.
    state: State,

    /// Configuration.
    config: TransportConfig,

    /// Peer's version string (set after version exchange).
    peer_version: Option<Version>,

    /// Peer's KEXINIT message (set after receiving KEXINIT).
    peer_kex_init: Option<KexInit>,

    /// Encryption parameters (set after key exchange).
    encryption_params: Option<EncryptionParams>,

    /// Bytes transferred since last key exchange.
    bytes_transferred: u64,

    /// Timestamp of last key exchange (Unix timestamp).
    last_kex_time: u64,
}

impl TransportState {
    /// Creates a new transport state machine.
    ///
    /// Starts in VersionExchange state.
    ///
    /// # Arguments
    ///
    /// * `config` - Transport configuration
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::transport::{TransportState, TransportConfig};
    ///
    /// let state = TransportState::new(TransportConfig::default());
    /// ```
    pub fn new(config: TransportConfig) -> Self {
        Self {
            state: State::VersionExchange,
            config,
            peer_version: None,
            peer_kex_init: None,
            encryption_params: None,
            bytes_transferred: 0,
            last_kex_time: 0,
        }
    }

    /// Returns the current state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::transport::{TransportState, TransportConfig, State};
    ///
    /// let state = TransportState::new(TransportConfig::default());
    /// assert!(matches!(state.current(), State::VersionExchange));
    /// ```
    pub fn current(&self) -> &State {
        &self.state
    }

    /// Returns the configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Returns the peer's version string (if received).
    pub fn peer_version(&self) -> Option<&Version> {
        self.peer_version.as_ref()
    }

    /// Returns the peer's KEXINIT message (if received).
    pub fn peer_kex_init(&self) -> Option<&KexInit> {
        self.peer_kex_init.as_ref()
    }

    /// Returns the encryption parameters (if keys installed).
    pub fn encryption_params(&self) -> Option<&EncryptionParams> {
        self.encryption_params.as_ref()
    }

    /// Returns mutable encryption parameters (if keys installed).
    pub fn encryption_params_mut(&mut self) -> Option<&mut EncryptionParams> {
        self.encryption_params.as_mut()
    }

    /// Returns whether encryption is active.
    pub fn is_encrypted(&self) -> bool {
        matches!(self.state, State::Encrypted)
            && self
                .encryption_params
                .as_ref()
                .is_some_and(|p| p.is_active())
    }

    /// Transitions to the next state.
    ///
    /// # Arguments
    ///
    /// * `next_state` - The state to transition to
    ///
    /// # Returns
    ///
    /// Ok(()) if transition is valid, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns error if the transition is invalid (e.g., VersionExchange -> Encrypted).
    pub fn transition(&mut self, next_state: State) -> FynxResult<()> {
        // Validate state transition
        let valid = match (&self.state, &next_state) {
            // Normal progression
            (State::VersionExchange, State::KexInit) => true,
            (State::KexInit, State::KeyExchange) => true,
            (State::KeyExchange, State::NewKeys) => true,
            (State::NewKeys, State::Encrypted) => true,
            // Rekeying: return to KexInit from Encrypted
            (State::Encrypted, State::KexInit) => true,
            // Stay in same state
            (s1, s2) if s1 == s2 => true,
            // All other transitions invalid
            _ => false,
        };

        if !valid {
            return Err(FynxError::Protocol(format!(
                "Invalid state transition: {:?} -> {:?}",
                self.state, next_state
            )));
        }

        self.state = next_state;
        Ok(())
    }

    /// Sets the peer's version string.
    ///
    /// Should be called after receiving the peer's version during VersionExchange.
    pub fn set_peer_version(&mut self, version: Version) {
        self.peer_version = Some(version);
    }

    /// Sets the peer's KEXINIT message.
    ///
    /// Should be called after receiving SSH_MSG_KEXINIT.
    pub fn set_peer_kex_init(&mut self, kex_init: KexInit) {
        self.peer_kex_init = Some(kex_init);
    }

    /// Sets the encryption parameters.
    ///
    /// Should be called after key exchange negotiation.
    pub fn set_encryption_params(&mut self, params: EncryptionParams) {
        self.encryption_params = Some(params);
    }

    /// Records bytes transferred for rekey tracking.
    ///
    /// Should be called after sending/receiving each packet.
    pub fn add_bytes(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
    }

    /// Checks if rekeying is needed.
    ///
    /// Returns true if:
    /// - Bytes transferred exceeds limit, OR
    /// - Time since last KEX exceeds limit
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp
    pub fn needs_rekey(&self, current_time: u64) -> bool {
        if !matches!(self.state, State::Encrypted) {
            return false;
        }

        // Check bytes limit
        if self.bytes_transferred >= self.config.rekey_bytes_limit {
            return true;
        }

        // Check time limit
        if current_time >= self.last_kex_time + self.config.rekey_time_limit {
            return true;
        }

        false
    }

    /// Resets rekey tracking counters.
    ///
    /// Should be called after completing key exchange.
    ///
    /// # Arguments
    ///
    /// * `current_time` - Current Unix timestamp
    pub fn reset_rekey_tracking(&mut self, current_time: u64) {
        self.bytes_transferred = 0;
        self.last_kex_time = current_time;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_new() {
        let config = TransportConfig::new(true);
        assert!(config.is_client);
        assert_eq!(config.rekey_bytes_limit, 1_000_000_000);
        assert_eq!(config.rekey_time_limit, 3600);
    }

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert!(config.is_client);
    }

    #[test]
    fn test_transport_state_new() {
        let state = TransportState::new(TransportConfig::default());
        assert!(matches!(state.current(), State::VersionExchange));
        assert!(!state.is_encrypted());
    }

    #[test]
    fn test_state_transition_valid() {
        let mut state = TransportState::new(TransportConfig::default());

        // Normal progression
        assert!(state.transition(State::KexInit).is_ok());
        assert!(matches!(state.current(), State::KexInit));

        assert!(state.transition(State::KeyExchange).is_ok());
        assert!(matches!(state.current(), State::KeyExchange));

        assert!(state.transition(State::NewKeys).is_ok());
        assert!(matches!(state.current(), State::NewKeys));

        assert!(state.transition(State::Encrypted).is_ok());
        assert!(matches!(state.current(), State::Encrypted));
    }

    #[test]
    fn test_state_transition_rekey() {
        let mut state = TransportState::new(TransportConfig::default());

        // Move to Encrypted
        state.transition(State::KexInit).unwrap();
        state.transition(State::KeyExchange).unwrap();
        state.transition(State::NewKeys).unwrap();
        state.transition(State::Encrypted).unwrap();

        // Rekey: return to KexInit
        assert!(state.transition(State::KexInit).is_ok());
        assert!(matches!(state.current(), State::KexInit));
    }

    #[test]
    fn test_state_transition_invalid() {
        let mut state = TransportState::new(TransportConfig::default());

        // Can't jump directly to Encrypted
        let result = state.transition(State::Encrypted);
        assert!(result.is_err());
        match result {
            Err(FynxError::Protocol(msg)) => {
                assert!(msg.contains("Invalid state transition"));
            }
            _ => panic!("Expected Protocol error"),
        }
    }

    #[test]
    fn test_peer_version() {
        let mut state = TransportState::new(TransportConfig::default());
        assert!(state.peer_version().is_none());

        let version = Version::new("OpenSSH_8.0", None);
        state.set_peer_version(version.clone());
        assert_eq!(state.peer_version(), Some(&version));
    }

    #[test]
    fn test_peer_kex_init() {
        let mut state = TransportState::new(TransportConfig::default());
        assert!(state.peer_kex_init().is_none());

        let kex_init = KexInit::new_default();
        state.set_peer_kex_init(kex_init.clone());
        assert_eq!(state.peer_kex_init(), Some(&kex_init));
    }

    #[test]
    fn test_encryption_params() {
        let params = EncryptionParams::new(
            CipherAlgorithm::ChaCha20Poly1305,
            CipherAlgorithm::ChaCha20Poly1305,
            None,
            None,
        );
        assert!(!params.is_active()); // No keys installed yet
    }

    #[test]
    fn test_needs_rekey_bytes() {
        let mut state = TransportState::new(TransportConfig::default());

        // Not encrypted state, no rekey needed
        assert!(!state.needs_rekey(1000));

        // Move to encrypted state properly
        state.transition(State::KexInit).unwrap();
        state.transition(State::KeyExchange).unwrap();
        state.transition(State::NewKeys).unwrap();
        state.transition(State::Encrypted).unwrap();

        // Add bytes below limit
        state.add_bytes(500_000_000);
        assert!(!state.needs_rekey(1000));

        // Exceed bytes limit
        state.add_bytes(600_000_000);
        assert!(state.needs_rekey(1000));
    }

    #[test]
    fn test_needs_rekey_time() {
        let mut state = TransportState::new(TransportConfig::default());
        state.state = State::VersionExchange;
        state.transition(State::KexInit).unwrap();
        state.transition(State::KeyExchange).unwrap();
        state.transition(State::NewKeys).unwrap();
        state.transition(State::Encrypted).unwrap();

        state.reset_rekey_tracking(1000);

        // Within time limit
        assert!(!state.needs_rekey(2000));

        // Exceed time limit
        assert!(state.needs_rekey(5000));
    }

    #[test]
    fn test_reset_rekey_tracking() {
        let mut state = TransportState::new(TransportConfig::default());
        state.add_bytes(500_000_000);
        assert_eq!(state.bytes_transferred, 500_000_000);

        state.reset_rekey_tracking(1000);
        assert_eq!(state.bytes_transferred, 0);
        assert_eq!(state.last_kex_time, 1000);
    }
}
