//! Dead Peer Detection (DPD)
//!
//! Implements Dead Peer Detection as described in RFC 3706.
//!
//! # Overview
//!
//! DPD detects when an IKE peer has become unreachable by periodically
//! sending INFORMATIONAL exchanges and expecting timely responses.
//!
//! # Algorithm
//!
//! 1. **Periodic Checks**: Send empty INFORMATIONAL message at intervals
//! 2. **Response Timeout**: Wait for response within timeout period
//! 3. **Retry Logic**: Retry up to max_retries times
//! 4. **Dead Declaration**: Mark peer as dead after max retries exceeded
//!
//! # Example Flow
//!
//! ```text
//! Time:  0s       30s      40s      70s      80s     110s
//!        |--------|--------|--------|--------|--------|
//!        Send     Send     Send     Send     Dead
//!        DPD      DPD      DPD      DPD      Peer
//!         ↓        ↓        ↓        ↓
//!        OK       OK       Timeout  Timeout
//!                          (retry)  (retry)
//!
//! Config: interval=30s, timeout=10s, max_retries=3
//! ```
//!
//! # References
//!
//! - [RFC 3706](https://datatracker.ietf.org/doc/html/rfc3706) - Dead Peer Detection

use std::time::{Duration, Instant};

/// Default DPD check interval (30 seconds)
pub const DEFAULT_DPD_INTERVAL: Duration = Duration::from_secs(30);

/// Default DPD response timeout (10 seconds)
pub const DEFAULT_DPD_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum retry attempts (3 times)
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// DPD Configuration
///
/// Controls Dead Peer Detection behavior.
///
/// # Example
///
/// ```rust,ignore
/// use fynx_proto::ipsec::dpd::DpdConfig;
/// use std::time::Duration;
///
/// let config = DpdConfig {
///     enabled: true,
///     interval: Duration::from_secs(30),
///     timeout: Duration::from_secs(10),
///     max_retries: 3,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdConfig {
    /// Enable DPD
    pub enabled: bool,

    /// Interval between DPD checks
    ///
    /// How often to send DPD INFORMATIONAL messages when no other
    /// traffic has been received. Typically 30 seconds.
    pub interval: Duration,

    /// Timeout for DPD response
    ///
    /// How long to wait for a response before considering it a failure.
    /// Typically 10 seconds.
    pub timeout: Duration,

    /// Maximum retry attempts
    ///
    /// How many failed DPD attempts before marking peer as dead.
    /// Typically 3 retries.
    pub max_retries: u32,
}

impl Default for DpdConfig {
    fn default() -> Self {
        DpdConfig {
            enabled: true,
            interval: DEFAULT_DPD_INTERVAL,
            timeout: DEFAULT_DPD_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

impl DpdConfig {
    /// Create new DPD configuration
    pub fn new(enabled: bool, interval: Duration, timeout: Duration, max_retries: u32) -> Self {
        DpdConfig {
            enabled,
            interval,
            timeout,
            max_retries,
        }
    }

    /// Create disabled DPD configuration
    pub fn disabled() -> Self {
        DpdConfig {
            enabled: false,
            interval: DEFAULT_DPD_INTERVAL,
            timeout: DEFAULT_DPD_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

/// DPD State
///
/// Tracks the state of Dead Peer Detection for an IKE SA.
///
/// # Example
///
/// ```rust,ignore
/// use fynx_proto::ipsec::dpd::{DpdConfig, DpdState};
///
/// let config = DpdConfig::default();
/// let mut state = DpdState::new();
///
/// // Check if should send DPD
/// if state.should_send(&config) {
///     // Send DPD request
///     state.mark_sent(1);
/// }
///
/// // Later, when response received
/// state.mark_received();
/// ```
#[derive(Debug, Clone)]
pub struct DpdState {
    /// Last DPD request sent
    last_sent: Option<Instant>,

    /// Waiting for response
    waiting: bool,

    /// Current retry count
    retries: u32,

    /// Message ID of last DPD request
    message_id: Option<u32>,

    /// Last activity (any traffic received)
    last_activity: Option<Instant>,
}

impl Default for DpdState {
    fn default() -> Self {
        Self::new()
    }
}

impl DpdState {
    /// Create new DPD state
    pub fn new() -> Self {
        DpdState {
            last_sent: None,
            waiting: false,
            retries: 0,
            message_id: None,
            last_activity: Some(Instant::now()), // Start with current time
        }
    }

    /// Check if DPD check should be sent
    ///
    /// Returns true if:
    /// - Not currently waiting for a response
    /// - Interval has elapsed since last send or last activity
    pub fn should_send(&self, config: &DpdConfig) -> bool {
        if !config.enabled {
            return false;
        }

        // Don't send if already waiting for response
        if self.waiting {
            return false;
        }

        let now = Instant::now();

        // Check time since last activity (any traffic)
        if let Some(last_activity) = self.last_activity {
            if now.duration_since(last_activity) < config.interval {
                // Recent activity, no need for DPD
                return false;
            }
        }

        // Check time since last DPD sent
        if let Some(last_sent) = self.last_sent {
            now.duration_since(last_sent) >= config.interval
        } else {
            // Never sent, should send now
            true
        }
    }

    /// Record DPD request sent
    ///
    /// Updates state to reflect that a DPD check has been sent.
    pub fn mark_sent(&mut self, msg_id: u32) {
        self.last_sent = Some(Instant::now());
        self.waiting = true;
        self.message_id = Some(msg_id);
    }

    /// Record DPD response received
    ///
    /// Resets retry counter and waiting state.
    pub fn mark_received(&mut self) {
        self.waiting = false;
        self.retries = 0;
        self.message_id = None;
        self.last_activity = Some(Instant::now());
    }

    /// Record any activity (not just DPD)
    ///
    /// Updates last_activity to prevent unnecessary DPD checks.
    pub fn mark_activity(&mut self) {
        self.last_activity = Some(Instant::now());
        // If we received any traffic, peer is alive
        if self.waiting {
            self.waiting = false;
            self.retries = 0;
            self.message_id = None;
        }
    }

    /// Check if DPD response has timed out
    ///
    /// Returns true if waiting for response and timeout has elapsed.
    pub fn is_timeout(&self, config: &DpdConfig) -> bool {
        if !self.waiting {
            return false;
        }

        if let Some(last_sent) = self.last_sent {
            let elapsed = Instant::now().duration_since(last_sent);
            elapsed >= config.timeout
        } else {
            false
        }
    }

    /// Handle DPD timeout
    ///
    /// Increments retry counter. Returns true if should retry.
    pub fn handle_timeout(&mut self, config: &DpdConfig) -> bool {
        if !self.is_timeout(config) {
            return false;
        }

        self.retries += 1;
        self.waiting = false;
        self.message_id = None;

        // Can retry if retries < max_retries
        self.retries < config.max_retries
    }

    /// Check if peer is dead
    ///
    /// Returns true if max retries exceeded.
    pub fn is_dead(&self, config: &DpdConfig) -> bool {
        if !config.enabled {
            return false;
        }

        self.retries >= config.max_retries
    }

    /// Get current retry count
    pub fn retry_count(&self) -> u32 {
        self.retries
    }

    /// Check if waiting for response
    pub fn is_waiting(&self) -> bool {
        self.waiting
    }

    /// Get message ID of pending DPD request
    pub fn pending_message_id(&self) -> Option<u32> {
        if self.waiting {
            self.message_id
        } else {
            None
        }
    }

    /// Reset DPD state
    ///
    /// Clears all retry counters and timers.
    pub fn reset(&mut self) {
        self.last_sent = None;
        self.waiting = false;
        self.retries = 0;
        self.message_id = None;
        self.last_activity = Some(Instant::now());
    }

    /// Get time since last activity
    pub fn time_since_last_activity(&self) -> Option<Duration> {
        self.last_activity
            .map(|last| Instant::now().duration_since(last))
    }
}

/// DPD Status
///
/// Represents the current status of Dead Peer Detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdStatus {
    /// Peer is alive (normal operation)
    Alive,

    /// Should send DPD request
    SendRequest,

    /// Waiting for DPD response
    Waiting,

    /// DPD response timed out, should retry
    Timeout,

    /// Peer is dead (max retries exceeded)
    Dead,
}

/// DPD Manager
///
/// Convenience wrapper for managing DPD configuration and state together.
#[derive(Debug, Clone)]
pub struct DpdManager {
    /// DPD configuration
    config: DpdConfig,

    /// DPD state
    state: DpdState,
}

impl DpdManager {
    /// Create new DPD manager with configuration
    pub fn new(config: DpdConfig) -> Self {
        DpdManager {
            config,
            state: DpdState::new(),
        }
    }

    /// Get DPD configuration
    pub fn config(&self) -> &DpdConfig {
        &self.config
    }

    /// Get mutable DPD configuration
    pub fn config_mut(&mut self) -> &mut DpdConfig {
        &mut self.config
    }

    /// Get DPD state
    pub fn state(&self) -> &DpdState {
        &self.state
    }

    /// Get mutable DPD state
    pub fn state_mut(&mut self) -> &mut DpdState {
        &mut self.state
    }

    /// Check DPD status
    pub fn check_status(&self) -> DpdStatus {
        if !self.config.enabled {
            return DpdStatus::Alive;
        }

        if self.state.is_dead(&self.config) {
            return DpdStatus::Dead;
        }

        if self.state.is_waiting() {
            if self.state.is_timeout(&self.config) {
                return DpdStatus::Timeout;
            }
            return DpdStatus::Waiting;
        }

        if self.state.should_send(&self.config) {
            return DpdStatus::SendRequest;
        }

        DpdStatus::Alive
    }

    /// Mark DPD request sent
    pub fn mark_sent(&mut self, msg_id: u32) {
        self.state.mark_sent(msg_id);
    }

    /// Mark DPD response received
    pub fn mark_received(&mut self) {
        self.state.mark_received();
    }

    /// Mark any activity (resets DPD timer)
    pub fn mark_activity(&mut self) {
        self.state.mark_activity();
    }

    /// Handle DPD timeout (increments retry counter)
    ///
    /// Returns true if should retry.
    pub fn handle_timeout(&mut self) -> bool {
        self.state.handle_timeout(&self.config)
    }

    /// Reset DPD state
    pub fn reset(&mut self) {
        self.state.reset();
    }
}

impl Default for DpdManager {
    fn default() -> Self {
        Self::new(DpdConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_dpd_config_default() {
        let config = DpdConfig::default();

        assert!(config.enabled);
        assert_eq!(config.interval, DEFAULT_DPD_INTERVAL);
        assert_eq!(config.timeout, DEFAULT_DPD_TIMEOUT);
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn test_dpd_config_disabled() {
        let config = DpdConfig::disabled();

        assert!(!config.enabled);
    }

    #[test]
    fn test_dpd_config_new() {
        let config = DpdConfig::new(true, Duration::from_secs(60), Duration::from_secs(15), 5);

        assert!(config.enabled);
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(15));
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_dpd_state_new() {
        let state = DpdState::new();

        assert!(!state.is_waiting());
        assert_eq!(state.retry_count(), 0);
        assert!(state.pending_message_id().is_none());
        assert!(state.time_since_last_activity().is_some());
    }

    #[test]
    fn test_dpd_should_send_disabled() {
        let config = DpdConfig::disabled();
        let state = DpdState::new();

        assert!(!state.should_send(&config));
    }

    #[test]
    fn test_dpd_should_send_initial() {
        let mut config = DpdConfig::default();
        config.interval = Duration::from_millis(10); // Short interval for testing

        let mut state = DpdState::new();
        // Clear initial activity
        state.last_activity = None;

        // Should send immediately on first check
        assert!(state.should_send(&config));
    }

    #[test]
    fn test_dpd_should_send_after_interval() {
        let mut config = DpdConfig::default();
        config.interval = Duration::from_millis(50); // Short interval for testing

        let mut state = DpdState::new();
        state.last_activity = None;

        // Send first DPD
        state.mark_sent(1);

        // Should not send immediately (waiting for response)
        assert!(!state.should_send(&config));

        // Receive response
        state.mark_received();

        // Should not send immediately after receiving (interval not elapsed)
        assert!(!state.should_send(&config));

        // Wait for interval
        thread::sleep(Duration::from_millis(60));

        // Should send now (interval elapsed, not waiting)
        assert!(state.should_send(&config));
    }

    #[test]
    fn test_dpd_should_not_send_while_waiting() {
        let config = DpdConfig::default();
        let mut state = DpdState::new();

        state.mark_sent(1);

        // Should not send while waiting for response
        assert!(!state.should_send(&config));
    }

    #[test]
    fn test_dpd_mark_sent() {
        let mut state = DpdState::new();

        state.mark_sent(42);

        assert!(state.is_waiting());
        assert_eq!(state.pending_message_id(), Some(42));
    }

    #[test]
    fn test_dpd_mark_received() {
        let mut state = DpdState::new();

        state.mark_sent(1);
        state.retries = 2;

        state.mark_received();

        assert!(!state.is_waiting());
        assert_eq!(state.retry_count(), 0);
        assert!(state.pending_message_id().is_none());
    }

    #[test]
    fn test_dpd_mark_activity() {
        let mut state = DpdState::new();

        state.mark_sent(1);

        state.mark_activity();

        // Activity clears waiting state
        assert!(!state.is_waiting());
        assert_eq!(state.retry_count(), 0);
    }

    #[test]
    fn test_dpd_timeout() {
        let mut config = DpdConfig::default();
        config.timeout = Duration::from_millis(50);

        let mut state = DpdState::new();

        state.mark_sent(1);

        // Should not timeout immediately
        assert!(!state.is_timeout(&config));

        // Wait for timeout
        thread::sleep(Duration::from_millis(60));

        // Should timeout now
        assert!(state.is_timeout(&config));
    }

    #[test]
    fn test_dpd_handle_timeout() {
        let mut config = DpdConfig::default();
        config.timeout = Duration::from_millis(10);
        config.max_retries = 3;

        let mut state = DpdState::new();

        state.mark_sent(1);
        thread::sleep(Duration::from_millis(20));

        // First timeout - should retry
        assert!(state.handle_timeout(&config));
        assert_eq!(state.retry_count(), 1);
        assert!(!state.is_waiting());

        // Second timeout
        state.mark_sent(2);
        thread::sleep(Duration::from_millis(20));
        assert!(state.handle_timeout(&config));
        assert_eq!(state.retry_count(), 2);

        // Third timeout - max retries reached
        state.mark_sent(3);
        thread::sleep(Duration::from_millis(20));
        assert!(!state.handle_timeout(&config));
        assert_eq!(state.retry_count(), 3);
    }

    #[test]
    fn test_dpd_is_dead() {
        let config = DpdConfig::default();
        let mut state = DpdState::new();

        assert!(!state.is_dead(&config));

        state.retries = config.max_retries;

        assert!(state.is_dead(&config));
    }

    #[test]
    fn test_dpd_reset() {
        let mut state = DpdState::new();

        state.mark_sent(1);
        state.retries = 2;

        state.reset();

        assert!(!state.is_waiting());
        assert_eq!(state.retry_count(), 0);
        assert!(state.pending_message_id().is_none());
    }

    #[test]
    fn test_dpd_manager_new() {
        let config = DpdConfig::default();
        let manager = DpdManager::new(config.clone());

        assert_eq!(manager.config(), &config);
    }

    #[test]
    fn test_dpd_manager_check_status_alive() {
        let manager = DpdManager::default();

        assert_eq!(manager.check_status(), DpdStatus::Alive);
    }

    #[test]
    fn test_dpd_manager_check_status_send_request() {
        let mut config = DpdConfig::default();
        config.interval = Duration::from_millis(10);

        let mut manager = DpdManager::new(config);
        manager.state.last_activity = None;

        thread::sleep(Duration::from_millis(20));

        assert_eq!(manager.check_status(), DpdStatus::SendRequest);
    }

    #[test]
    fn test_dpd_manager_check_status_waiting() {
        let mut manager = DpdManager::default();

        manager.mark_sent(1);

        assert_eq!(manager.check_status(), DpdStatus::Waiting);
    }

    #[test]
    fn test_dpd_manager_check_status_timeout() {
        let mut config = DpdConfig::default();
        config.timeout = Duration::from_millis(10);

        let mut manager = DpdManager::new(config);

        manager.mark_sent(1);
        thread::sleep(Duration::from_millis(20));

        assert_eq!(manager.check_status(), DpdStatus::Timeout);
    }

    #[test]
    fn test_dpd_manager_check_status_dead() {
        let mut manager = DpdManager::default();

        manager.state.retries = manager.config.max_retries;

        assert_eq!(manager.check_status(), DpdStatus::Dead);
    }

    #[test]
    fn test_dpd_manager_mark_sent() {
        let mut manager = DpdManager::default();

        manager.mark_sent(42);

        assert!(manager.state().is_waiting());
        assert_eq!(manager.state().pending_message_id(), Some(42));
    }

    #[test]
    fn test_dpd_manager_mark_received() {
        let mut manager = DpdManager::default();

        manager.mark_sent(1);
        manager.mark_received();

        assert!(!manager.state().is_waiting());
        assert_eq!(manager.state().retry_count(), 0);
    }

    #[test]
    fn test_dpd_recent_activity_prevents_send() {
        let mut config = DpdConfig::default();
        config.interval = Duration::from_millis(100);

        let mut state = DpdState::new();

        // Mark recent activity
        state.mark_activity();

        // Should not send DPD (recent activity)
        assert!(!state.should_send(&config));

        // Wait for interval
        thread::sleep(Duration::from_millis(110));

        // Should send now (interval passed)
        assert!(state.should_send(&config));
    }
}
