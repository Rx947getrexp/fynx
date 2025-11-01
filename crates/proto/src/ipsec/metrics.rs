//! Metrics for IPSec operations
//!
//! Provides counters and gauges for monitoring IPSec performance and health.
//! All metrics use atomic operations for thread-safe updates.
//!
//! # Example
//!
//! ```
//! use fynx_proto::ipsec::metrics::IpsecMetrics;
//!
//! let metrics = IpsecMetrics::new();
//!
//! // Record handshake
//! metrics.record_handshake_started();
//! // ... perform handshake ...
//! metrics.record_handshake_completed();
//!
//! // Record ESP packet
//! metrics.record_esp_encrypted(1500);
//!
//! // Get snapshot for monitoring
//! let snapshot = metrics.snapshot();
//! println!("Handshakes: {}", snapshot.ike_handshakes_total);
//! println!("ESP packets: {}", snapshot.esp_packets_encrypted);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// IPSec metrics for monitoring
///
/// Provides thread-safe atomic counters for all IPSec operations.
/// Metrics can be exported for monitoring systems like Prometheus.
#[derive(Debug, Clone)]
pub struct IpsecMetrics {
    /// Total IKE handshakes initiated
    pub ike_handshakes_total: Arc<AtomicU64>,

    /// Successfully completed IKE handshakes
    pub ike_handshakes_completed: Arc<AtomicU64>,

    /// Failed IKE handshakes
    pub ike_handshake_failures: Arc<AtomicU64>,

    /// Total ESP packets encrypted
    pub esp_packets_encrypted: Arc<AtomicU64>,

    /// Total bytes encrypted via ESP
    pub esp_bytes_encrypted: Arc<AtomicU64>,

    /// Total ESP packets decrypted
    pub esp_packets_decrypted: Arc<AtomicU64>,

    /// Total bytes decrypted via ESP
    pub esp_bytes_decrypted: Arc<AtomicU64>,

    /// Replay attacks detected and prevented
    pub esp_replay_detected: Arc<AtomicU64>,

    /// IKE SAs rekeyed
    pub ike_sa_rekeyed: Arc<AtomicU64>,

    /// Child SAs rekeyed
    pub child_sa_rekeyed: Arc<AtomicU64>,

    /// DPD checks performed
    pub dpd_checks_total: Arc<AtomicU64>,

    /// DPD timeouts (peer not responding)
    pub dpd_timeout: Arc<AtomicU64>,

    /// Currently active IKE SAs
    pub ike_sa_active: Arc<AtomicU64>,

    /// Currently active Child SAs
    pub child_sa_active: Arc<AtomicU64>,

    /// IKE SAs deleted
    pub ike_sa_deleted: Arc<AtomicU64>,

    /// Child SAs deleted
    pub child_sa_deleted: Arc<AtomicU64>,

    /// Proposal negotiation failures
    pub proposal_negotiation_failed: Arc<AtomicU64>,

    /// Authentication failures
    pub authentication_failed: Arc<AtomicU64>,
}

impl IpsecMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self {
            ike_handshakes_total: Arc::new(AtomicU64::new(0)),
            ike_handshakes_completed: Arc::new(AtomicU64::new(0)),
            ike_handshake_failures: Arc::new(AtomicU64::new(0)),
            esp_packets_encrypted: Arc::new(AtomicU64::new(0)),
            esp_bytes_encrypted: Arc::new(AtomicU64::new(0)),
            esp_packets_decrypted: Arc::new(AtomicU64::new(0)),
            esp_bytes_decrypted: Arc::new(AtomicU64::new(0)),
            esp_replay_detected: Arc::new(AtomicU64::new(0)),
            ike_sa_rekeyed: Arc::new(AtomicU64::new(0)),
            child_sa_rekeyed: Arc::new(AtomicU64::new(0)),
            dpd_checks_total: Arc::new(AtomicU64::new(0)),
            dpd_timeout: Arc::new(AtomicU64::new(0)),
            ike_sa_active: Arc::new(AtomicU64::new(0)),
            child_sa_active: Arc::new(AtomicU64::new(0)),
            ike_sa_deleted: Arc::new(AtomicU64::new(0)),
            child_sa_deleted: Arc::new(AtomicU64::new(0)),
            proposal_negotiation_failed: Arc::new(AtomicU64::new(0)),
            authentication_failed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record IKE handshake started
    pub fn record_handshake_started(&self) {
        self.ike_handshakes_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record IKE handshake completed successfully
    pub fn record_handshake_completed(&self) {
        self.ike_handshakes_completed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record IKE handshake failed
    pub fn record_handshake_failed(&self) {
        self.ike_handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record ESP packet encrypted
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes encrypted
    pub fn record_esp_encrypted(&self, bytes: usize) {
        self.esp_packets_encrypted.fetch_add(1, Ordering::Relaxed);
        self.esp_bytes_encrypted
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record ESP packet decrypted
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes decrypted
    pub fn record_esp_decrypted(&self, bytes: usize) {
        self.esp_packets_decrypted.fetch_add(1, Ordering::Relaxed);
        self.esp_bytes_decrypted
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record replay attack detected
    pub fn record_replay_detected(&self) {
        self.esp_replay_detected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record IKE SA created
    pub fn record_ike_sa_created(&self) {
        self.ike_sa_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record IKE SA deleted
    pub fn record_ike_sa_deleted(&self) {
        self.ike_sa_active.fetch_sub(1, Ordering::Relaxed);
        self.ike_sa_deleted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record IKE SA rekeyed
    pub fn record_ike_sa_rekeyed(&self) {
        self.ike_sa_rekeyed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record Child SA created
    pub fn record_child_sa_created(&self) {
        self.child_sa_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record Child SA deleted
    pub fn record_child_sa_deleted(&self) {
        self.child_sa_active.fetch_sub(1, Ordering::Relaxed);
        self.child_sa_deleted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record Child SA rekeyed
    pub fn record_child_sa_rekeyed(&self) {
        self.child_sa_rekeyed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record DPD check performed
    ///
    /// # Arguments
    ///
    /// * `success` - Whether peer responded
    pub fn record_dpd_check(&self, success: bool) {
        self.dpd_checks_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.dpd_timeout.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record proposal negotiation failure
    pub fn record_proposal_negotiation_failed(&self) {
        self.proposal_negotiation_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record authentication failure
    pub fn record_authentication_failed(&self) {
        self.authentication_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current metrics snapshot
    ///
    /// Returns a point-in-time view of all metrics.
    /// Values may be slightly inconsistent across metrics due to concurrent updates.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            ike_handshakes_total: self.ike_handshakes_total.load(Ordering::Relaxed),
            ike_handshakes_completed: self.ike_handshakes_completed.load(Ordering::Relaxed),
            ike_handshake_failures: self.ike_handshake_failures.load(Ordering::Relaxed),
            esp_packets_encrypted: self.esp_packets_encrypted.load(Ordering::Relaxed),
            esp_bytes_encrypted: self.esp_bytes_encrypted.load(Ordering::Relaxed),
            esp_packets_decrypted: self.esp_packets_decrypted.load(Ordering::Relaxed),
            esp_bytes_decrypted: self.esp_bytes_decrypted.load(Ordering::Relaxed),
            esp_replay_detected: self.esp_replay_detected.load(Ordering::Relaxed),
            ike_sa_rekeyed: self.ike_sa_rekeyed.load(Ordering::Relaxed),
            child_sa_rekeyed: self.child_sa_rekeyed.load(Ordering::Relaxed),
            dpd_checks_total: self.dpd_checks_total.load(Ordering::Relaxed),
            dpd_timeout: self.dpd_timeout.load(Ordering::Relaxed),
            ike_sa_active: self.ike_sa_active.load(Ordering::Relaxed),
            child_sa_active: self.child_sa_active.load(Ordering::Relaxed),
            ike_sa_deleted: self.ike_sa_deleted.load(Ordering::Relaxed),
            child_sa_deleted: self.child_sa_deleted.load(Ordering::Relaxed),
            proposal_negotiation_failed: self.proposal_negotiation_failed.load(Ordering::Relaxed),
            authentication_failed: self.authentication_failed.load(Ordering::Relaxed),
        }
    }

    /// Reset all metrics to zero
    ///
    /// Useful for testing or periodic resets in monitoring systems.
    pub fn reset(&self) {
        self.ike_handshakes_total.store(0, Ordering::Relaxed);
        self.ike_handshakes_completed.store(0, Ordering::Relaxed);
        self.ike_handshake_failures.store(0, Ordering::Relaxed);
        self.esp_packets_encrypted.store(0, Ordering::Relaxed);
        self.esp_bytes_encrypted.store(0, Ordering::Relaxed);
        self.esp_packets_decrypted.store(0, Ordering::Relaxed);
        self.esp_bytes_decrypted.store(0, Ordering::Relaxed);
        self.esp_replay_detected.store(0, Ordering::Relaxed);
        self.ike_sa_rekeyed.store(0, Ordering::Relaxed);
        self.child_sa_rekeyed.store(0, Ordering::Relaxed);
        self.dpd_checks_total.store(0, Ordering::Relaxed);
        self.dpd_timeout.store(0, Ordering::Relaxed);
        self.ike_sa_active.store(0, Ordering::Relaxed);
        self.child_sa_active.store(0, Ordering::Relaxed);
        self.ike_sa_deleted.store(0, Ordering::Relaxed);
        self.child_sa_deleted.store(0, Ordering::Relaxed);
        self.proposal_negotiation_failed.store(0, Ordering::Relaxed);
        self.authentication_failed.store(0, Ordering::Relaxed);
    }
}

impl Default for IpsecMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of all IPSec metrics
///
/// All values represent the state at the time `snapshot()` was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total IKE handshakes initiated
    pub ike_handshakes_total: u64,

    /// Successfully completed IKE handshakes
    pub ike_handshakes_completed: u64,

    /// Failed IKE handshakes
    pub ike_handshake_failures: u64,

    /// Total ESP packets encrypted
    pub esp_packets_encrypted: u64,

    /// Total bytes encrypted via ESP
    pub esp_bytes_encrypted: u64,

    /// Total ESP packets decrypted
    pub esp_packets_decrypted: u64,

    /// Total bytes decrypted via ESP
    pub esp_bytes_decrypted: u64,

    /// Replay attacks detected
    pub esp_replay_detected: u64,

    /// IKE SAs rekeyed
    pub ike_sa_rekeyed: u64,

    /// Child SAs rekeyed
    pub child_sa_rekeyed: u64,

    /// DPD checks performed
    pub dpd_checks_total: u64,

    /// DPD timeouts
    pub dpd_timeout: u64,

    /// Currently active IKE SAs
    pub ike_sa_active: u64,

    /// Currently active Child SAs
    pub child_sa_active: u64,

    /// Total IKE SAs deleted
    pub ike_sa_deleted: u64,

    /// Total Child SAs deleted
    pub child_sa_deleted: u64,

    /// Proposal negotiation failures
    pub proposal_negotiation_failed: u64,

    /// Authentication failures
    pub authentication_failed: u64,
}

impl MetricsSnapshot {
    /// Calculate IKE handshake success rate (0.0 to 1.0)
    pub fn handshake_success_rate(&self) -> f64 {
        if self.ike_handshakes_total == 0 {
            return 0.0;
        }
        self.ike_handshakes_completed as f64 / self.ike_handshakes_total as f64
    }

    /// Calculate average encrypted packet size in bytes
    pub fn avg_encrypted_packet_size(&self) -> f64 {
        if self.esp_packets_encrypted == 0 {
            return 0.0;
        }
        self.esp_bytes_encrypted as f64 / self.esp_packets_encrypted as f64
    }

    /// Calculate average decrypted packet size in bytes
    pub fn avg_decrypted_packet_size(&self) -> f64 {
        if self.esp_packets_decrypted == 0 {
            return 0.0;
        }
        self.esp_bytes_decrypted as f64 / self.esp_packets_decrypted as f64
    }

    /// Calculate DPD success rate (0.0 to 1.0)
    pub fn dpd_success_rate(&self) -> f64 {
        if self.dpd_checks_total == 0 {
            return 1.0; // No checks = no failures
        }
        let successes = self.dpd_checks_total - self.dpd_timeout;
        successes as f64 / self.dpd_checks_total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = IpsecMetrics::new();
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.ike_handshakes_total, 0);
        assert_eq!(snapshot.esp_packets_encrypted, 0);
    }

    #[test]
    fn test_handshake_metrics() {
        let metrics = IpsecMetrics::new();

        metrics.record_handshake_started();
        metrics.record_handshake_completed();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.ike_handshakes_total, 1);
        assert_eq!(snapshot.ike_handshakes_completed, 1);
        assert_eq!(snapshot.ike_handshake_failures, 0);
    }

    #[test]
    fn test_esp_metrics() {
        let metrics = IpsecMetrics::new();

        metrics.record_esp_encrypted(1500);
        metrics.record_esp_decrypted(1400);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.esp_packets_encrypted, 1);
        assert_eq!(snapshot.esp_bytes_encrypted, 1500);
        assert_eq!(snapshot.esp_packets_decrypted, 1);
        assert_eq!(snapshot.esp_bytes_decrypted, 1400);
    }

    #[test]
    fn test_sa_lifecycle_metrics() {
        let metrics = IpsecMetrics::new();

        metrics.record_ike_sa_created();
        metrics.record_child_sa_created();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.ike_sa_active, 1);
        assert_eq!(snapshot.child_sa_active, 1);

        metrics.record_ike_sa_deleted();
        metrics.record_child_sa_deleted();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.ike_sa_active, 0);
        assert_eq!(snapshot.child_sa_active, 0);
        assert_eq!(snapshot.ike_sa_deleted, 1);
        assert_eq!(snapshot.child_sa_deleted, 1);
    }

    #[test]
    fn test_dpd_metrics() {
        let metrics = IpsecMetrics::new();

        metrics.record_dpd_check(true);
        metrics.record_dpd_check(true);
        metrics.record_dpd_check(false);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.dpd_checks_total, 3);
        assert_eq!(snapshot.dpd_timeout, 1);
    }

    #[test]
    fn test_snapshot_calculations() {
        let metrics = IpsecMetrics::new();

        metrics.record_handshake_started();
        metrics.record_handshake_started();
        metrics.record_handshake_completed();

        metrics.record_esp_encrypted(1500);
        metrics.record_esp_encrypted(500);

        metrics.record_dpd_check(true);
        metrics.record_dpd_check(true);
        metrics.record_dpd_check(false);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.handshake_success_rate(), 0.5);
        assert_eq!(snapshot.avg_encrypted_packet_size(), 1000.0);
        assert!((snapshot.dpd_success_rate() - 0.666666).abs() < 0.001);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = IpsecMetrics::new();

        metrics.record_handshake_started();
        metrics.record_esp_encrypted(1500);

        let snapshot_before = metrics.snapshot();
        assert_eq!(snapshot_before.ike_handshakes_total, 1);
        assert_eq!(snapshot_before.esp_packets_encrypted, 1);

        metrics.reset();

        let snapshot_after = metrics.snapshot();
        assert_eq!(snapshot_after.ike_handshakes_total, 0);
        assert_eq!(snapshot_after.esp_packets_encrypted, 0);
    }

    #[test]
    fn test_metrics_clone() {
        let metrics1 = IpsecMetrics::new();
        metrics1.record_handshake_started();

        let metrics2 = metrics1.clone();
        metrics2.record_handshake_started();

        // Both should show 2 because they share the same Arc<AtomicU64>
        let snapshot1 = metrics1.snapshot();
        let snapshot2 = metrics2.snapshot();

        assert_eq!(snapshot1.ike_handshakes_total, 2);
        assert_eq!(snapshot2.ike_handshakes_total, 2);
    }
}
