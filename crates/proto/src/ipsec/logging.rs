//! Structured logging for IPSec operations
//!
//! Provides structured, contextual logging using the `tracing` framework.
//! All log messages include relevant context fields for debugging and monitoring.
//!
//! # Log Levels
//!
//! - **TRACE**: Detailed protocol state and message contents
//! - **DEBUG**: ESP packet processing, sequence numbers
//! - **INFO**: IKE state transitions, handshake events
//! - **WARN**: Retryable errors, unusual but valid conditions
//! - **ERROR**: Failed operations, authentication failures
//!
//! # Example
//!
//! ```no_run
//! use fynx_proto::ipsec::logging;
//!
//! // Initialize tracing subscriber (in tests or applications)
//! tracing_subscriber::fmt()
//!     .with_env_filter("fynx_proto::ipsec=debug")
//!     .init();
//!
//! // Log IKE state transition
//! logging::log_ike_state_transition(
//!     &[0x01, 0x02, 0x03, 0x04],
//!     &[0x05, 0x06, 0x07, 0x08],
//!     "INIT",
//!     "ESTABLISHED"
//! );
//! ```

use tracing::{debug, error, info, trace, warn};

/// Log IKE SA state transition 
///
/// # Arguments
///
/// * `spi_i` - Initiator SPI
/// * `spi_r` - Responder SPI
/// * `old_state` - Previous IKE SA state
/// * `new_state` - New IKE SA state
pub fn log_ike_state_transition(spi_i: &[u8], spi_r: &[u8], old_state: &str, new_state: &str) {
    info!(
        ike_spi_i = %hex::encode(spi_i),
        ike_spi_r = %hex::encode(spi_r),
        state_from = old_state,
        state_to = new_state,
        "IKE SA state transition"
    );
}

/// Log ESP packet processing
///
/// # Arguments
///
/// * `operation` - "encrypt" or "decrypt"
/// * `spi` - ESP Security Parameter Index
/// * `seq` - Sequence number
/// * `payload_len` - Payload length in bytes
pub fn log_esp_packet(operation: &str, spi: u32, seq: u32, payload_len: usize) {
    debug!(
        operation = operation,
        child_spi = spi,
        seq_num = seq,
        payload_len = payload_len,
        "ESP packet processed"
    );
}

/// Log IKE handshake start
///
/// # Arguments
///
/// * `peer_addr` - Peer IP address and port
/// * `role` - "initiator" or "responder"
pub fn log_handshake_start(peer_addr: &str, role: &str) {
    info!(
        peer = peer_addr,
        role = role,
        "IKE handshake started"
    );
}

/// Log IKE handshake completion
///
/// # Arguments
///
/// * `peer_addr` - Peer IP address and port
/// * `duration_ms` - Handshake duration in milliseconds
pub fn log_handshake_complete(peer_addr: &str, duration_ms: u64) {
    info!(
        peer = peer_addr,
        duration_ms = duration_ms,
        "IKE handshake completed successfully"
    );
}

/// Log IKE handshake failure
///
/// # Arguments
///
/// * `peer_addr` - Peer IP address and port
/// * `error` - Error message
pub fn log_handshake_failed(peer_addr: &str, error: &str) {
    error!(
        peer = peer_addr,
        error = error,
        "IKE handshake failed"
    );
}

/// Log IKE SA rekey start
///
/// # Arguments
///
/// * `old_spi_i` - Old initiator SPI
/// * `old_spi_r` - Old responder SPI
pub fn log_ike_rekey_start(old_spi_i: &[u8], old_spi_r: &[u8]) {
    info!(
        old_spi_i = %hex::encode(old_spi_i),
        old_spi_r = %hex::encode(old_spi_r),
        "IKE SA rekey started"
    );
}

/// Log IKE SA rekey completion
///
/// # Arguments
///
/// * `old_spi_i` - Old initiator SPI
/// * `new_spi_i` - New initiator SPI
/// * `new_spi_r` - New responder SPI
pub fn log_ike_rekey_complete(old_spi_i: &[u8], new_spi_i: &[u8], new_spi_r: &[u8]) {
    info!(
        old_spi_i = %hex::encode(old_spi_i),
        new_spi_i = %hex::encode(new_spi_i),
        new_spi_r = %hex::encode(new_spi_r),
        "IKE SA rekey completed successfully"
    );
}

/// Log Child SA creation
///
/// # Arguments
///
/// * `child_spi` - Child SA SPI
/// * `protocol` - IPSec protocol (50 for ESP, 51 for AH)
pub fn log_child_sa_created(child_spi: u32, protocol: u8) {
    info!(
        child_spi = child_spi,
        protocol = protocol,
        "Child SA created"
    );
}

/// Log Child SA rekey start
///
/// # Arguments
///
/// * `old_spi` - Old Child SA SPI
pub fn log_child_rekey_start(old_spi: u32) {
    info!(
        old_child_spi = old_spi,
        "Child SA rekey started"
    );
}

/// Log Child SA rekey completion
///
/// # Arguments
///
/// * `old_spi` - Old Child SA SPI
/// * `new_spi` - New Child SA SPI
pub fn log_child_rekey_complete(old_spi: u32, new_spi: u32) {
    info!(
        old_child_spi = old_spi,
        new_child_spi = new_spi,
        "Child SA rekey completed successfully"
    );
}

/// Log Child SA deletion
///
/// # Arguments
///
/// * `child_spi` - Child SA SPI to delete
/// * `reason` - Deletion reason (e.g., "shutdown", "rekey", "lifetime")
pub fn log_child_sa_deleted(child_spi: u32, reason: &str) {
    info!(
        child_spi = child_spi,
        reason = reason,
        "Child SA deleted"
    );
}

/// Log DPD check
///
/// # Arguments
///
/// * `peer_addr` - Peer IP address
/// * `success` - Whether peer responded
pub fn log_dpd_check(peer_addr: &str, success: bool) {
    if success {
        debug!(peer = peer_addr, "DPD check successful");
    } else {
        warn!(peer = peer_addr, "DPD check failed - peer not responding");
    }
}

/// Log proposal negotiation
///
/// # Arguments
///
/// * `offered` - Number of proposals offered
/// * `chosen_id` - ID of chosen proposal, or None if no match
pub fn log_proposal_negotiation(offered: usize, chosen_id: Option<u8>) {
    match chosen_id {
        Some(id) => {
            debug!(
                proposals_offered = offered,
                chosen_id = id,
                "Proposal negotiation successful"
            );
        }
        None => {
            warn!(
                proposals_offered = offered,
                "Proposal negotiation failed - no acceptable proposal"
            );
        }
    }
}

/// Log replay detection
///
/// # Arguments
///
/// * `child_spi` - Child SA SPI
/// * `seq` - Sequence number that triggered replay detection
pub fn log_replay_detected(child_spi: u32, seq: u32) {
    warn!(
        child_spi = child_spi,
        seq_num = seq,
        "Replay attack detected - packet rejected"
    );
}

/// Log authentication success
///
/// # Arguments
///
/// * `peer_id` - Peer identity
/// * `auth_method` - Authentication method used (e.g., "PSK", "RSA")
pub fn log_authentication_success(peer_id: &str, auth_method: &str) {
    info!(
        peer_id = peer_id,
        auth_method = auth_method,
        "Peer authenticated successfully"
    );
}

/// Log authentication failure
///
/// # Arguments
///
/// * `peer_id` - Peer identity
/// * `reason` - Failure reason
pub fn log_authentication_failed(peer_id: &str, reason: &str) {
    error!(
        peer_id = peer_id,
        reason = reason,
        "Peer authentication failed"
    );
}

/// Log generic error with context
///
/// # Arguments
///
/// * `context` - Context where error occurred (e.g., "IKE_SA_INIT", "ESP encryption")
/// * `error` - Error message
pub fn log_error(context: &str, error: &str) {
    error!(context = context, error = error, "IPSec error occurred");
}

/// Log protocol message send
///
/// # Arguments
///
/// * `msg_type` - Message type (e.g., "IKE_SA_INIT", "IKE_AUTH")
/// * `peer_addr` - Peer address
/// * `size_bytes` - Message size in bytes
pub fn log_message_send(msg_type: &str, peer_addr: &str, size_bytes: usize) {
    trace!(
        msg_type = msg_type,
        peer = peer_addr,
        size_bytes = size_bytes,
        "Sending IKE message"
    );
}

/// Log protocol message receive
///
/// # Arguments
///
/// * `msg_type` - Message type (e.g., "IKE_SA_INIT", "IKE_AUTH")
/// * `peer_addr` - Peer address
/// * `size_bytes` - Message size in bytes
pub fn log_message_recv(msg_type: &str, peer_addr: &str, size_bytes: usize) {
    trace!(
        msg_type = msg_type,
        peer = peer_addr,
        size_bytes = size_bytes,
        "Received IKE message"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_functions() {
        // These tests just verify the functions compile and execute
        // Actual log output would require tracing subscriber setup

        log_ike_state_transition(
            &[0x01, 0x02, 0x03, 0x04],
            &[0x05, 0x06, 0x07, 0x08],
            "INIT",
            "ESTABLISHED",
        );

        log_esp_packet("encrypt", 12345, 100, 1500);

        log_handshake_start("10.0.0.1:500", "initiator");
        log_handshake_complete("10.0.0.1:500", 150);
        log_handshake_failed("10.0.0.1:500", "timeout");

        log_ike_rekey_start(&[0x01, 0x02], &[0x03, 0x04]);
        log_ike_rekey_complete(&[0x01, 0x02], &[0x05, 0x06], &[0x07, 0x08]);

        log_child_sa_created(12345, 50);
        log_child_rekey_start(12345);
        log_child_rekey_complete(12345, 67890);
        log_child_sa_deleted(12345, "shutdown");

        log_dpd_check("10.0.0.1", true);
        log_dpd_check("10.0.0.1", false);

        log_proposal_negotiation(3, Some(1));
        log_proposal_negotiation(3, None);

        log_replay_detected(12345, 100);

        log_authentication_success("client@example.com", "PSK");
        log_authentication_failed("client@example.com", "invalid PSK");

        log_error("ESP encryption", "invalid key length");

        log_message_send("IKE_SA_INIT", "10.0.0.1:500", 256);
        log_message_recv("IKE_SA_INIT", "10.0.0.1:500", 256);
    }
}
