//! Anti-Replay Protection for IPSec ESP
//!
//! Implements RFC 4303 Section 3.4.3 - Anti-Replay mechanism.
//!
//! # Overview
//!
//! The anti-replay window prevents attackers from capturing and replaying
//! valid ESP packets. Each inbound Child SA maintains a sliding window
//! of recently received sequence numbers using a bitmap.
//!
//! # Algorithm
//!
//! ```text
//! Window Size: 64 packets (configurable)
//!
//! Bitmap Representation:
//! ┌────────────────────────────────────────────────────────┐
//! │ MSB                                              LSB   │
//! │  63  62  61  ...  2   1   0                           │
//! │   ↑                        ↑                           │
//! │ Oldest              Newest (highest_seq)              │
//! └────────────────────────────────────────────────────────┘
//!
//! Bit = 1: Packet received
//! Bit = 0: Packet not received
//!
//! Example:
//! - highest_seq = 100
//! - window_size = 64
//! - Valid range: [37, 100]
//!
//! Incoming packet with seq=50:
//! - diff = 100 - 50 = 50
//! - bit_pos = 50
//! - Check bitmap bit 50
//! ```
//!
//! # References
//!
//! - [RFC 4303 Section 3.4.3](https://datatracker.ietf.org/doc/html/rfc4303#section-3.4.3)

#![warn(missing_docs)]

/// Default anti-replay window size (64 packets)
///
/// RFC 4303 recommends a minimum window size of 32.
/// Common implementations use 64 for better protection.
pub const DEFAULT_WINDOW_SIZE: u32 = 64;

/// Minimum allowed window size
pub const MIN_WINDOW_SIZE: u32 = 32;

/// Maximum window size (limited by bitmap storage)
pub const MAX_WINDOW_SIZE: u32 = 64;

/// Anti-Replay Window
///
/// Tracks received sequence numbers using a sliding window with bitmap.
/// Used by inbound Child SAs to detect and reject replay attacks.
///
/// # Example
///
/// ```rust,ignore
/// use fynx_proto::ipsec::replay::ReplayWindow;
///
/// let mut window = ReplayWindow::new(64);
///
/// // Accept new packet
/// assert!(window.check_and_update(1));
///
/// // Reject duplicate
/// assert!(!window.check_and_update(1));
///
/// // Accept newer packet
/// assert!(window.check_and_update(2));
/// ```
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest sequence number received so far
    highest_seq: u64,

    /// Bitmap of received packets within window
    ///
    /// Bit 0 (LSB) = highest_seq
    /// Bit 1 = highest_seq - 1
    /// Bit 63 (MSB) = highest_seq - 63
    bitmap: u64,

    /// Window size (number of packets to track)
    ///
    /// Must be between MIN_WINDOW_SIZE and MAX_WINDOW_SIZE
    window_size: u32,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }
}

impl ReplayWindow {
    /// Create new anti-replay window
    ///
    /// # Arguments
    ///
    /// * `window_size` - Number of packets to track (32-64)
    ///
    /// # Panics
    ///
    /// Panics if window_size is outside valid range
    pub fn new(window_size: u32) -> Self {
        assert!(
            (MIN_WINDOW_SIZE..=MAX_WINDOW_SIZE).contains(&window_size),
            "Window size must be between {} and {}",
            MIN_WINDOW_SIZE,
            MAX_WINDOW_SIZE
        );

        ReplayWindow {
            highest_seq: 0,
            bitmap: 0,
            window_size,
        }
    }

    /// Check sequence number and update window if valid
    ///
    /// Returns `true` if packet should be accepted, `false` if rejected.
    ///
    /// # Arguments
    ///
    /// * `seq` - Sequence number from ESP packet
    ///
    /// # Returns
    ///
    /// - `true`: Packet is valid, window updated
    /// - `false`: Packet rejected (duplicate, too old, or seq=0)
    ///
    /// # Algorithm
    ///
    /// 1. Reject seq=0 (RFC 4303: reserved, never used)
    /// 2. If seq > highest_seq: advance window, accept
    /// 3. If seq within window: check bitmap
    ///    - If already received: reject (duplicate)
    ///    - If not received: mark as received, accept
    /// 4. If seq too old (outside window): reject
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        // RFC 4303: Sequence number 0 is invalid (never transmitted)
        if seq == 0 {
            return false;
        }

        // First packet received
        if self.highest_seq == 0 {
            self.highest_seq = seq;
            self.bitmap = 1; // Mark seq as received (bit 0)
            return true;
        }

        if seq > self.highest_seq {
            // New packet advances window
            let shift = seq - self.highest_seq;

            // Shift bitmap left, clearing old bits
            if shift < 64 {
                self.bitmap <<= shift;
            } else {
                // Complete window shift, clear all bits
                self.bitmap = 0;
            }

            // Mark new packet as received (bit 0)
            self.bitmap |= 1;
            self.highest_seq = seq;
            true
        } else {
            // Packet within or before window
            let diff = self.highest_seq - seq;

            // Packet too old (outside window)
            // Window of size N accepts packets from [highest_seq - (N-1), highest_seq]
            // Example: window_size=64, highest=100 accepts [37, 100] (64 packets total)
            // diff=63 is inside (seq=37), diff=64 is outside (seq=36)
            if diff > self.window_size as u64 - 1 {
                return false;
            }

            // Check if already received
            let bit_pos = diff;
            let mask = 1u64 << bit_pos;

            if self.bitmap & mask != 0 {
                // Duplicate packet
                false
            } else {
                // New packet within window, mark as received
                self.bitmap |= mask;
                true
            }
        }
    }

    /// Get highest sequence number received
    pub fn highest_seq(&self) -> u64 {
        self.highest_seq
    }

    /// Get window size
    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    /// Get current bitmap (for debugging/testing)
    pub fn bitmap(&self) -> u64 {
        self.bitmap
    }

    /// Reset window to initial state
    pub fn reset(&mut self) {
        self.highest_seq = 0;
        self.bitmap = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window_new() {
        let window = ReplayWindow::new(64);
        assert_eq!(window.highest_seq(), 0);
        assert_eq!(window.bitmap(), 0);
        assert_eq!(window.window_size(), 64);
    }

    #[test]
    fn test_replay_window_default() {
        let window = ReplayWindow::default();
        assert_eq!(window.window_size(), DEFAULT_WINDOW_SIZE);
    }

    #[test]
    #[should_panic(expected = "Window size must be between")]
    fn test_replay_window_invalid_size_too_small() {
        ReplayWindow::new(31); // Below minimum
    }

    #[test]
    #[should_panic(expected = "Window size must be between")]
    fn test_replay_window_invalid_size_too_large() {
        ReplayWindow::new(65); // Above maximum
    }

    #[test]
    fn test_reject_sequence_zero() {
        let mut window = ReplayWindow::new(64);
        assert!(!window.check_and_update(0));
        assert_eq!(window.highest_seq(), 0);
    }

    #[test]
    fn test_accept_first_packet() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(1));
        assert_eq!(window.highest_seq(), 1);
        assert_eq!(window.bitmap(), 1);
    }

    #[test]
    fn test_reject_duplicate_packet() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(1));
        assert!(!window.check_and_update(1)); // Duplicate
    }

    #[test]
    fn test_accept_sequential_packets() {
        let mut window = ReplayWindow::new(64);
        for i in 1..=10 {
            assert!(window.check_and_update(i), "Failed at seq {}", i);
        }
        assert_eq!(window.highest_seq(), 10);
    }

    #[test]
    fn test_accept_out_of_order_within_window() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(10));
        assert!(window.check_and_update(5)); // Earlier, but within window
        assert!(window.check_and_update(8));
        assert!(window.check_and_update(3));
    }

    #[test]
    fn test_reject_duplicate_out_of_order() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(10));
        assert!(window.check_and_update(5));
        assert!(!window.check_and_update(5)); // Duplicate
    }

    #[test]
    fn test_reject_packet_outside_window() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(100));

        // Window size 64 accepts range [highest - 63, highest] = [37, 100]
        // seq=36 is 64 behind (diff=64 > 63), outside window
        assert!(!window.check_and_update(36));

        // seq=37 is 63 behind (diff=63 <= 63), at window edge, should be accepted
        assert!(window.check_and_update(37));

        // seq=35 is 65 behind (diff=65 > 63), outside window
        assert!(!window.check_and_update(35));
    }

    #[test]
    fn test_window_sliding() {
        let mut window = ReplayWindow::new(64);

        // Initialize window at seq=100
        assert!(window.check_and_update(100));

        // Fill some of the window
        assert!(window.check_and_update(90));
        assert!(window.check_and_update(95));

        // Advance window
        assert!(window.check_and_update(150));
        assert_eq!(window.highest_seq(), 150);

        // Old packets now outside window
        assert!(!window.check_and_update(85)); // Too old (150 - 85 = 65 > 63)

        // seq=90 was already received before window slid
        // After sliding 50 positions, the bit for seq=90 is still marked
        // (bit 10 became bit 60 after left shift of 50)
        // So it should be rejected as duplicate
        assert!(!window.check_and_update(90)); // Duplicate (already received)

        // seq=87 is within new window [87, 150] and not received yet
        assert!(window.check_and_update(87)); // New packet in window
    }

    #[test]
    fn test_large_gap_advance() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(10));

        // Large gap (>64) should clear bitmap
        assert!(window.check_and_update(200));
        assert_eq!(window.highest_seq(), 200);

        // Old packet should be rejected
        assert!(!window.check_and_update(10));
    }

    #[test]
    fn test_bitmap_tracking() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(10));

        // Bitmap should have bit 0 set (highest_seq = 10)
        assert_eq!(window.bitmap() & 1, 1);

        // Receive seq=8 (diff=2, bit_pos=2)
        assert!(window.check_and_update(8));
        assert_eq!(window.bitmap() & 0b101, 0b101); // Bits 0 and 2 set
    }

    #[test]
    fn test_reset() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(10));
        assert!(window.check_and_update(20));

        window.reset();
        assert_eq!(window.highest_seq(), 0);
        assert_eq!(window.bitmap(), 0);

        // Can accept packets again after reset
        assert!(window.check_and_update(1));
    }

    #[test]
    fn test_edge_case_exactly_64_behind() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(100));

        // seq=36 is exactly 64 behind (100 - 36 = 64)
        // Should be rejected (outside window: diff >= window_size)
        assert!(!window.check_and_update(36));
    }

    #[test]
    fn test_edge_case_63_behind() {
        let mut window = ReplayWindow::new(64);
        assert!(window.check_and_update(100));

        // seq=37 is 63 behind (100 - 37 = 63)
        // Should be accepted (inside window: diff < window_size)
        assert!(window.check_and_update(37));
    }

    #[test]
    fn test_first_packet_not_one() {
        let mut window = ReplayWindow::new(64);

        // First packet can have any sequence number
        assert!(window.check_and_update(1000));
        assert_eq!(window.highest_seq(), 1000);

        // Earlier packets within window should work
        assert!(window.check_and_update(950));
    }

    #[test]
    fn test_window_size_32() {
        let mut window = ReplayWindow::new(32);
        assert!(window.check_and_update(100));

        // 32-packet window: valid range is [69, 100]
        assert!(!window.check_and_update(68)); // Outside
        assert!(window.check_and_update(69)); // Edge
        assert!(window.check_and_update(80)); // Inside
    }
}
