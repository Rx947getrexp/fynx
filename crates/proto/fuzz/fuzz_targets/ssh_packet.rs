//! Fuzz target for SSH packet parsing.
//!
//! This fuzzer tests the packet parser against random input to find:
//! - Panics
//! - Memory safety issues
//! - Infinite loops
//! - Incorrect error handling
//!
//! Run with:
//! ```bash
//! cd crates/proto
//! cargo +nightly fuzz run ssh_packet -- -max_total_time=300
//! ```

#![no_main]
use libfuzzer_sys::fuzz_target;
use fynx_proto::ssh::Packet;

fuzz_target!(|data: &[u8]| {
    // Try to parse the packet
    let _ = Packet::from_bytes(data);

    // If parsing succeeds, ensure round-trip works
    if let Ok(packet) = Packet::from_bytes(data) {
        let serialized = packet.to_bytes();
        let reparsed = Packet::from_bytes(&serialized).expect("Round-trip parsing should never fail");

        // Payload should be identical
        assert_eq!(packet.payload(), reparsed.payload());
    }
});
