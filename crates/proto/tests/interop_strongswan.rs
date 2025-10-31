//! strongSwan Interoperability Test Suite
//!
//! Entry point for running interoperability tests with strongSwan.
//!
//! # Prerequisites
//!
//! 1. **strongSwan Installation**:
//!    - Ubuntu/Debian: `sudo apt install strongswan`
//!    - macOS: `brew install strongswan`
//!
//! 2. **Configuration**:
//!    - Copy test configurations to `/etc/strongswan/`
//!    - See `docs/ipsec/STAGE4_INTEROP_GUIDE.md` for details
//!
//! 3. **Permissions**:
//!    - Tests require root/sudo for port 500
//!
//! # Running Tests
//!
//! ## Run All Tests
//!
//! ```bash
//! # Start strongSwan first
//! sudo ipsec start
//!
//! # Run all interop tests
//! cargo test --test interop_strongswan --features ipsec -- --test-threads=1 --ignored
//! ```
//!
//! ## Run Specific Test
//!
//! ```bash
//! cargo test --test interop_strongswan test_fynx_client_to_strongswan_server \
//!   --features ipsec -- --ignored --nocapture
//! ```
//!
//! ## With Verbose Logging
//!
//! ```bash
//! RUST_LOG=fynx_proto::ipsec=trace cargo test --test interop_strongswan \
//!   --features ipsec -- --ignored --nocapture
//! ```
//!
//! # Test Results
//!
//! Tests are marked `#[ignore]` because they require external strongSwan setup.
//! Use `--ignored` flag to run them.
//!
//! Expected results when strongSwan is properly configured:
//!
//! ```text
//! running 10 tests
//! test test_fynx_client_to_strongswan_server ... ok
//! test test_strongswan_client_to_fynx_server ... ok
//! test test_cipher_suite_aes128gcm ... ok
//! test test_cipher_suite_aes256gcm ... ok
//! test test_cipher_suite_chacha20poly1305 ... ok
//! test test_nat_traversal ... ok (manual)
//! test test_dead_peer_detection ... ok (manual)
//! test test_ike_sa_rekey ... ok (long-running)
//! test test_child_sa_rekey ... ok (long-running)
//! test test_bidirectional_data_transfer ... ok
//!
//! test result: ok. 10 passed; 0 failed; 0 ignored
//! ```

#![cfg(feature = "ipsec")]

// Include strongSwan interop tests
// Tests are in the interop/strongswan.rs module
#[path = "interop/strongswan.rs"]
mod strongswan_tests;
