//! Interoperability Tests
//!
//! This module contains interoperability tests with third-party IPSec implementations.
//!
//! # Available Test Suites
//!
//! - **strongSwan**: Tests against the strongSwan IPSec implementation
//!
//! # Running Tests
//!
//! These tests require external setup and are marked with `#[ignore]`.
//! Run with:
//!
//! ```bash
//! cargo test --test interop --features ipsec -- --ignored
//! ```
//!
//! See individual test modules for setup instructions.

#![cfg(feature = "ipsec")]

pub mod strongswan;
