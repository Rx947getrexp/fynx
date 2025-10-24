//! IPSec cryptographic operations
//!
//! This module provides cryptographic primitives for IKEv2 and ESP:
//! - PRF (Pseudo-Random Functions)
//! - Key Derivation Functions
//! - AEAD ciphers for IKE messages
//! - Diffie-Hellman key exchange (reused from SSH)

pub mod prf;

pub use prf::*;
