//! Protocol implementations for the Fynx security ecosystem.
//!
//! This crate provides Rust implementations of various network security protocols:
//!
//! - **SSH** (Secure Shell) - RFC 4251-4254 compliant implementation
//! - **DTLS** (Datagram Transport Layer Security) - Coming in Phase 2
//! - **IPSec** (Internet Protocol Security) - Coming in Phase 2
//!
//! # Features
//!
//! - `ssh` (default) - SSH protocol support (client + server)
//! - `dtls` - DTLS protocol support
//! - `ipsec` - IPSec protocol support
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::Packet;
//!
//! // Create and serialize an SSH packet
//! let packet = Packet::new(b"SSH message payload".to_vec());
//! let wire_format = packet.to_bytes();
//!
//! // Parse from wire format
//! let parsed = Packet::from_bytes(&wire_format).unwrap();
//! assert_eq!(parsed.payload(), b"SSH message payload");
//! ```
//!
//! Full client/server API coming in Stage 5 (see IMPLEMENTATION_PLAN.md)
//!
//! # Security
//!
//! This crate follows OpenSSF Best Practices (Gold Level):
//! - All cryptographic operations use vetted libraries (`ring`, `dalek`)
//! - Constant-time operations for authentication
//! - Secure memory handling with `zeroize`
//! - Comprehensive testing including fuzz testing
//!
//! # References
//!
//! - [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251) - SSH Protocol Architecture
//! - [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) - SSH Authentication Protocol
//! - [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253) - SSH Transport Layer Protocol
//! - [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254) - SSH Connection Protocol

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "ssh")]
pub mod ssh;
