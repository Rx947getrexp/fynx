//! IPSec protocol implementation (IKEv2 + ESP)
//!
//! This module implements the Internet Protocol Security (IPSec) protocol suite,
//! including:
//!
//! - **IKEv2** (Internet Key Exchange v2) - RFC 7296
//! - **ESP** (Encapsulating Security Payload) - RFC 4303
//! - **NAT-T** (NAT Traversal) - RFC 3948
//!
//! # Overview
//!
//! IPSec provides security services for IP communications:
//! - **Confidentiality**: Encryption of IP packets
//! - **Authentication**: Verification of packet origin
//! - **Integrity**: Detection of packet tampering
//! - **Anti-replay**: Protection against replay attacks
//!
//! # Architecture
//!
//! ```text
//! IKEv2 Control Plane (UDP 500/4500)
//!   ├── SA Negotiation
//!   ├── Authentication (PSK, X.509)
//!   └── Key Management
//!        ↓
//! ESP Data Plane (IP Protocol 50)
//!   ├── Encryption (AES-GCM, ChaCha20-Poly1305)
//!   ├── Authentication (HMAC-SHA2)
//!   └── Anti-Replay Protection
//! ```
//!
//! # Example (Future API)
//!
//! ```rust,ignore
//! use fynx_proto::ipsec::IpsecClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = IpsecClient::new()
//!         .with_psk("my-secret-key")
//!         .with_local_id("client@example.com");
//!
//!     client.connect("vpn.example.com:500").await?;
//!     client.send_packet(&data).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # References
//!
//! - [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296) - IKEv2 Protocol
//! - [RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303) - ESP Protocol
//! - [RFC 3948](https://datatracker.ietf.org/doc/html/rfc3948) - NAT Traversal
//!
//! # Security
//!
//! This implementation follows security best practices:
//! - No unsafe code
//! - Constant-time cryptographic operations
//! - Secure memory handling with zeroization
//! - Comprehensive input validation

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod ikev2;

// Re-export commonly used types
pub use error::{Error, Result};
