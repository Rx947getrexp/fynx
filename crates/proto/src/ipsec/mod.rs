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
//! # Quick Start
//!
//! ## Client Example
//!
//! ```rust,no_run
//! use fynx_proto::ipsec::{IpsecClient, ClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure client
//!     let config = ClientConfig::builder()
//!         .with_local_id("client@example.com")
//!         .with_remote_id("server@example.com")
//!         .with_psk(b"my-secret-key")
//!         .build()?;
//!
//!     // Create client and connect
//!     let mut client = IpsecClient::new(config);
//!     client.connect("10.0.0.1:500".parse()?).await?;
//!
//!     // Send and receive encrypted data
//!     client.send_packet(b"Hello, VPN!").await?;
//!     let response = client.recv_packet().await?;
//!     println!("Received: {:?}", response);
//!
//!     // Graceful shutdown
//!     client.shutdown().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Server Example
//!
//! ```rust,no_run
//! use fynx_proto::ipsec::{IpsecServer, ServerConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure server
//!     let config = ServerConfig::builder()
//!         .with_local_id("server@example.com")
//!         .with_psk(b"my-secret-key")
//!         .build()?;
//!
//!     // Bind server
//!     let mut server = IpsecServer::bind(config, "0.0.0.0:500".parse()?).await?;
//!     println!("IPSec server listening on port 500");
//!
//!     // Accept client connection
//!     let (peer_addr, mut session) = server.accept().await?;
//!     println!("Client connected from: {}", peer_addr);
//!
//!     // Handle encrypted data
//!     // Note: In production, spawn this in a separate task
//!     loop {
//!         match server.recv_packet().await {
//!             Ok((addr, data)) => {
//!                 println!("Received from {}: {:?}", addr, data);
//!                 // Echo back
//!                 server.send_packet(addr, &data).await?;
//!             }
//!             Err(e) => {
//!                 eprintln!("Error: {}", e);
//!                 break;
//!             }
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **IKEv2 Handshake**: Automatic negotiation of Security Associations
//! - **ESP Encryption**: AES-GCM-128/256, ChaCha20-Poly1305
//! - **PSK Authentication**: Pre-shared key authentication
//! - **NAT Traversal**: Automatic NAT-T detection and handling
//! - **Dead Peer Detection**: Automatic peer liveness monitoring
//! - **SA Rekeying**: Automatic Security Association renewal
//! - **Anti-Replay**: Sequence number validation and replay protection
//! - **Production Ready**: Structured logging, metrics, error handling
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

pub mod child_sa;
pub mod client;
pub mod config;
pub mod crypto;
pub mod dpd;
pub mod error;
pub mod esp;
pub mod ikev2;
pub mod logging;
pub mod metrics;
pub mod nat;
pub mod replay;
pub mod server;

// Re-export commonly used types
pub use client::IpsecClient;
pub use config::{ClientConfig, ServerConfig};
pub use error::{Error, Result};
pub use server::{IpsecServer, IpsecSession};
