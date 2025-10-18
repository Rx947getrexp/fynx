//! SSH (Secure Shell) protocol implementation.
//!
//! This module implements the SSH protocol according to RFC 4251-4254.
//!
//! # Architecture
//!
//! The SSH implementation is layered:
//!
//! 1. **Packet Layer** ([`packet`]) - Binary packet protocol (RFC 4253 Section 6)
//! 2. **Transport Layer** ([`transport`]) - Key exchange, encryption, MAC (RFC 4253)
//! 3. **Authentication Layer** ([`auth`]) - User authentication (RFC 4252)
//! 4. **Connection Layer** ([`connection`]) - Channels and requests (RFC 4254)
//! 5. **Client/Server APIs** - High-level interfaces (coming in Stage 5)
//!
//! # Security Considerations
//!
//! This implementation prioritizes security:
//!
//! - **Input Validation**: All packet parsing validates size limits (max 35000 bytes)
//! - **Constant-Time Operations**: Authentication uses constant-time comparisons
//! - **Memory Safety**: Secrets are zeroized on drop using [`zeroize`]
//! - **Modern Algorithms**: Prefers ChaCha20-Poly1305, Curve25519, Ed25519
//! - **No Unsafe Code**: Pure Rust implementation without `unsafe`
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::Packet;
//!
//! // Create a packet
//! let packet = Packet::new(b"SSH-MSG-KEXINIT payload".to_vec());
//!
//! // Serialize to wire format
//! let bytes = packet.to_bytes();
//!
//! // Parse from wire format
//! let parsed = Packet::from_bytes(&bytes).unwrap();
//! assert_eq!(parsed.payload(), b"SSH-MSG-KEXINIT payload");
//! ```
//!
//! Full client/server API coming in Stage 5 (see IMPLEMENTATION_PLAN.md)
//!
//! # References
//!
//! - [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251) - SSH Protocol Architecture
//! - [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) - SSH Authentication Protocol
//! - [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253) - SSH Transport Layer Protocol
//! - [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254) - SSH Connection Protocol

pub mod auth;
pub mod authorized_keys;
pub mod client;
pub mod connection;
pub mod crypto;
pub mod hostkey;
pub mod kex;
pub mod kex_dh;
pub mod message;
pub mod packet;
pub mod privatekey;
pub mod server;
pub mod transport;
pub mod version;

// Re-export main types
pub use auth::{
    constant_time_compare, AuthBanner, AuthFailure, AuthMethod, AuthPkOk, AuthRequest,
    AuthSuccess, construct_signature_data,
};
pub use authorized_keys::{AuthorizedKey, AuthorizedKeysFile};
pub use client::{SshClient, SshClientConfig};
pub use connection::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure, ChannelOpen,
    ChannelOpenConfirmation, ChannelOpenFailure, ChannelOpenFailureReason, ChannelRequest,
    ChannelRequestType, ChannelSuccess, ChannelType, ChannelWindowAdjust, ExtendedDataType,
    MAX_PACKET_SIZE, MAX_WINDOW_SIZE,
};
pub use crypto::{CipherAlgorithm, DecryptionKey, EncryptionKey, MacAlgorithm, MacKey};
pub use hostkey::{
    EcdsaP256HostKey, EcdsaP384HostKey, EcdsaP521HostKey, Ed25519HostKey, HostKey,
    HostKeyAlgorithm, RsaSha2_256HostKey, RsaSha2_512HostKey, SshRsaHostKey,
};
pub use kex::{negotiate_algorithm, KexInit, NewKeys};
pub use kex_dh::{derive_key, Curve25519Exchange, DhGroup14Exchange};
pub use message::MessageType;
pub use packet::Packet;
pub use privatekey::{
    EcdsaCurve, EcdsaPrivateKey, Ed25519PrivateKey, PasswordCallback, PrivateKey,
    PublicKey as PrivateKeyPublicKey, RsaPrivateKey, SimplePasswordCallback,
};
pub use server::{SessionHandler, SshServer, SshServerConfig, SshSession};
pub use transport::{EncryptionParams, State, TransportConfig, TransportState};
pub use version::Version;
