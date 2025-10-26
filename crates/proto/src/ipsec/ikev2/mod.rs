//! IKEv2 (Internet Key Exchange v2) protocol implementation
//!
//! This module implements the IKEv2 protocol as defined in RFC 7296.
//!
//! # Protocol Overview
//!
//! IKEv2 is used to negotiate Security Associations (SAs) for IPSec.
//! The protocol consists of several exchanges:
//!
//! 1. **IKE_SA_INIT**: Initial handshake, negotiate crypto algorithms
//! 2. **IKE_AUTH**: Authenticate peers and create first Child SA
//! 3. **CREATE_CHILD_SA**: Create additional Child SAs or rekey
//! 4. **INFORMATIONAL**: Error handling and notifications
//!
//! # Message Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       IKE SA Initiator's SPI                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       IKE SA Responder's SPI                  |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Message ID                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Length                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # References
//!
//! - [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296) - IKEv2 Protocol

pub mod auth;
pub mod constants;
pub mod exchange;
pub mod informational;
pub mod message;
pub mod payload;
pub mod proposal;
pub mod state;

pub use auth::*;
pub use constants::*;
pub use exchange::*;
pub use informational::*;
pub use message::*;
pub use payload::*;
pub use proposal::*;
pub use state::*;
