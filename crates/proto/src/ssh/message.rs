//! SSH protocol message types (RFC 4253).
//!
//! This module defines all SSH protocol message types and their numeric identifiers
//! as specified in RFC 4253 Section 12 and related RFCs.
//!
//! # Message Categories
//!
//! - **Transport Layer Generic** (1-19): Disconnect, ignore, debug
//! - **Algorithm Negotiation** (20-29): Key exchange initialization
//! - **Key Exchange Method** (30-49): Method-specific messages
//! - **User Authentication Generic** (50-79): Authentication protocol
//! - **Connection Protocol Generic** (80-127): Channel management
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::message::MessageType;
//!
//! let msg_type = MessageType::KexInit;
//! assert_eq!(msg_type as u8, 20);
//! ```

/// SSH message types as defined in RFC 4253 Section 12.
///
/// Each message type has a unique numeric identifier used in the binary protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    // Transport layer generic (1-19)
    /// Disconnect message - terminates the connection.
    Disconnect = 1,
    /// Ignore message - can be used for padding or keep-alive.
    Ignore = 2,
    /// Unimplemented message - response to unknown message type.
    Unimplemented = 3,
    /// Debug message - debugging information.
    Debug = 4,
    /// Service request - request a service (e.g., "ssh-userauth").
    ServiceRequest = 5,
    /// Service accept - service request accepted.
    ServiceAccept = 6,

    // Algorithm negotiation (20-29)
    /// Key exchange init - algorithm negotiation.
    KexInit = 20,
    /// New keys - signals transition to new keys.
    NewKeys = 21,

    // Key exchange method specific (30-49)
    /// Diffie-Hellman/ECDH key exchange init (both use same message number).
    /// Used for DH group1/group14 and ECDH (Curve25519, nistp256, etc.).
    KexdhInit = 30,
    /// Diffie-Hellman/ECDH key exchange reply (both use same message number).
    KexdhReply = 31,

    // User authentication generic (50-79)
    /// User authentication request.
    UserauthRequest = 50,
    /// User authentication failure.
    UserauthFailure = 51,
    /// User authentication success.
    UserauthSuccess = 52,
    /// User authentication banner.
    UserauthBanner = 53,
    /// Public key OK (server accepts public key for authentication).
    UserauthPkOk = 60,

    // Connection protocol generic (80-127)
    /// Global request.
    GlobalRequest = 80,
    /// Request success.
    RequestSuccess = 81,
    /// Request failure.
    RequestFailure = 82,
    /// Channel open.
    ChannelOpen = 90,
    /// Channel open confirmation.
    ChannelOpenConfirmation = 91,
    /// Channel open failure.
    ChannelOpenFailure = 92,
    /// Channel window adjust.
    ChannelWindowAdjust = 93,
    /// Channel data.
    ChannelData = 94,
    /// Channel extended data (stderr).
    ChannelExtendedData = 95,
    /// Channel EOF.
    ChannelEof = 96,
    /// Channel close.
    ChannelClose = 97,
    /// Channel request.
    ChannelRequest = 98,
    /// Channel success.
    ChannelSuccess = 99,
    /// Channel failure.
    ChannelFailure = 100,
}

impl MessageType {
    /// Converts a byte to a message type.
    ///
    /// # Arguments
    ///
    /// * `byte` - The message type byte
    ///
    /// # Returns
    ///
    /// Some(MessageType) if valid, None otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::message::MessageType;
    ///
    /// assert_eq!(MessageType::from_u8(20), Some(MessageType::KexInit));
    /// assert_eq!(MessageType::from_u8(255), None);
    /// ```
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(MessageType::Disconnect),
            2 => Some(MessageType::Ignore),
            3 => Some(MessageType::Unimplemented),
            4 => Some(MessageType::Debug),
            5 => Some(MessageType::ServiceRequest),
            6 => Some(MessageType::ServiceAccept),
            20 => Some(MessageType::KexInit),
            21 => Some(MessageType::NewKeys),
            30 => Some(MessageType::KexdhInit),
            31 => Some(MessageType::KexdhReply),
            50 => Some(MessageType::UserauthRequest),
            51 => Some(MessageType::UserauthFailure),
            52 => Some(MessageType::UserauthSuccess),
            53 => Some(MessageType::UserauthBanner),
            60 => Some(MessageType::UserauthPkOk),
            80 => Some(MessageType::GlobalRequest),
            81 => Some(MessageType::RequestSuccess),
            82 => Some(MessageType::RequestFailure),
            90 => Some(MessageType::ChannelOpen),
            91 => Some(MessageType::ChannelOpenConfirmation),
            92 => Some(MessageType::ChannelOpenFailure),
            93 => Some(MessageType::ChannelWindowAdjust),
            94 => Some(MessageType::ChannelData),
            95 => Some(MessageType::ChannelExtendedData),
            96 => Some(MessageType::ChannelEof),
            97 => Some(MessageType::ChannelClose),
            98 => Some(MessageType::ChannelRequest),
            99 => Some(MessageType::ChannelSuccess),
            100 => Some(MessageType::ChannelFailure),
            _ => None,
        }
    }

    /// Returns the message type name.
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::message::MessageType;
    ///
    /// assert_eq!(MessageType::KexInit.name(), "SSH_MSG_KEXINIT");
    /// ```
    pub fn name(&self) -> &'static str {
        match self {
            MessageType::Disconnect => "SSH_MSG_DISCONNECT",
            MessageType::Ignore => "SSH_MSG_IGNORE",
            MessageType::Unimplemented => "SSH_MSG_UNIMPLEMENTED",
            MessageType::Debug => "SSH_MSG_DEBUG",
            MessageType::ServiceRequest => "SSH_MSG_SERVICE_REQUEST",
            MessageType::ServiceAccept => "SSH_MSG_SERVICE_ACCEPT",
            MessageType::KexInit => "SSH_MSG_KEXINIT",
            MessageType::NewKeys => "SSH_MSG_NEWKEYS",
            MessageType::KexdhInit => "SSH_MSG_KEXDH_INIT",
            MessageType::KexdhReply => "SSH_MSG_KEXDH_REPLY",
            MessageType::UserauthRequest => "SSH_MSG_USERAUTH_REQUEST",
            MessageType::UserauthFailure => "SSH_MSG_USERAUTH_FAILURE",
            MessageType::UserauthSuccess => "SSH_MSG_USERAUTH_SUCCESS",
            MessageType::UserauthBanner => "SSH_MSG_USERAUTH_BANNER",
            MessageType::UserauthPkOk => "SSH_MSG_USERAUTH_PK_OK",
            MessageType::GlobalRequest => "SSH_MSG_GLOBAL_REQUEST",
            MessageType::RequestSuccess => "SSH_MSG_REQUEST_SUCCESS",
            MessageType::RequestFailure => "SSH_MSG_REQUEST_FAILURE",
            MessageType::ChannelOpen => "SSH_MSG_CHANNEL_OPEN",
            MessageType::ChannelOpenConfirmation => "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
            MessageType::ChannelOpenFailure => "SSH_MSG_CHANNEL_OPEN_FAILURE",
            MessageType::ChannelWindowAdjust => "SSH_MSG_CHANNEL_WINDOW_ADJUST",
            MessageType::ChannelData => "SSH_MSG_CHANNEL_DATA",
            MessageType::ChannelExtendedData => "SSH_MSG_CHANNEL_EXTENDED_DATA",
            MessageType::ChannelEof => "SSH_MSG_CHANNEL_EOF",
            MessageType::ChannelClose => "SSH_MSG_CHANNEL_CLOSE",
            MessageType::ChannelRequest => "SSH_MSG_CHANNEL_REQUEST",
            MessageType::ChannelSuccess => "SSH_MSG_CHANNEL_SUCCESS",
            MessageType::ChannelFailure => "SSH_MSG_CHANNEL_FAILURE",
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name(), *self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::from_u8(20), Some(MessageType::KexInit));
        assert_eq!(MessageType::from_u8(21), Some(MessageType::NewKeys));
        assert_eq!(MessageType::from_u8(255), None);
    }

    #[test]
    fn test_message_type_values() {
        assert_eq!(MessageType::Disconnect as u8, 1);
        assert_eq!(MessageType::KexInit as u8, 20);
        assert_eq!(MessageType::NewKeys as u8, 21);
        assert_eq!(MessageType::ChannelData as u8, 94);
    }

    #[test]
    fn test_message_type_name() {
        assert_eq!(MessageType::KexInit.name(), "SSH_MSG_KEXINIT");
        assert_eq!(MessageType::NewKeys.name(), "SSH_MSG_NEWKEYS");
    }

    #[test]
    fn test_message_type_display() {
        let msg = MessageType::KexInit;
        assert_eq!(format!("{}", msg), "SSH_MSG_KEXINIT(20)");
    }
}
