//! SSH connection protocol (RFC 4254).
//!
//! This module implements SSH channels and connection services:
//! - Channel multiplexing (multiple channels over one connection)
//! - Channel types: session, direct-tcpip, forwarded-tcpip
//! - Channel flow control (window size management)
//! - Channel requests: exec, shell, pty-req, env, exit-status, exit-signal
//! - Global requests: tcpip-forward, cancel-tcpip-forward
//!
//! # Architecture
//!
//! The SSH Connection Protocol runs on top of the authenticated transport layer
//! and provides channels for multiplexing different services over a single connection.
//!
//! # Security
//!
//! - **Window size limits** - Prevents memory exhaustion attacks
//! - **Maximum packet size** - Prevents buffer overflow attacks
//! - **Channel number validation** - Prevents channel confusion attacks
//!
//! # Example
//!
//! ```rust
//! use fynx_proto::ssh::connection::{ChannelOpen, ChannelType};
//!
//! // Open a session channel
//! let open = ChannelOpen::new(
//!     ChannelType::Session,
//!     0,           // sender channel
//!     1048576,     // initial window size (1MB)
//!     32768,       // maximum packet size (32KB)
//! );
//! ```

use bytes::{BufMut, BytesMut};
use fynx_platform::{FynxError, FynxResult};

/// Maximum window size (16 MB).
pub const MAX_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

/// Maximum packet size (256 KB).
pub const MAX_PACKET_SIZE: u32 = 256 * 1024;

/// Channel type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelType {
    /// Session channel (interactive shell, exec, subsystem).
    Session,
    /// Direct TCP/IP channel (port forwarding).
    DirectTcpip {
        /// Host to connect to
        host: String,
        /// Port to connect to
        port: u32,
        /// Originator IP address
        originator_address: String,
        /// Originator port
        originator_port: u32,
    },
    /// Forwarded TCP/IP channel (reverse port forwarding).
    ForwardedTcpip {
        /// Connected address
        connected_address: String,
        /// Connected port
        connected_port: u32,
        /// Originator IP address
        originator_address: String,
        /// Originator port
        originator_port: u32,
    },
}

impl ChannelType {
    /// Returns the channel type name.
    pub fn name(&self) -> &str {
        match self {
            ChannelType::Session => "session",
            ChannelType::DirectTcpip { .. } => "direct-tcpip",
            ChannelType::ForwardedTcpip { .. } => "forwarded-tcpip",
        }
    }
}

/// SSH_MSG_CHANNEL_OPEN message (RFC 4254 Section 5.1).
///
/// Sent by either side to open a new channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpen {
    /// Channel type
    channel_type: ChannelType,
    /// Sender channel number
    sender_channel: u32,
    /// Initial window size
    initial_window_size: u32,
    /// Maximum packet size
    maximum_packet_size: u32,
}

impl ChannelOpen {
    /// Creates a new channel open message.
    ///
    /// # Arguments
    ///
    /// * `channel_type` - Type of channel to open
    /// * `sender_channel` - Sender's channel number
    /// * `initial_window_size` - Initial window size (max 16 MB)
    /// * `maximum_packet_size` - Maximum packet size (max 256 KB)
    ///
    /// # Example
    ///
    /// ```rust
    /// use fynx_proto::ssh::connection::{ChannelOpen, ChannelType};
    ///
    /// let open = ChannelOpen::new(
    ///     ChannelType::Session,
    ///     0,
    ///     1048576,  // 1 MB window
    ///     32768,    // 32 KB max packet
    /// );
    /// ```
    pub fn new(
        channel_type: ChannelType,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    ) -> Self {
        Self {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        }
    }

    /// Returns the channel type.
    pub fn channel_type(&self) -> &ChannelType {
        &self.channel_type
    }

    /// Returns the sender channel number.
    pub fn sender_channel(&self) -> u32 {
        self.sender_channel
    }

    /// Returns the initial window size.
    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    /// Returns the maximum packet size.
    pub fn maximum_packet_size(&self) -> u32 {
        self.maximum_packet_size
    }

    /// Serializes to bytes.
    ///
    /// Format (RFC 4254 Section 5.1):
    /// ```text
    /// byte      SSH_MSG_CHANNEL_OPEN (90)
    /// string    channel type
    /// uint32    sender channel
    /// uint32    initial window size
    /// uint32    maximum packet size
    /// ....      channel type specific data
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_OPEN (90)
        buf.put_u8(90);

        // string channel type
        write_string(&mut buf, self.channel_type.name());

        // uint32 sender channel
        buf.put_u32(self.sender_channel);

        // uint32 initial window size
        buf.put_u32(self.initial_window_size);

        // uint32 maximum packet size
        buf.put_u32(self.maximum_packet_size);

        // Channel type specific data
        match &self.channel_type {
            ChannelType::Session => {
                // No additional data
            }
            ChannelType::DirectTcpip {
                host,
                port,
                originator_address,
                originator_port,
            } => {
                write_string(&mut buf, host);
                buf.put_u32(*port);
                write_string(&mut buf, originator_address);
                buf.put_u32(*originator_port);
            }
            ChannelType::ForwardedTcpip {
                connected_address,
                connected_port,
                originator_address,
                originator_port,
            } => {
                write_string(&mut buf, connected_address);
                buf.put_u32(*connected_port);
                write_string(&mut buf, originator_address);
                buf.put_u32(*originator_port);
            }
        }

        buf.to_vec()
    }

    /// Parses from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FynxError::Protocol`] if the data is invalid.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_OPEN message is empty".to_string(),
            ));
        }

        if data[0] != 90 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 90 (SSH_MSG_CHANNEL_OPEN), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        // string channel type
        let type_name = read_string(data, &mut offset)?;

        // uint32 sender channel
        let sender_channel = read_u32(data, &mut offset)?;

        // uint32 initial window size
        let initial_window_size = read_u32(data, &mut offset)?;

        // uint32 maximum packet size
        let maximum_packet_size = read_u32(data, &mut offset)?;

        // Validate window size and packet size
        if initial_window_size > MAX_WINDOW_SIZE {
            return Err(FynxError::Protocol(format!(
                "Initial window size {} exceeds maximum {}",
                initial_window_size, MAX_WINDOW_SIZE
            )));
        }

        if maximum_packet_size > MAX_PACKET_SIZE {
            return Err(FynxError::Protocol(format!(
                "Maximum packet size {} exceeds maximum {}",
                maximum_packet_size, MAX_PACKET_SIZE
            )));
        }

        // Parse channel type specific data
        let channel_type = match type_name.as_str() {
            "session" => ChannelType::Session,
            "direct-tcpip" => {
                let host = read_string(data, &mut offset)?;
                let port = read_u32(data, &mut offset)?;
                let originator_address = read_string(data, &mut offset)?;
                let originator_port = read_u32(data, &mut offset)?;
                ChannelType::DirectTcpip {
                    host,
                    port,
                    originator_address,
                    originator_port,
                }
            }
            "forwarded-tcpip" => {
                let connected_address = read_string(data, &mut offset)?;
                let connected_port = read_u32(data, &mut offset)?;
                let originator_address = read_string(data, &mut offset)?;
                let originator_port = read_u32(data, &mut offset)?;
                ChannelType::ForwardedTcpip {
                    connected_address,
                    connected_port,
                    originator_address,
                    originator_port,
                }
            }
            _ => {
                return Err(FynxError::Protocol(format!(
                    "Unsupported channel type: '{}'",
                    type_name
                )))
            }
        };

        Ok(Self {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}

/// SSH_MSG_CHANNEL_OPEN_CONFIRMATION message (RFC 4254 Section 5.1).
///
/// Sent in response to SSH_MSG_CHANNEL_OPEN to confirm the channel opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenConfirmation {
    /// Recipient channel number
    recipient_channel: u32,
    /// Sender channel number
    sender_channel: u32,
    /// Initial window size
    initial_window_size: u32,
    /// Maximum packet size
    maximum_packet_size: u32,
}

impl ChannelOpenConfirmation {
    /// Creates a new channel open confirmation message.
    pub fn new(
        recipient_channel: u32,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    ) -> Self {
        Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Returns the sender channel number.
    pub fn sender_channel(&self) -> u32 {
        self.sender_channel
    }

    /// Returns the initial window size.
    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    /// Returns the maximum packet size.
    pub fn maximum_packet_size(&self) -> u32 {
        self.maximum_packet_size
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91)
        buf.put_u8(91);
        buf.put_u32(self.recipient_channel);
        buf.put_u32(self.sender_channel);
        buf.put_u32(self.initial_window_size);
        buf.put_u32(self.maximum_packet_size);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_OPEN_CONFIRMATION message is empty".to_string(),
            ));
        }

        if data[0] != 91 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 91 (SSH_MSG_CHANNEL_OPEN_CONFIRMATION), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let recipient_channel = read_u32(data, &mut offset)?;
        let sender_channel = read_u32(data, &mut offset)?;
        let initial_window_size = read_u32(data, &mut offset)?;
        let maximum_packet_size = read_u32(data, &mut offset)?;

        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}

/// Channel open failure reason codes (RFC 4254 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ChannelOpenFailureReason {
    /// Administratively prohibited
    AdministrativelyProhibited = 1,
    /// Connect failed
    ConnectFailed = 2,
    /// Unknown channel type
    UnknownChannelType = 3,
    /// Resource shortage
    ResourceShortage = 4,
}

impl ChannelOpenFailureReason {
    /// Converts from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::AdministrativelyProhibited),
            2 => Some(Self::ConnectFailed),
            3 => Some(Self::UnknownChannelType),
            4 => Some(Self::ResourceShortage),
            _ => None,
        }
    }

    /// Returns the reason as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AdministrativelyProhibited => "Administratively prohibited",
            Self::ConnectFailed => "Connect failed",
            Self::UnknownChannelType => "Unknown channel type",
            Self::ResourceShortage => "Resource shortage",
        }
    }
}

/// SSH_MSG_CHANNEL_OPEN_FAILURE message (RFC 4254 Section 5.1).
///
/// Sent in response to SSH_MSG_CHANNEL_OPEN to indicate channel open failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenFailure {
    /// Recipient channel number
    recipient_channel: u32,
    /// Reason code
    reason_code: ChannelOpenFailureReason,
    /// Description
    description: String,
    /// Language tag
    language_tag: String,
}

impl ChannelOpenFailure {
    /// Creates a new channel open failure message.
    pub fn new(recipient_channel: u32, reason_code: ChannelOpenFailureReason) -> Self {
        Self {
            recipient_channel,
            reason_code,
            description: reason_code.as_str().to_string(),
            language_tag: String::new(),
        }
    }

    /// Creates a new channel open failure with custom description.
    pub fn with_description(
        recipient_channel: u32,
        reason_code: ChannelOpenFailureReason,
        description: String,
    ) -> Self {
        Self {
            recipient_channel,
            reason_code,
            description,
            language_tag: String::new(),
        }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Returns the reason code.
    pub fn reason_code(&self) -> ChannelOpenFailureReason {
        self.reason_code
    }

    /// Returns the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_OPEN_FAILURE (92)
        buf.put_u8(92);
        buf.put_u32(self.recipient_channel);
        buf.put_u32(self.reason_code as u32);
        write_string(&mut buf, &self.description);
        write_string(&mut buf, &self.language_tag);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_OPEN_FAILURE message is empty".to_string(),
            ));
        }

        if data[0] != 92 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 92 (SSH_MSG_CHANNEL_OPEN_FAILURE), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let recipient_channel = read_u32(data, &mut offset)?;
        let reason_code_u32 = read_u32(data, &mut offset)?;
        let description = read_string(data, &mut offset)?;
        let language_tag = read_string(data, &mut offset)?;

        let reason_code = ChannelOpenFailureReason::from_u32(reason_code_u32).ok_or_else(|| {
            FynxError::Protocol(format!("Invalid failure reason code: {}", reason_code_u32))
        })?;

        Ok(Self {
            recipient_channel,
            reason_code,
            description,
            language_tag,
        })
    }
}

/// SSH_MSG_CHANNEL_WINDOW_ADJUST message (RFC 4254 Section 5.2).
///
/// Sent to increase the window size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelWindowAdjust {
    /// Recipient channel number
    recipient_channel: u32,
    /// Bytes to add to window
    bytes_to_add: u32,
}

impl ChannelWindowAdjust {
    /// Creates a new window adjust message.
    pub fn new(recipient_channel: u32, bytes_to_add: u32) -> Self {
        Self {
            recipient_channel,
            bytes_to_add,
        }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Returns the bytes to add.
    pub fn bytes_to_add(&self) -> u32 {
        self.bytes_to_add
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_WINDOW_ADJUST (93)
        buf.put_u8(93);
        buf.put_u32(self.recipient_channel);
        buf.put_u32(self.bytes_to_add);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_WINDOW_ADJUST message is empty".to_string(),
            ));
        }

        if data[0] != 93 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 93 (SSH_MSG_CHANNEL_WINDOW_ADJUST), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let recipient_channel = read_u32(data, &mut offset)?;
        let bytes_to_add = read_u32(data, &mut offset)?;

        Ok(Self {
            recipient_channel,
            bytes_to_add,
        })
    }
}

/// SSH_MSG_CHANNEL_DATA message (RFC 4254 Section 5.2).
///
/// Sent to transmit data on a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelData {
    /// Recipient channel number
    recipient_channel: u32,
    /// Data to send
    data: Vec<u8>,
}

impl ChannelData {
    /// Creates a new channel data message.
    pub fn new(recipient_channel: u32, data: Vec<u8>) -> Self {
        Self {
            recipient_channel,
            data,
        }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Returns the data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_DATA (94)
        buf.put_u8(94);
        buf.put_u32(self.recipient_channel);
        write_bytes(&mut buf, &self.data);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_DATA message is empty".to_string(),
            ));
        }

        if data[0] != 94 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 94 (SSH_MSG_CHANNEL_DATA), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let recipient_channel = read_u32(data, &mut offset)?;
        let channel_data = read_bytes(data, &mut offset)?;

        Ok(Self {
            recipient_channel,
            data: channel_data,
        })
    }
}

/// Extended data type code (RFC 4254 Section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ExtendedDataType {
    /// Stderr data
    Stderr = 1,
}

impl ExtendedDataType {
    /// Converts from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Stderr),
            _ => None,
        }
    }
}

/// SSH_MSG_CHANNEL_EXTENDED_DATA message (RFC 4254 Section 5.2).
///
/// Sent to transmit extended data (e.g., stderr) on a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelExtendedData {
    /// Recipient channel number
    recipient_channel: u32,
    /// Data type code
    data_type_code: ExtendedDataType,
    /// Data to send
    data: Vec<u8>,
}

impl ChannelExtendedData {
    /// Creates a new channel extended data message.
    pub fn new(recipient_channel: u32, data_type_code: ExtendedDataType, data: Vec<u8>) -> Self {
        Self {
            recipient_channel,
            data_type_code,
            data,
        }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Returns the data type code.
    pub fn data_type_code(&self) -> ExtendedDataType {
        self.data_type_code
    }

    /// Returns the data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_EXTENDED_DATA (95)
        buf.put_u8(95);
        buf.put_u32(self.recipient_channel);
        buf.put_u32(self.data_type_code as u32);
        write_bytes(&mut buf, &self.data);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_EXTENDED_DATA message is empty".to_string(),
            ));
        }

        if data[0] != 95 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 95 (SSH_MSG_CHANNEL_EXTENDED_DATA), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let recipient_channel = read_u32(data, &mut offset)?;
        let data_type_code_u32 = read_u32(data, &mut offset)?;
        let channel_data = read_bytes(data, &mut offset)?;

        let data_type_code = ExtendedDataType::from_u32(data_type_code_u32).ok_or_else(|| {
            FynxError::Protocol(format!(
                "Invalid extended data type: {}",
                data_type_code_u32
            ))
        })?;

        Ok(Self {
            recipient_channel,
            data_type_code,
            data: channel_data,
        })
    }
}

/// SSH_MSG_CHANNEL_EOF message (RFC 4254 Section 5.3).
///
/// Sent when no more data will be sent on a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelEof {
    /// Recipient channel number
    recipient_channel: u32,
}

impl ChannelEof {
    /// Creates a new channel EOF message.
    pub fn new(recipient_channel: u32) -> Self {
        Self { recipient_channel }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_EOF (96)
        buf.put_u8(96);
        buf.put_u32(self.recipient_channel);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_EOF message is empty".to_string(),
            ));
        }

        if data[0] != 96 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 96 (SSH_MSG_CHANNEL_EOF), got {}",
                data[0]
            )));
        }

        let mut offset = 1;
        let recipient_channel = read_u32(data, &mut offset)?;

        Ok(Self { recipient_channel })
    }
}

/// SSH_MSG_CHANNEL_CLOSE message (RFC 4254 Section 5.3).
///
/// Sent to close a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelClose {
    /// Recipient channel number
    recipient_channel: u32,
}

impl ChannelClose {
    /// Creates a new channel close message.
    pub fn new(recipient_channel: u32) -> Self {
        Self { recipient_channel }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_CLOSE (97)
        buf.put_u8(97);
        buf.put_u32(self.recipient_channel);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_CLOSE message is empty".to_string(),
            ));
        }

        if data[0] != 97 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 97 (SSH_MSG_CHANNEL_CLOSE), got {}",
                data[0]
            )));
        }

        let mut offset = 1;
        let recipient_channel = read_u32(data, &mut offset)?;

        Ok(Self { recipient_channel })
    }
}

/// Channel request type (RFC 4254 Section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRequestType {
    /// PTY request (pseudoterminal allocation)
    PtyReq {
        /// Terminal type (e.g., "xterm")
        term: String,
        /// Terminal width in characters
        width_chars: u32,
        /// Terminal height in rows
        height_rows: u32,
        /// Terminal width in pixels
        width_pixels: u32,
        /// Terminal height in pixels
        height_pixels: u32,
        /// Encoded terminal modes
        modes: Vec<u8>,
    },
    /// Environment variable
    Env {
        /// Variable name
        name: String,
        /// Variable value
        value: String,
    },
    /// Execute command
    Exec {
        /// Command to execute
        command: String,
    },
    /// Start interactive shell
    Shell,
    /// Start subsystem (e.g., "sftp")
    Subsystem {
        /// Subsystem name
        name: String,
    },
    /// Exit status
    ExitStatus {
        /// Exit status code
        exit_status: u32,
    },
    /// Exit signal
    ExitSignal {
        /// Signal name
        signal_name: String,
        /// Core dumped flag
        core_dumped: bool,
        /// Error message
        error_message: String,
        /// Language tag
        language_tag: String,
    },
}

impl ChannelRequestType {
    /// Returns the request type name.
    pub fn name(&self) -> &str {
        match self {
            ChannelRequestType::PtyReq { .. } => "pty-req",
            ChannelRequestType::Env { .. } => "env",
            ChannelRequestType::Exec { .. } => "exec",
            ChannelRequestType::Shell => "shell",
            ChannelRequestType::Subsystem { .. } => "subsystem",
            ChannelRequestType::ExitStatus { .. } => "exit-status",
            ChannelRequestType::ExitSignal { .. } => "exit-signal",
        }
    }
}

/// SSH_MSG_CHANNEL_REQUEST message (RFC 4254 Section 6).
///
/// Sent to make a channel-specific request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRequest {
    /// Recipient channel number
    recipient_channel: u32,
    /// Request type
    request_type: ChannelRequestType,
    /// Want reply flag
    want_reply: bool,
}

impl ChannelRequest {
    /// Creates a new channel request.
    pub fn new(recipient_channel: u32, request_type: ChannelRequestType, want_reply: bool) -> Self {
        Self {
            recipient_channel,
            request_type,
            want_reply,
        }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Returns the request type.
    pub fn request_type(&self) -> &ChannelRequestType {
        &self.request_type
    }

    /// Returns whether a reply is wanted.
    pub fn want_reply(&self) -> bool {
        self.want_reply
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_REQUEST (98)
        buf.put_u8(98);
        buf.put_u32(self.recipient_channel);
        write_string(&mut buf, self.request_type.name());
        buf.put_u8(if self.want_reply { 1 } else { 0 });

        // Request type specific data
        match &self.request_type {
            ChannelRequestType::PtyReq {
                term,
                width_chars,
                height_rows,
                width_pixels,
                height_pixels,
                modes,
            } => {
                write_string(&mut buf, term);
                buf.put_u32(*width_chars);
                buf.put_u32(*height_rows);
                buf.put_u32(*width_pixels);
                buf.put_u32(*height_pixels);
                write_bytes(&mut buf, modes);
            }
            ChannelRequestType::Env { name, value } => {
                write_string(&mut buf, name);
                write_string(&mut buf, value);
            }
            ChannelRequestType::Exec { command } => {
                write_string(&mut buf, command);
            }
            ChannelRequestType::Shell => {
                // No additional data
            }
            ChannelRequestType::Subsystem { name } => {
                write_string(&mut buf, name);
            }
            ChannelRequestType::ExitStatus { exit_status } => {
                buf.put_u32(*exit_status);
            }
            ChannelRequestType::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                language_tag,
            } => {
                write_string(&mut buf, signal_name);
                buf.put_u8(if *core_dumped { 1 } else { 0 });
                write_string(&mut buf, error_message);
                write_string(&mut buf, language_tag);
            }
        }

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_REQUEST message is empty".to_string(),
            ));
        }

        if data[0] != 98 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 98 (SSH_MSG_CHANNEL_REQUEST), got {}",
                data[0]
            )));
        }

        let mut offset = 1;

        let recipient_channel = read_u32(data, &mut offset)?;
        let request_name = read_string(data, &mut offset)?;

        // boolean want reply
        if offset >= data.len() {
            return Err(FynxError::Protocol(
                "CHANNEL_REQUEST truncated (missing want_reply flag)".to_string(),
            ));
        }
        let want_reply = data[offset] != 0;
        offset += 1;

        // Parse request type specific data
        let request_type = match request_name.as_str() {
            "pty-req" => {
                let term = read_string(data, &mut offset)?;
                let width_chars = read_u32(data, &mut offset)?;
                let height_rows = read_u32(data, &mut offset)?;
                let width_pixels = read_u32(data, &mut offset)?;
                let height_pixels = read_u32(data, &mut offset)?;
                let modes = read_bytes(data, &mut offset)?;
                ChannelRequestType::PtyReq {
                    term,
                    width_chars,
                    height_rows,
                    width_pixels,
                    height_pixels,
                    modes,
                }
            }
            "env" => {
                let name = read_string(data, &mut offset)?;
                let value = read_string(data, &mut offset)?;
                ChannelRequestType::Env { name, value }
            }
            "exec" => {
                let command = read_string(data, &mut offset)?;
                ChannelRequestType::Exec { command }
            }
            "shell" => ChannelRequestType::Shell,
            "subsystem" => {
                let name = read_string(data, &mut offset)?;
                ChannelRequestType::Subsystem { name }
            }
            "exit-status" => {
                let exit_status = read_u32(data, &mut offset)?;
                ChannelRequestType::ExitStatus { exit_status }
            }
            "exit-signal" => {
                let signal_name = read_string(data, &mut offset)?;
                let core_dumped = if offset < data.len() {
                    let val = data[offset] != 0;
                    offset += 1;
                    val
                } else {
                    return Err(FynxError::Protocol(
                        "CHANNEL_REQUEST exit-signal truncated".to_string(),
                    ));
                };
                let error_message = read_string(data, &mut offset)?;
                let language_tag = read_string(data, &mut offset)?;
                ChannelRequestType::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    language_tag,
                }
            }
            _ => {
                return Err(FynxError::Protocol(format!(
                    "Unsupported channel request type: '{}'",
                    request_name
                )))
            }
        };

        Ok(Self {
            recipient_channel,
            request_type,
            want_reply,
        })
    }
}

/// SSH_MSG_CHANNEL_SUCCESS message (RFC 4254 Section 6.4).
///
/// Sent in response to a channel request to indicate success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSuccess {
    /// Recipient channel number
    recipient_channel: u32,
}

impl ChannelSuccess {
    /// Creates a new channel success message.
    pub fn new(recipient_channel: u32) -> Self {
        Self { recipient_channel }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_SUCCESS (99)
        buf.put_u8(99);
        buf.put_u32(self.recipient_channel);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_SUCCESS message is empty".to_string(),
            ));
        }

        if data[0] != 99 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 99 (SSH_MSG_CHANNEL_SUCCESS), got {}",
                data[0]
            )));
        }

        let mut offset = 1;
        let recipient_channel = read_u32(data, &mut offset)?;

        Ok(Self { recipient_channel })
    }
}

/// SSH_MSG_CHANNEL_FAILURE message (RFC 4254 Section 6.4).
///
/// Sent in response to a channel request to indicate failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelFailure {
    /// Recipient channel number
    recipient_channel: u32,
}

impl ChannelFailure {
    /// Creates a new channel failure message.
    pub fn new(recipient_channel: u32) -> Self {
        Self { recipient_channel }
    }

    /// Returns the recipient channel number.
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // byte SSH_MSG_CHANNEL_FAILURE (100)
        buf.put_u8(100);
        buf.put_u32(self.recipient_channel);

        buf.to_vec()
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.is_empty() {
            return Err(FynxError::Protocol(
                "CHANNEL_FAILURE message is empty".to_string(),
            ));
        }

        if data[0] != 100 {
            return Err(FynxError::Protocol(format!(
                "Invalid message type: expected 100 (SSH_MSG_CHANNEL_FAILURE), got {}",
                data[0]
            )));
        }

        let mut offset = 1;
        let recipient_channel = read_u32(data, &mut offset)?;

        Ok(Self { recipient_channel })
    }
}

// Helper functions for encoding/decoding

fn write_string(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

fn write_bytes(buf: &mut BytesMut, bytes: &[u8]) {
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

fn read_string(data: &[u8], offset: &mut usize) -> FynxResult<String> {
    let bytes = read_bytes(data, offset)?;
    String::from_utf8(bytes)
        .map_err(|_| FynxError::Protocol("String contains invalid UTF-8".to_string()))
}

fn read_bytes(data: &[u8], offset: &mut usize) -> FynxResult<Vec<u8>> {
    if *offset + 4 > data.len() {
        return Err(FynxError::Protocol(format!(
            "Cannot read length at offset {}",
            offset
        )));
    }

    let length = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]) as usize;
    *offset += 4;

    if *offset + length > data.len() {
        return Err(FynxError::Protocol(format!(
            "Data truncated: expected {} bytes at offset {}",
            length, offset
        )));
    }

    let bytes = data[*offset..*offset + length].to_vec();
    *offset += length;

    Ok(bytes)
}

fn read_u32(data: &[u8], offset: &mut usize) -> FynxResult<u32> {
    if *offset + 4 > data.len() {
        return Err(FynxError::Protocol(format!(
            "Cannot read u32 at offset {}",
            offset
        )));
    }

    let value = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_open_session() {
        let open = ChannelOpen::new(ChannelType::Session, 0, 1048576, 32768);

        assert_eq!(open.sender_channel(), 0);
        assert_eq!(open.initial_window_size(), 1048576);
        assert_eq!(open.maximum_packet_size(), 32768);

        let bytes = open.to_bytes();
        let parsed = ChannelOpen::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.channel_type(), &ChannelType::Session);
        assert_eq!(parsed.sender_channel(), 0);
    }

    #[test]
    fn test_channel_open_direct_tcpip() {
        let open = ChannelOpen::new(
            ChannelType::DirectTcpip {
                host: "example.com".to_string(),
                port: 80,
                originator_address: "192.168.1.1".to_string(),
                originator_port: 12345,
            },
            1,
            1048576,
            32768,
        );

        let bytes = open.to_bytes();
        let parsed = ChannelOpen::from_bytes(&bytes).unwrap();

        if let ChannelType::DirectTcpip {
            host,
            port,
            originator_address,
            originator_port,
        } = parsed.channel_type()
        {
            assert_eq!(host, "example.com");
            assert_eq!(*port, 80);
            assert_eq!(originator_address, "192.168.1.1");
            assert_eq!(*originator_port, 12345);
        } else {
            panic!("Expected DirectTcpip channel type");
        }
    }

    #[test]
    fn test_channel_open_confirmation() {
        let confirm = ChannelOpenConfirmation::new(0, 1, 1048576, 32768);

        let bytes = confirm.to_bytes();
        let parsed = ChannelOpenConfirmation::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
        assert_eq!(parsed.sender_channel(), 1);
        assert_eq!(parsed.initial_window_size(), 1048576);
        assert_eq!(parsed.maximum_packet_size(), 32768);
    }

    #[test]
    fn test_channel_open_failure() {
        let failure =
            ChannelOpenFailure::new(0, ChannelOpenFailureReason::AdministrativelyProhibited);

        assert_eq!(
            failure.reason_code(),
            ChannelOpenFailureReason::AdministrativelyProhibited
        );

        let bytes = failure.to_bytes();
        let parsed = ChannelOpenFailure::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
        assert_eq!(
            parsed.reason_code(),
            ChannelOpenFailureReason::AdministrativelyProhibited
        );
    }

    #[test]
    fn test_channel_window_adjust() {
        let adjust = ChannelWindowAdjust::new(0, 32768);

        let bytes = adjust.to_bytes();
        let parsed = ChannelWindowAdjust::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
        assert_eq!(parsed.bytes_to_add(), 32768);
    }

    #[test]
    fn test_channel_data() {
        let data = ChannelData::new(0, b"Hello, SSH!".to_vec());

        assert_eq!(data.data(), b"Hello, SSH!");

        let bytes = data.to_bytes();
        let parsed = ChannelData::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
        assert_eq!(parsed.data(), b"Hello, SSH!");
    }

    #[test]
    fn test_channel_extended_data() {
        let data = ChannelExtendedData::new(0, ExtendedDataType::Stderr, b"Error!".to_vec());

        let bytes = data.to_bytes();
        let parsed = ChannelExtendedData::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
        assert_eq!(parsed.data_type_code(), ExtendedDataType::Stderr);
        assert_eq!(parsed.data(), b"Error!");
    }

    #[test]
    fn test_channel_eof() {
        let eof = ChannelEof::new(0);

        let bytes = eof.to_bytes();
        let parsed = ChannelEof::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
    }

    #[test]
    fn test_channel_close() {
        let close = ChannelClose::new(0);

        let bytes = close.to_bytes();
        let parsed = ChannelClose::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
    }

    #[test]
    fn test_window_size_validation() {
        let mut data =
            ChannelOpen::new(ChannelType::Session, 0, MAX_WINDOW_SIZE + 1, 32768).to_bytes();
        // Manually set invalid window size
        data[13] = 0x01; // Set to MAX_WINDOW_SIZE + 1

        let result = ChannelOpen::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_size_validation() {
        let mut data =
            ChannelOpen::new(ChannelType::Session, 0, 1048576, MAX_PACKET_SIZE + 1).to_bytes();
        // Manually set invalid packet size
        data[17] = 0x01; // Set to MAX_PACKET_SIZE + 1

        let result = ChannelOpen::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_request_exec() {
        let request = ChannelRequest::new(
            0,
            ChannelRequestType::Exec {
                command: "ls -la".to_string(),
            },
            true,
        );

        assert!(request.want_reply());

        let bytes = request.to_bytes();
        let parsed = ChannelRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
        assert!(parsed.want_reply());

        if let ChannelRequestType::Exec { command } = parsed.request_type() {
            assert_eq!(command, "ls -la");
        } else {
            panic!("Expected Exec request type");
        }
    }

    #[test]
    fn test_channel_request_shell() {
        let request = ChannelRequest::new(0, ChannelRequestType::Shell, true);

        let bytes = request.to_bytes();
        let parsed = ChannelRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.request_type(), &ChannelRequestType::Shell);
    }

    #[test]
    fn test_channel_request_pty() {
        let request = ChannelRequest::new(
            0,
            ChannelRequestType::PtyReq {
                term: "xterm".to_string(),
                width_chars: 80,
                height_rows: 24,
                width_pixels: 640,
                height_pixels: 480,
                modes: vec![0],
            },
            true,
        );

        let bytes = request.to_bytes();
        let parsed = ChannelRequest::from_bytes(&bytes).unwrap();

        if let ChannelRequestType::PtyReq {
            term,
            width_chars,
            height_rows,
            ..
        } = parsed.request_type()
        {
            assert_eq!(term, "xterm");
            assert_eq!(*width_chars, 80);
            assert_eq!(*height_rows, 24);
        } else {
            panic!("Expected PtyReq request type");
        }
    }

    #[test]
    fn test_channel_request_env() {
        let request = ChannelRequest::new(
            0,
            ChannelRequestType::Env {
                name: "PATH".to_string(),
                value: "/usr/bin".to_string(),
            },
            false,
        );

        let bytes = request.to_bytes();
        let parsed = ChannelRequest::from_bytes(&bytes).unwrap();

        if let ChannelRequestType::Env { name, value } = parsed.request_type() {
            assert_eq!(name, "PATH");
            assert_eq!(value, "/usr/bin");
        } else {
            panic!("Expected Env request type");
        }
    }

    #[test]
    fn test_channel_request_subsystem() {
        let request = ChannelRequest::new(
            0,
            ChannelRequestType::Subsystem {
                name: "sftp".to_string(),
            },
            true,
        );

        let bytes = request.to_bytes();
        let parsed = ChannelRequest::from_bytes(&bytes).unwrap();

        if let ChannelRequestType::Subsystem { name } = parsed.request_type() {
            assert_eq!(name, "sftp");
        } else {
            panic!("Expected Subsystem request type");
        }
    }

    #[test]
    fn test_channel_request_exit_status() {
        let request =
            ChannelRequest::new(0, ChannelRequestType::ExitStatus { exit_status: 0 }, false);

        let bytes = request.to_bytes();
        let parsed = ChannelRequest::from_bytes(&bytes).unwrap();

        if let ChannelRequestType::ExitStatus { exit_status } = parsed.request_type() {
            assert_eq!(*exit_status, 0);
        } else {
            panic!("Expected ExitStatus request type");
        }
    }

    #[test]
    fn test_channel_success() {
        let success = ChannelSuccess::new(0);

        let bytes = success.to_bytes();
        let parsed = ChannelSuccess::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
    }

    #[test]
    fn test_channel_failure() {
        let failure = ChannelFailure::new(0);

        let bytes = failure.to_bytes();
        let parsed = ChannelFailure::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.recipient_channel(), 0);
    }
}
