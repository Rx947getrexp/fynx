//! SFTP protocol messages.
//!
//! Defines SFTP message types and serialization.

use fynx_platform::{FynxError, FynxResult};

/// SFTP protocol version (v3).
pub const SFTP_VERSION: u32 = 3;

/// SFTP message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SftpMessageType {
    /// SSH_FXP_INIT - Initialize SFTP session
    Init = 1,
    /// SSH_FXP_VERSION - Version response
    Version = 2,
    /// SSH_FXP_OPEN - Open file
    Open = 3,
    /// SSH_FXP_CLOSE - Close file/directory
    Close = 4,
    /// SSH_FXP_READ - Read from file
    Read = 5,
    /// SSH_FXP_WRITE - Write to file
    Write = 6,
    /// SSH_FXP_LSTAT - Get file attributes (no follow symlinks)
    LStat = 7,
    /// SSH_FXP_FSTAT - Get file attributes by handle
    FStat = 8,
    /// SSH_FXP_SETSTAT - Set file attributes
    SetStat = 9,
    /// SSH_FXP_FSETSTAT - Set file attributes by handle
    FSetStat = 10,
    /// SSH_FXP_OPENDIR - Open directory
    OpenDir = 11,
    /// SSH_FXP_READDIR - Read directory
    ReadDir = 12,
    /// SSH_FXP_REMOVE - Remove file
    Remove = 13,
    /// SSH_FXP_MKDIR - Create directory
    MkDir = 14,
    /// SSH_FXP_RMDIR - Remove directory
    RmDir = 15,
    /// SSH_FXP_REALPATH - Canonicalize path
    RealPath = 16,
    /// SSH_FXP_STAT - Get file attributes
    Stat = 17,
    /// SSH_FXP_RENAME - Rename file/directory
    Rename = 18,
    /// SSH_FXP_READLINK - Read symbolic link
    ReadLink = 19,
    /// SSH_FXP_SYMLINK - Create symbolic link
    Symlink = 20,

    // Response messages
    /// SSH_FXP_STATUS - Status response
    Status = 101,
    /// SSH_FXP_HANDLE - File handle response
    Handle = 102,
    /// SSH_FXP_DATA - Data response
    Data = 103,
    /// SSH_FXP_NAME - Name response
    Name = 104,
    /// SSH_FXP_ATTRS - Attributes response
    Attrs = 105,

    // Extended messages
    /// SSH_FXP_EXTENDED - Extended request
    Extended = 200,
    /// SSH_FXP_EXTENDED_REPLY - Extended response
    ExtendedReply = 201,
}

impl SftpMessageType {
    /// Convert from u8.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Init),
            2 => Some(Self::Version),
            3 => Some(Self::Open),
            4 => Some(Self::Close),
            5 => Some(Self::Read),
            6 => Some(Self::Write),
            7 => Some(Self::LStat),
            8 => Some(Self::FStat),
            9 => Some(Self::SetStat),
            10 => Some(Self::FSetStat),
            11 => Some(Self::OpenDir),
            12 => Some(Self::ReadDir),
            13 => Some(Self::Remove),
            14 => Some(Self::MkDir),
            15 => Some(Self::RmDir),
            16 => Some(Self::RealPath),
            17 => Some(Self::Stat),
            18 => Some(Self::Rename),
            19 => Some(Self::ReadLink),
            20 => Some(Self::Symlink),
            101 => Some(Self::Status),
            102 => Some(Self::Handle),
            103 => Some(Self::Data),
            104 => Some(Self::Name),
            105 => Some(Self::Attrs),
            200 => Some(Self::Extended),
            201 => Some(Self::ExtendedReply),
            _ => None,
        }
    }
}

/// SFTP message.
#[derive(Debug)]
pub struct SftpMessage {
    /// Message type
    pub msg_type: SftpMessageType,
    /// Message payload
    pub payload: Vec<u8>,
}

impl SftpMessage {
    /// Creates a new SFTP message.
    pub fn new(msg_type: SftpMessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Serializes to bytes.
    ///
    /// Format:
    /// ```text
    /// uint32    length
    /// byte      type
    /// byte[n]   payload
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // length (payload + 1 for type byte)
        let length = (self.payload.len() + 1) as u32;
        buf.extend_from_slice(&length.to_be_bytes());

        // type
        buf.push(self.msg_type as u8);

        // payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<Self> {
        if data.len() < 5 {
            return Err(FynxError::Protocol("SFTP message too short".to_string()));
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if data.len() < 4 + length {
            return Err(FynxError::Protocol("SFTP message incomplete".to_string()));
        }

        let msg_type = SftpMessageType::from_u8(data[4]).ok_or_else(|| {
            FynxError::Protocol(format!("Unknown SFTP message type: {}", data[4]))
        })?;

        let payload = data[5..4 + length].to_vec();

        Ok(Self { msg_type, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(SftpMessageType::from_u8(1), Some(SftpMessageType::Init));
        assert_eq!(SftpMessageType::from_u8(101), Some(SftpMessageType::Status));
        assert_eq!(SftpMessageType::from_u8(255), None);
    }

    #[test]
    fn test_message_serialization() {
        let msg = SftpMessage::new(SftpMessageType::Init, vec![0, 0, 0, 3]);
        let bytes = msg.to_bytes();

        // length (4) + type (1) + payload (4) = 9 bytes
        assert_eq!(bytes.len(), 9);

        // Verify length field
        let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(length, 5); // type (1) + payload (4)

        // Verify type
        assert_eq!(bytes[4], SftpMessageType::Init as u8);
    }

    #[test]
    fn test_message_deserialization() {
        let bytes = vec![
            0, 0, 0, 5, // length = 5
            1, // type = Init
            0, 0, 0, 3, // payload (version 3)
        ];

        let msg = SftpMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg.msg_type, SftpMessageType::Init);
        assert_eq!(msg.payload, vec![0, 0, 0, 3]);
    }
}
