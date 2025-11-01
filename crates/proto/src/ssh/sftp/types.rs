//! SFTP data types and structures.

use fynx_platform::{FynxError, FynxResult};

/// SFTP error codes (SSH_FX_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SftpErrorCode {
    /// SSH_FX_OK - Success
    Ok = 0,
    /// SSH_FX_EOF - End of file
    Eof = 1,
    /// SSH_FX_NO_SUCH_FILE - No such file
    NoSuchFile = 2,
    /// SSH_FX_PERMISSION_DENIED - Permission denied
    PermissionDenied = 3,
    /// SSH_FX_FAILURE - General failure
    Failure = 4,
    /// SSH_FX_BAD_MESSAGE - Bad message
    BadMessage = 5,
    /// SSH_FX_NO_CONNECTION - No connection
    NoConnection = 6,
    /// SSH_FX_CONNECTION_LOST - Connection lost
    ConnectionLost = 7,
    /// SSH_FX_OP_UNSUPPORTED - Operation not supported
    OpUnsupported = 8,
}

impl SftpErrorCode {
    /// Convert from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Eof),
            2 => Some(Self::NoSuchFile),
            3 => Some(Self::PermissionDenied),
            4 => Some(Self::Failure),
            5 => Some(Self::BadMessage),
            6 => Some(Self::NoConnection),
            7 => Some(Self::ConnectionLost),
            8 => Some(Self::OpUnsupported),
            _ => None,
        }
    }

    /// Returns error message.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Ok => "Success",
            Self::Eof => "End of file",
            Self::NoSuchFile => "No such file or directory",
            Self::PermissionDenied => "Permission denied",
            Self::Failure => "Failure",
            Self::BadMessage => "Bad message",
            Self::NoConnection => "No connection",
            Self::ConnectionLost => "Connection lost",
            Self::OpUnsupported => "Operation not supported",
        }
    }
}

/// SFTP error.
#[derive(Debug, Clone)]
pub struct SftpError {
    /// Error code
    pub code: SftpErrorCode,
    /// Error message
    pub message: String,
}

impl SftpError {
    /// Creates a new SFTP error.
    pub fn new(code: SftpErrorCode, message: String) -> Self {
        Self { code, message }
    }
}

impl std::fmt::Display for SftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SFTP error {}: {}", self.code as u32, self.message)
    }
}

impl std::error::Error for SftpError {}

/// File type flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file
    Regular,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
    /// Special file
    Special,
    /// Unknown type
    Unknown,
}

/// File open flags (SSH_FXF_*).
#[derive(Debug, Clone, Copy)]
pub struct FileOpenFlags(pub u32);

impl FileOpenFlags {
    /// SSH_FXF_READ - Open for reading
    pub const READ: u32 = 0x00000001;
    /// SSH_FXF_WRITE - Open for writing
    pub const WRITE: u32 = 0x00000002;
    /// SSH_FXF_APPEND - Force writes to append
    pub const APPEND: u32 = 0x00000004;
    /// SSH_FXF_CREAT - Create if doesn't exist
    pub const CREAT: u32 = 0x00000008;
    /// SSH_FXF_TRUNC - Truncate to 0 length
    pub const TRUNC: u32 = 0x00000010;
    /// SSH_FXF_EXCL - Fail if file exists
    pub const EXCL: u32 = 0x00000020;
}

/// File mode (permissions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMode(pub u32);

impl FileMode {
    /// Owner read
    pub const USER_READ: u32 = 0o400;
    /// Owner write
    pub const USER_WRITE: u32 = 0o200;
    /// Owner execute
    pub const USER_EXEC: u32 = 0o100;
    /// Group read
    pub const GROUP_READ: u32 = 0o040;
    /// Group write
    pub const GROUP_WRITE: u32 = 0o020;
    /// Group execute
    pub const GROUP_EXEC: u32 = 0o010;
    /// Others read
    pub const OTHER_READ: u32 = 0o004;
    /// Others write
    pub const OTHER_WRITE: u32 = 0o002;
    /// Others execute
    pub const OTHER_EXEC: u32 = 0o001;

    /// Default file permissions (0644 = rw-r--r--)
    pub const DEFAULT_FILE: u32 = 0o644;
    /// Default directory permissions (0755 = rwxr-xr-x)
    pub const DEFAULT_DIR: u32 = 0o755;
}

/// File attribute flags.
#[derive(Debug, Clone, Copy)]
pub struct AttrFlags(pub u32);

impl AttrFlags {
    /// SSH_FILEXFER_ATTR_SIZE
    pub const SIZE: u32 = 0x00000001;
    /// SSH_FILEXFER_ATTR_UIDGID
    pub const UIDGID: u32 = 0x00000002;
    /// SSH_FILEXFER_ATTR_PERMISSIONS
    pub const PERMISSIONS: u32 = 0x00000004;
    /// SSH_FILEXFER_ATTR_ACMODTIME
    pub const ACMODTIME: u32 = 0x00000008;
    /// SSH_FILEXFER_ATTR_EXTENDED
    pub const EXTENDED: u32 = 0x80000000;
}

/// File attributes.
#[derive(Debug, Clone, Default)]
pub struct FileAttributes {
    /// File size in bytes
    pub size: Option<u64>,
    /// User ID
    pub uid: Option<u32>,
    /// Group ID
    pub gid: Option<u32>,
    /// Permissions
    pub permissions: Option<FileMode>,
    /// Access time (Unix timestamp)
    pub atime: Option<u32>,
    /// Modification time (Unix timestamp)
    pub mtime: Option<u32>,
}

impl FileAttributes {
    /// Creates empty attributes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut flags = 0u32;

        // Calculate flags
        if self.size.is_some() {
            flags |= AttrFlags::SIZE;
        }
        if self.uid.is_some() && self.gid.is_some() {
            flags |= AttrFlags::UIDGID;
        }
        if self.permissions.is_some() {
            flags |= AttrFlags::PERMISSIONS;
        }
        if self.atime.is_some() && self.mtime.is_some() {
            flags |= AttrFlags::ACMODTIME;
        }

        // Write flags
        buf.extend_from_slice(&flags.to_be_bytes());

        // Write attributes
        if let Some(size) = self.size {
            buf.extend_from_slice(&size.to_be_bytes());
        }
        if let (Some(uid), Some(gid)) = (self.uid, self.gid) {
            buf.extend_from_slice(&uid.to_be_bytes());
            buf.extend_from_slice(&gid.to_be_bytes());
        }
        if let Some(permissions) = self.permissions {
            buf.extend_from_slice(&permissions.0.to_be_bytes());
        }
        if let (Some(atime), Some(mtime)) = (self.atime, self.mtime) {
            buf.extend_from_slice(&atime.to_be_bytes());
            buf.extend_from_slice(&mtime.to_be_bytes());
        }

        buf
    }

    /// Parses from bytes.
    pub fn from_bytes(data: &[u8]) -> FynxResult<(Self, usize)> {
        if data.len() < 4 {
            return Err(FynxError::Protocol("Attributes too short".to_string()));
        }

        let flags = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let mut offset = 4;
        let mut attrs = Self::new();

        // Read size
        if flags & AttrFlags::SIZE != 0 {
            if data.len() < offset + 8 {
                return Err(FynxError::Protocol("Missing size field".to_string()));
            }
            attrs.size = Some(u64::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]));
            offset += 8;
        }

        // Read UID/GID
        if flags & AttrFlags::UIDGID != 0 {
            if data.len() < offset + 8 {
                return Err(FynxError::Protocol("Missing UID/GID fields".to_string()));
            }
            attrs.uid = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
            attrs.gid = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        // Read permissions
        if flags & AttrFlags::PERMISSIONS != 0 {
            if data.len() < offset + 4 {
                return Err(FynxError::Protocol("Missing permissions field".to_string()));
            }
            attrs.permissions = Some(FileMode(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])));
            offset += 4;
        }

        // Read times
        if flags & AttrFlags::ACMODTIME != 0 {
            if data.len() < offset + 8 {
                return Err(FynxError::Protocol("Missing time fields".to_string()));
            }
            attrs.atime = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
            attrs.mtime = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        Ok((attrs, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(SftpErrorCode::from_u32(0), Some(SftpErrorCode::Ok));
        assert_eq!(SftpErrorCode::from_u32(2), Some(SftpErrorCode::NoSuchFile));
        assert_eq!(SftpErrorCode::from_u32(999), None);
    }

    #[test]
    fn test_file_attributes_serialization() {
        let mut attrs = FileAttributes::new();
        attrs.size = Some(1024);
        attrs.permissions = Some(FileMode(0o644));

        let bytes = attrs.to_bytes();
        let (parsed, _) = FileAttributes::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.size, Some(1024));
        assert_eq!(parsed.permissions.map(|p| p.0), Some(0o644));
    }
}
