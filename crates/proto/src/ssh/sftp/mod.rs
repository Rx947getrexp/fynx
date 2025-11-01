//! SFTP (SSH File Transfer Protocol) implementation.
//!
//! This module implements SFTP v3, the most widely supported version.
//!
//! # Architecture
//!
//! SFTP runs as an SSH subsystem over an SSH channel:
//! 1. Open SSH channel
//! 2. Request "sftp" subsystem
//! 3. Exchange SFTP protocol messages
//!
//! # Protocol Flow
//!
//! ```text
//! Client                          Server
//!   |                               |
//!   |-- SSH_MSG_CHANNEL_OPEN ------>|
//!   |<- SSH_MSG_CHANNEL_OPEN_CONF --|
//!   |                               |
//!   |-- SSH_MSG_CHANNEL_REQUEST --->|  (subsystem "sftp")
//!   |<- SSH_MSG_CHANNEL_SUCCESS ----|
//!   |                               |
//!   |-- SSH_FXP_INIT -------------->|
//!   |<- SSH_FXP_VERSION ------------|
//!   |                               |
//!   |-- SSH_FXP_OPEN -------------->|
//!   |<- SSH_FXP_HANDLE -------------|
//!   |                               |
//!   |-- SSH_FXP_READ -------------->|
//!   |<- SSH_FXP_DATA ---------------|
//!   |                               |
//!   |-- SSH_FXP_CLOSE ------------->|
//!   |<- SSH_FXP_STATUS -------------|
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use fynx_proto::ssh::client::SshClient;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = SshClient::connect("server:22").await?;
//! client.authenticate_password("user", "password").await?;
//!
//! // Create SFTP session
//! let mut sftp = client.sftp().await?;
//!
//! // Upload file
//! sftp.upload("local.txt", "/remote/file.txt").await?;
//!
//! // Download file
//! sftp.download("/remote/file.txt", "local.txt").await?;
//!
//! // List directory
//! let entries = sftp.readdir("/remote/path").await?;
//! for entry in entries {
//!     println!("{}", entry.filename);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [SFTP Draft v3](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) - Most common version
//! - [SFTP Draft v6](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13) - Latest draft

pub mod client;
pub mod message;
pub mod types;

pub use client::SftpClient;
pub use message::{SftpMessage, SftpMessageType};
pub use types::{FileAttributes, FileMode, FileType, SftpError, SftpErrorCode};
