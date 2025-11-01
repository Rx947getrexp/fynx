//! SFTP client implementation.

use super::message::{SftpMessage, SftpMessageType, SFTP_VERSION};
use super::types::{FileAttributes, FileMode, FileOpenFlags, SftpError, SftpErrorCode};
use crate::ssh::channel::{ChannelMessage, SshChannel};
use crate::ssh::connection::{ChannelOpen, ChannelRequest, ChannelRequestType, ChannelType};
use crate::ssh::connection::{MAX_PACKET_SIZE, MAX_WINDOW_SIZE};
use crate::ssh::connection_mgr::SshConnection;
use crate::ssh::dispatcher::MessageDispatcher;
use fynx_platform::{FynxError, FynxResult};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, info};

/// SFTP client.
pub struct SftpClient {
    /// SSH channel for SFTP subsystem
    channel: SshChannel,
    /// SSH connection
    connection: Arc<Mutex<SshConnection>>,
    /// Request ID counter
    next_request_id: AtomicU32,
}

impl SftpClient {
    /// Creates a new SFTP client.
    ///
    /// This opens an SSH channel and requests the "sftp" subsystem.
    ///
    /// # Arguments
    ///
    /// * `connection` - SSH connection
    /// * `dispatcher` - Message dispatcher
    pub async fn new(
        connection: Arc<Mutex<SshConnection>>,
        dispatcher: Arc<Mutex<MessageDispatcher>>,
    ) -> FynxResult<Self> {
        info!("Opening SFTP session");

        // Allocate channel ID and create channel
        let (local_id, mut channel, tx) = {
            let mut conn = connection.lock().await;
            let local_id = conn.allocate_channel_id();
            let (channel, tx) = SshChannel::with_channels(
                local_id,
                0, // remote_id will be set after confirmation
                MAX_WINDOW_SIZE,
                MAX_PACKET_SIZE,
            );
            (local_id, channel, tx)
        };

        // Register channel with dispatcher
        dispatcher.lock().await.register_channel(local_id, tx).await;

        // Send CHANNEL_OPEN (session)
        let channel_open = ChannelOpen::new(
            ChannelType::Session,
            local_id,
            MAX_WINDOW_SIZE,
            MAX_PACKET_SIZE,
        );
        let open_msg = channel_open.to_bytes();

        {
            let mut conn = connection.lock().await;
            conn.send_packet(&open_msg).await?;
        }

        // TODO: Wait for CHANNEL_OPEN_CONFIRMATION
        // For now, assume it succeeds

        debug!("Channel {} opened for SFTP", local_id);

        // Request "sftp" subsystem
        let subsystem_request = ChannelRequest::new(
            channel.remote_id(),
            ChannelRequestType::Subsystem {
                name: "sftp".to_string(),
            },
            true, // want_reply
        );
        let subsystem_msg = subsystem_request.to_bytes();

        {
            let mut conn = connection.lock().await;
            conn.send_packet(&subsystem_msg).await?;
        }

        // TODO: Wait for CHANNEL_SUCCESS
        // For now, assume it succeeds

        debug!("SFTP subsystem requested");

        let mut client = Self {
            channel,
            connection,
            next_request_id: AtomicU32::new(1),
        };

        // Initialize SFTP protocol
        client.initialize().await?;

        Ok(client)
    }

    /// Initialize SFTP protocol (send SSH_FXP_INIT, receive SSH_FXP_VERSION).
    async fn initialize(&mut self) -> FynxResult<()> {
        debug!("Initializing SFTP protocol");

        // Send SSH_FXP_INIT
        let init_payload = SFTP_VERSION.to_be_bytes().to_vec();
        let init_msg = SftpMessage::new(SftpMessageType::Init, init_payload);
        self.send_message(&init_msg).await?;

        // Receive SSH_FXP_VERSION
        let version_msg = self.receive_message().await?;
        if version_msg.msg_type != SftpMessageType::Version {
            return Err(FynxError::Protocol(format!(
                "Expected VERSION, got {:?}",
                version_msg.msg_type
            )));
        }

        if version_msg.payload.len() < 4 {
            return Err(FynxError::Protocol("VERSION payload too short".to_string()));
        }

        let server_version = u32::from_be_bytes([
            version_msg.payload[0],
            version_msg.payload[1],
            version_msg.payload[2],
            version_msg.payload[3],
        ]);

        info!("SFTP protocol initialized (server version: {})", server_version);

        Ok(())
    }

    /// Sends an SFTP message.
    async fn send_message(&mut self, msg: &SftpMessage) -> FynxResult<()> {
        use crate::ssh::connection::ChannelData;

        let data = msg.to_bytes();
        let channel_data = ChannelData::new(self.channel.remote_id(), data);
        let packet = channel_data.to_bytes();

        let mut conn = self.connection.lock().await;
        conn.send_packet(&packet).await
    }

    /// Receives an SFTP message.
    async fn receive_message(&mut self) -> FynxResult<SftpMessage> {
        loop {
            match self.channel.read().await? {
                Some(ChannelMessage::Data(data)) => {
                    return SftpMessage::from_bytes(&data);
                }
                Some(ChannelMessage::Eof) | Some(ChannelMessage::Close) => {
                    return Err(FynxError::Protocol("SFTP channel closed".to_string()));
                }
                Some(_) => {
                    // Ignore other messages
                }
                None => {
                    return Err(FynxError::Protocol(
                        "Channel in legacy mode".to_string()
                    ));
                }
            }
        }
    }

    /// Gets the next request ID.
    fn next_request_id(&self) -> u32 {
        self.next_request_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Uploads a file.
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to local file
    /// * `remote_path` - Path on remote server
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::sftp::SftpClient;
    /// # async fn example(sftp: &mut SftpClient) -> Result<(), Box<dyn std::error::Error>> {
    /// sftp.upload("local.txt", "/remote/file.txt").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upload(&mut self, local_path: &str, remote_path: &str) -> FynxResult<()> {
        info!("Uploading {} -> {}", local_path, remote_path);

        // TODO: Implement file upload
        // 1. Read local file
        // 2. Open remote file (SSH_FXP_OPEN)
        // 3. Write data in chunks (SSH_FXP_WRITE)
        // 4. Close remote file (SSH_FXP_CLOSE)

        Err(FynxError::NotImplemented(
            "SFTP upload not yet fully implemented".to_string()
        ))
    }

    /// Downloads a file.
    ///
    /// # Arguments
    ///
    /// * `remote_path` - Path on remote server
    /// * `local_path` - Path to save locally
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::sftp::SftpClient;
    /// # async fn example(sftp: &mut SftpClient) -> Result<(), Box<dyn std::error::Error>> {
    /// sftp.download("/remote/file.txt", "local.txt").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download(&mut self, remote_path: &str, local_path: &str) -> FynxResult<()> {
        info!("Downloading {} -> {}", remote_path, local_path);

        // TODO: Implement file download
        // 1. Open remote file (SSH_FXP_OPEN)
        // 2. Read data in chunks (SSH_FXP_READ)
        // 3. Write to local file
        // 4. Close remote file (SSH_FXP_CLOSE)

        Err(FynxError::NotImplemented(
            "SFTP download not yet fully implemented".to_string()
        ))
    }

    /// Lists a directory.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path
    ///
    /// # Returns
    ///
    /// Vector of directory entries (filename, attributes).
    pub async fn readdir(&mut self, path: &str) -> FynxResult<Vec<(String, FileAttributes)>> {
        info!("Listing directory: {}", path);

        // TODO: Implement directory listing
        // 1. Open directory (SSH_FXP_OPENDIR)
        // 2. Read entries (SSH_FXP_READDIR)
        // 3. Close directory (SSH_FXP_CLOSE)

        Err(FynxError::NotImplemented(
            "SFTP readdir not yet fully implemented".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_counter() {
        let client_data = AtomicU32::new(1);

        let id1 = client_data.fetch_add(1, Ordering::SeqCst);
        let id2 = client_data.fetch_add(1, Ordering::SeqCst);
        let id3 = client_data.fetch_add(1, Ordering::SeqCst);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    // TODO: Add more tests when implementation is complete
    // Full tests require:
    // 1. Mock or real SFTP server
    // 2. Connection and dispatcher setup
    // 3. End-to-end SFTP operations
}
