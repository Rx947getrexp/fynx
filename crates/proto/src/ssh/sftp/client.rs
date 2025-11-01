//! SFTP client implementation.

use super::message::{SftpMessage, SftpMessageType, SFTP_VERSION};
use super::types::{FileAttributes, FileMode, FileOpenFlags, SftpErrorCode};
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
        use tokio::io::AsyncReadExt;

        info!("Uploading {} -> {}", local_path, remote_path);

        // Read local file
        let mut file = tokio::fs::File::open(local_path).await
            .map_err(FynxError::Io)?;

        let metadata = file.metadata().await
            .map_err(FynxError::Io)?;
        let file_size = metadata.len();

        debug!("Local file size: {} bytes", file_size);

        // Open remote file (SSH_FXP_OPEN)
        let request_id = self.next_request_id();
        let open_payload = self.build_open_request(
            request_id,
            remote_path,
            FileOpenFlags::WRITE | FileOpenFlags::CREAT | FileOpenFlags::TRUNC,
            FileMode::DEFAULT_FILE,
        );
        let open_msg = SftpMessage::new(SftpMessageType::Open, open_payload);
        self.send_message(&open_msg).await?;

        // Receive SSH_FXP_HANDLE
        let handle_msg = self.receive_message().await?;
        if handle_msg.msg_type != SftpMessageType::Handle {
            return self.handle_status_response(handle_msg);
        }
        let handle = self.parse_handle(&handle_msg.payload)?;
        debug!("Remote file opened, handle length: {}", handle.len());

        // Write data in chunks (32KB recommended)
        const CHUNK_SIZE: usize = 32768;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut offset = 0u64;
        let mut total_written = 0u64;

        loop {
            let bytes_read = file.read(&mut buffer).await
                .map_err(FynxError::Io)?;

            if bytes_read == 0 {
                break; // EOF
            }

            let request_id = self.next_request_id();
            let write_payload = self.build_write_request(
                request_id,
                &handle,
                offset,
                &buffer[..bytes_read],
            );
            let write_msg = SftpMessage::new(SftpMessageType::Write, write_payload);
            self.send_message(&write_msg).await?;

            // Receive SSH_FXP_STATUS
            let status_msg = self.receive_message().await?;
            self.verify_status_ok(status_msg)?;

            offset += bytes_read as u64;
            total_written += bytes_read as u64;

            if total_written % (CHUNK_SIZE as u64 * 10) == 0 {
                debug!("Uploaded {} / {} bytes", total_written, file_size);
            }
        }

        info!("Uploaded {} bytes", total_written);

        // Close remote file (SSH_FXP_CLOSE)
        let request_id = self.next_request_id();
        let close_payload = self.build_close_request(request_id, &handle);
        let close_msg = SftpMessage::new(SftpMessageType::Close, close_payload);
        self.send_message(&close_msg).await?;

        // Receive SSH_FXP_STATUS
        let status_msg = self.receive_message().await?;
        self.verify_status_ok(status_msg)?;

        debug!("Remote file closed");
        Ok(())
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
        use tokio::io::AsyncWriteExt;

        info!("Downloading {} -> {}", remote_path, local_path);

        // Open remote file (SSH_FXP_OPEN for reading)
        let request_id = self.next_request_id();
        let open_payload = self.build_open_request(
            request_id,
            remote_path,
            FileOpenFlags::READ,
            0, // mode not needed for reading
        );
        let open_msg = SftpMessage::new(SftpMessageType::Open, open_payload);
        self.send_message(&open_msg).await?;

        // Receive SSH_FXP_HANDLE
        let handle_msg = self.receive_message().await?;
        if handle_msg.msg_type != SftpMessageType::Handle {
            return self.handle_status_response(handle_msg);
        }
        let handle = self.parse_handle(&handle_msg.payload)?;
        debug!("Remote file opened, handle length: {}", handle.len());

        // Create local file
        let mut local_file = tokio::fs::File::create(local_path).await
            .map_err(FynxError::Io)?;

        // Read data in chunks (32KB recommended)
        const CHUNK_SIZE: u32 = 32768;
        let mut offset = 0u64;
        let mut total_read = 0u64;

        loop {
            // Send SSH_FXP_READ
            let request_id = self.next_request_id();
            let read_payload = self.build_read_request(request_id, &handle, offset, CHUNK_SIZE);
            let read_msg = SftpMessage::new(SftpMessageType::Read, read_payload);
            self.send_message(&read_msg).await?;

            // Receive SSH_FXP_DATA or SSH_FXP_STATUS (EOF)
            let response = self.receive_message().await?;

            match response.msg_type {
                SftpMessageType::Data => {
                    // Parse data from response
                    let data = self.parse_data(&response.payload)?;

                    if data.is_empty() {
                        break; // EOF
                    }

                    // Write to local file
                    local_file.write_all(&data).await
                        .map_err(FynxError::Io)?;

                    offset += data.len() as u64;
                    total_read += data.len() as u64;

                    if total_read % (CHUNK_SIZE as u64 * 10) == 0 {
                        debug!("Downloaded {} bytes", total_read);
                    }
                }
                SftpMessageType::Status => {
                    // Check if it's EOF status
                    if response.payload.len() >= 8 {
                        let error_code = u32::from_be_bytes([
                            response.payload[4],
                            response.payload[5],
                            response.payload[6],
                            response.payload[7],
                        ]);

                        if error_code == SftpErrorCode::Eof as u32 {
                            debug!("Reached end of file");
                            break;
                        } else {
                            return self.verify_status_ok(response);
                        }
                    } else {
                        return Err(FynxError::Protocol("STATUS payload too short".to_string()));
                    }
                }
                _ => {
                    return Err(FynxError::Protocol(format!(
                        "Unexpected response type: {:?}",
                        response.msg_type
                    )));
                }
            }
        }

        // Flush and sync local file
        local_file.flush().await
            .map_err(FynxError::Io)?;

        info!("Downloaded {} bytes", total_read);

        // Close remote file (SSH_FXP_CLOSE)
        let request_id = self.next_request_id();
        let close_payload = self.build_close_request(request_id, &handle);
        let close_msg = SftpMessage::new(SftpMessageType::Close, close_payload);
        self.send_message(&close_msg).await?;

        // Receive SSH_FXP_STATUS
        let status_msg = self.receive_message().await?;
        self.verify_status_ok(status_msg)?;

        debug!("Remote file closed");
        Ok(())
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

        // Open directory (SSH_FXP_OPENDIR)
        let request_id = self.next_request_id();
        let opendir_payload = self.build_opendir_request(request_id, path);
        let opendir_msg = SftpMessage::new(SftpMessageType::OpenDir, opendir_payload);
        self.send_message(&opendir_msg).await?;

        // Receive SSH_FXP_HANDLE
        let handle_msg = self.receive_message().await?;
        if handle_msg.msg_type != SftpMessageType::Handle {
            return Err(FynxError::Protocol(format!(
                "Expected HANDLE, got {:?}",
                handle_msg.msg_type
            )));
        }
        let handle = self.parse_handle(&handle_msg.payload)?;
        debug!("Directory opened, handle length: {}", handle.len());

        // Read entries in a loop
        let mut entries = Vec::new();

        loop {
            // Send SSH_FXP_READDIR
            let request_id = self.next_request_id();
            let readdir_payload = self.build_readdir_request(request_id, &handle);
            let readdir_msg = SftpMessage::new(SftpMessageType::ReadDir, readdir_payload);
            self.send_message(&readdir_msg).await?;

            // Receive SSH_FXP_NAME or SSH_FXP_STATUS (EOF)
            let response = self.receive_message().await?;

            match response.msg_type {
                SftpMessageType::Name => {
                    // Parse entries from response
                    let batch = self.parse_name_entries(&response.payload)?;
                    entries.extend(batch);
                }
                SftpMessageType::Status => {
                    // Check if it's EOF status
                    if response.payload.len() >= 8 {
                        let error_code = u32::from_be_bytes([
                            response.payload[4],
                            response.payload[5],
                            response.payload[6],
                            response.payload[7],
                        ]);

                        if error_code == SftpErrorCode::Eof as u32 {
                            debug!("Reached end of directory");
                            break;
                        } else {
                            self.verify_status_ok(response)?;
                            return Err(FynxError::Protocol("Unexpected STATUS response".to_string()));
                        }
                    } else {
                        return Err(FynxError::Protocol("STATUS payload too short".to_string()));
                    }
                }
                _ => {
                    return Err(FynxError::Protocol(format!(
                        "Unexpected response type: {:?}",
                        response.msg_type
                    )));
                }
            }
        }

        info!("Listed {} entries", entries.len());

        // Close directory (SSH_FXP_CLOSE)
        let request_id = self.next_request_id();
        let close_payload = self.build_close_request(request_id, &handle);
        let close_msg = SftpMessage::new(SftpMessageType::Close, close_payload);
        self.send_message(&close_msg).await?;

        // Receive SSH_FXP_STATUS
        let status_msg = self.receive_message().await?;
        self.verify_status_ok(status_msg)?;

        debug!("Directory closed");
        Ok(entries)
    }

    // Helper methods for building SFTP request messages

    /// Builds SSH_FXP_OPEN request payload.
    fn build_open_request(&self, request_id: u32, filename: &str, flags: u32, mode: u32) -> Vec<u8> {
        let mut buf = Vec::new();

        // request-id
        buf.extend_from_slice(&request_id.to_be_bytes());

        // filename (string)
        let filename_bytes = filename.as_bytes();
        buf.extend_from_slice(&(filename_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(filename_bytes);

        // pflags
        buf.extend_from_slice(&flags.to_be_bytes());

        // attrs (minimal - just permissions)
        let mut attrs = FileAttributes::new();
        attrs.permissions = Some(FileMode(mode));
        buf.extend_from_slice(&attrs.to_bytes());

        buf
    }

    /// Builds SSH_FXP_CLOSE request payload.
    fn build_close_request(&self, request_id: u32, handle: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // request-id
        buf.extend_from_slice(&request_id.to_be_bytes());

        // handle (string)
        buf.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(handle);

        buf
    }

    /// Builds SSH_FXP_WRITE request payload.
    fn build_write_request(&self, request_id: u32, handle: &[u8], offset: u64, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // request-id
        buf.extend_from_slice(&request_id.to_be_bytes());

        // handle (string)
        buf.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(handle);

        // offset
        buf.extend_from_slice(&offset.to_be_bytes());

        // data (string)
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);

        buf
    }

    /// Builds SSH_FXP_READ request payload.
    fn build_read_request(&self, request_id: u32, handle: &[u8], offset: u64, len: u32) -> Vec<u8> {
        let mut buf = Vec::new();

        // request-id
        buf.extend_from_slice(&request_id.to_be_bytes());

        // handle (string)
        buf.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(handle);

        // offset
        buf.extend_from_slice(&offset.to_be_bytes());

        // len
        buf.extend_from_slice(&len.to_be_bytes());

        buf
    }

    /// Builds SSH_FXP_OPENDIR request payload.
    fn build_opendir_request(&self, request_id: u32, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();

        // request-id
        buf.extend_from_slice(&request_id.to_be_bytes());

        // path (string)
        let path_bytes = path.as_bytes();
        buf.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(path_bytes);

        buf
    }

    /// Builds SSH_FXP_READDIR request payload.
    fn build_readdir_request(&self, request_id: u32, handle: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // request-id
        buf.extend_from_slice(&request_id.to_be_bytes());

        // handle (string)
        buf.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        buf.extend_from_slice(handle);

        buf
    }

    /// Parses file handle from SSH_FXP_HANDLE response.
    fn parse_handle(&self, payload: &[u8]) -> FynxResult<Vec<u8>> {
        if payload.len() < 8 {
            return Err(FynxError::Protocol("HANDLE payload too short".to_string()));
        }

        // Skip request-id (first 4 bytes)
        let handle_len = u32::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
        ]) as usize;

        if payload.len() < 8 + handle_len {
            return Err(FynxError::Protocol("HANDLE data incomplete".to_string()));
        }

        Ok(payload[8..8 + handle_len].to_vec())
    }

    /// Parses data from SSH_FXP_DATA response.
    fn parse_data(&self, payload: &[u8]) -> FynxResult<Vec<u8>> {
        if payload.len() < 8 {
            return Err(FynxError::Protocol("DATA payload too short".to_string()));
        }

        // Skip request-id (first 4 bytes)
        let data_len = u32::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
        ]) as usize;

        if payload.len() < 8 + data_len {
            return Err(FynxError::Protocol("DATA incomplete".to_string()));
        }

        Ok(payload[8..8 + data_len].to_vec())
    }

    /// Parses directory entries from SSH_FXP_NAME response.
    fn parse_name_entries(&self, payload: &[u8]) -> FynxResult<Vec<(String, FileAttributes)>> {
        if payload.len() < 8 {
            return Err(FynxError::Protocol("NAME payload too short".to_string()));
        }

        // Skip request-id (first 4 bytes)
        let count = u32::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
        ]) as usize;

        let mut offset = 8;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            // Parse filename (string)
            if payload.len() < offset + 4 {
                return Err(FynxError::Protocol("NAME entry incomplete (filename length)".to_string()));
            }
            let filename_len = u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]) as usize;
            offset += 4;

            if payload.len() < offset + filename_len {
                return Err(FynxError::Protocol("NAME entry incomplete (filename)".to_string()));
            }
            let filename = String::from_utf8_lossy(&payload[offset..offset + filename_len]).to_string();
            offset += filename_len;

            // Parse longname (string) - we skip this for now
            if payload.len() < offset + 4 {
                return Err(FynxError::Protocol("NAME entry incomplete (longname length)".to_string()));
            }
            let longname_len = u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]) as usize;
            offset += 4;

            if payload.len() < offset + longname_len {
                return Err(FynxError::Protocol("NAME entry incomplete (longname)".to_string()));
            }
            offset += longname_len; // Skip longname

            // Parse attributes
            let (attrs, attrs_len) = FileAttributes::from_bytes(&payload[offset..])?;
            offset += attrs_len;

            entries.push((filename, attrs));
        }

        Ok(entries)
    }

    /// Handles SSH_FXP_STATUS response when expecting different message type.
    fn handle_status_response(&self, msg: SftpMessage) -> FynxResult<()> {
        if msg.msg_type == SftpMessageType::Status {
            if msg.payload.len() < 8 {
                return Err(FynxError::Protocol("STATUS payload too short".to_string()));
            }

            let error_code = u32::from_be_bytes([
                msg.payload[4],
                msg.payload[5],
                msg.payload[6],
                msg.payload[7],
            ]);

            let sftp_error = SftpErrorCode::from_u32(error_code)
                .unwrap_or(SftpErrorCode::Failure);

            return Err(FynxError::Protocol(format!(
                "SFTP operation failed: {}",
                sftp_error.message()
            )));
        }

        Err(FynxError::Protocol(format!(
            "Unexpected message type: {:?}",
            msg.msg_type
        )))
    }

    /// Verifies SSH_FXP_STATUS is OK.
    fn verify_status_ok(&self, msg: SftpMessage) -> FynxResult<()> {
        if msg.msg_type != SftpMessageType::Status {
            return Err(FynxError::Protocol(format!(
                "Expected STATUS, got {:?}",
                msg.msg_type
            )));
        }

        if msg.payload.len() < 8 {
            return Err(FynxError::Protocol("STATUS payload too short".to_string()));
        }

        let error_code = u32::from_be_bytes([
            msg.payload[4],
            msg.payload[5],
            msg.payload[6],
            msg.payload[7],
        ]);

        if error_code != SftpErrorCode::Ok as u32 {
            let sftp_error = SftpErrorCode::from_u32(error_code)
                .unwrap_or(SftpErrorCode::Failure);

            return Err(FynxError::Protocol(format!(
                "SFTP operation failed: {}",
                sftp_error.message()
            )));
        }

        Ok(())
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
