//! Dynamic port forwarding (SOCKS5 proxy).
//!
//! Creates a SOCKS5 proxy server that dynamically forwards connections
//! through the SSH tunnel based on the SOCKS5 protocol.
//!
//! # How it works
//!
//! 1. Listen on local address as SOCKS5 proxy
//! 2. Client connects and performs SOCKS5 handshake
//! 3. Extract target host and port from SOCKS5 request
//! 4. Open SSH channel (`direct-tcpip`) to target
//! 5. Relay data bidirectionally
//!
//! # Example
//!
//! ```rust,no_run
//! use fynx_proto::ssh::client::SshClient;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = SshClient::connect("server:22").await?;
//! client.authenticate_password("user", "pass").await?;
//!
//! // Create SOCKS5 proxy on localhost:1080
//! let mut proxy = client.dynamic_forward("localhost:1080").await?;
//!
//! // Run proxy
//! proxy.run().await?;
//! # Ok(())
//! # }
//! ```

use super::types::ForwardAddr;
use crate::ssh::connection_mgr::SshConnection;
use crate::ssh::dispatcher::MessageDispatcher;
use fynx_platform::{FynxError, FynxResult};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Dynamic port forwarding (SOCKS5 proxy) handle.
///
/// Created by [`SshClient::dynamic_forward()`](crate::ssh::client::SshClient::dynamic_forward).
pub struct DynamicForward {
    /// TCP listener for SOCKS5 connections
    listener: TcpListener,
    /// Local bind address
    local_addr: ForwardAddr,
    /// SSH connection (for opening channels)
    connection: Arc<Mutex<SshConnection>>,
    /// Message dispatcher (for channel communication)
    dispatcher: Arc<Mutex<MessageDispatcher>>,
    /// Connection counter
    connection_counter: Arc<Mutex<u64>>,
}

impl DynamicForward {
    /// Creates a new dynamic forward (SOCKS5 proxy).
    ///
    /// This is called by `SshClient::dynamic_forward()`.
    ///
    /// # Arguments
    ///
    /// * `listener` - TCP listener for SOCKS5 connections
    /// * `local_addr` - Local address (for logging)
    /// * `connection` - SSH connection for opening channels
    /// * `dispatcher` - Message dispatcher for channel communication
    pub(crate) fn new(
        listener: TcpListener,
        local_addr: ForwardAddr,
        connection: Arc<Mutex<SshConnection>>,
        dispatcher: Arc<Mutex<MessageDispatcher>>,
    ) -> Self {
        Self {
            listener,
            local_addr,
            connection,
            dispatcher,
            connection_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Returns the local address the SOCKS5 proxy is listening on.
    pub fn local_addr(&self) -> &ForwardAddr {
        &self.local_addr
    }

    /// Runs the SOCKS5 proxy.
    ///
    /// This method will accept connections and handle SOCKS5 protocol.
    pub async fn run(self) -> FynxResult<()> {
        info!("SOCKS5 proxy listening on {}", self.local_addr.to_string());

        loop {
            // Accept incoming SOCKS5 connection
            let (socks_stream, peer_addr) = match self.listener.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(e) => {
                    warn!("Failed to accept SOCKS5 connection: {}", e);
                    continue;
                }
            };

            debug!("Accepted SOCKS5 connection from {}", peer_addr);

            // Increment connection counter
            let connection_id = {
                let mut counter = self.connection_counter.lock().await;
                *counter += 1;
                *counter
            };

            // Clone Arc references for the spawned task
            let connection = Arc::clone(&self.connection);
            let dispatcher = Arc::clone(&self.dispatcher);

            // Spawn task to handle this connection
            tokio::spawn(async move {
                if let Err(e) = Self::handle_socks_connection(
                    connection_id,
                    socks_stream,
                    connection,
                    dispatcher,
                )
                .await
                {
                    warn!("[SOCKS #{}] Error: {}", connection_id, e);
                }
            });
        }
    }

    /// Handles a single SOCKS5 connection.
    async fn handle_socks_connection(
        connection_id: u64,
        mut socks_stream: TcpStream,
        connection: Arc<Mutex<SshConnection>>,
        dispatcher: Arc<Mutex<MessageDispatcher>>,
    ) -> FynxResult<()> {
        use crate::ssh::channel::{ChannelMessage, SshChannel};
        use crate::ssh::connection::{
            ChannelData, ChannelOpen, ChannelType, MAX_PACKET_SIZE, MAX_WINDOW_SIZE,
        };

        // Perform SOCKS5 handshake to get target address
        let (target_host, target_port) = match Self::socks5_handshake(&mut socks_stream).await {
            Ok(target) => target,
            Err(e) => {
                warn!("[SOCKS #{}] Handshake failed: {}", connection_id, e);
                let _ = Self::socks5_send_error(&mut socks_stream, 1).await;
                return Err(e);
            }
        };

        info!(
            "[SOCKS #{}] Target: {}:{}",
            connection_id, target_host, target_port
        );

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

        // Send CHANNEL_OPEN (direct-tcpip) message
        let channel_open = ChannelOpen::new(
            ChannelType::DirectTcpip {
                host: target_host.clone(),
                port: target_port as u32,
                originator_address: "127.0.0.1".to_string(), // SOCKS5 client is local
                originator_port: 0,                          // Unknown SOCKS5 client port
            },
            local_id,
            MAX_WINDOW_SIZE,
            MAX_PACKET_SIZE,
        );
        let open_msg = channel_open.to_bytes();

        {
            let mut conn = connection.lock().await;
            conn.send_packet(&open_msg).await?;
        }

        // Send SOCKS5 success response
        if let Err(e) = Self::socks5_send_success(&mut socks_stream).await {
            warn!("[SOCKS #{}] Failed to send success: {}", connection_id, e);
            dispatcher.lock().await.unregister_channel(local_id).await;
            return Err(e);
        }

        info!("[SOCKS #{}] Channel {} opened", connection_id, local_id);

        // Bidirectional relay between SOCKS client and SSH channel
        let (mut socks_read, mut socks_write) = tokio::io::split(socks_stream);
        let remote_id = channel.remote_id();

        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_upload = Arc::clone(&shutdown);
        let shutdown_download = Arc::clone(&shutdown);

        // Upload: SOCKS client -> SSH channel
        let connection_upload = Arc::clone(&connection);
        let upload_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 32768];
            loop {
                match socks_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!("[SOCKS #{}] Client EOF", connection_id);
                        break;
                    }
                    Ok(n) => {
                        let channel_data = ChannelData::new(remote_id, buf[..n].to_vec());
                        let data_msg = channel_data.to_bytes();

                        let mut conn = connection_upload.lock().await;
                        if let Err(e) = conn.send_packet(&data_msg).await {
                            warn!("[SOCKS #{}] Failed to send data: {}", connection_id, e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("[SOCKS #{}] Client read error: {}", connection_id, e);
                        break;
                    }
                }
            }
            shutdown_upload.notify_one();
        });

        // Download: SSH channel -> SOCKS client
        let download_task = tokio::spawn(async move {
            loop {
                match channel.read().await {
                    Ok(Some(ChannelMessage::Data(data))) => {
                        if let Err(e) = socks_write.write_all(&data).await {
                            warn!("[SOCKS #{}] Client write error: {}", connection_id, e);
                            break;
                        }
                    }
                    Ok(Some(ChannelMessage::Eof)) | Ok(Some(ChannelMessage::Close)) => {
                        debug!("[SOCKS #{}] SSH channel EOF/Close", connection_id);
                        break;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        warn!("[SOCKS #{}] Channel in legacy mode", connection_id);
                        break;
                    }
                    Err(e) => {
                        warn!("[SOCKS #{}] Channel read error: {}", connection_id, e);
                        break;
                    }
                }
            }
            shutdown_download.notify_one();
        });

        // Wait for either task to complete
        shutdown.notified().await;

        upload_task.abort();
        download_task.abort();

        // Unregister channel
        dispatcher.lock().await.unregister_channel(local_id).await;

        info!("[SOCKS #{}] Connection closed", connection_id);

        Ok(())
    }

    /// Handles SOCKS5 handshake and returns target address.
    ///
    /// # SOCKS5 Protocol
    ///
    /// ```text
    /// Client → Server: [version, nmethods, methods...]
    /// Server → Client: [version, method]
    /// Client → Server: [version, command, reserved, address_type, address, port]
    /// Server → Client: [version, status, reserved, address_type, address, port]
    /// ```
    async fn socks5_handshake(stream: &mut TcpStream) -> FynxResult<(String, u16)> {
        // Read greeting: [version, nmethods, methods...]
        let mut buf = [0u8; 257];
        stream.read_exact(&mut buf[..2]).await?;

        if buf[0] != 5 {
            return Err(FynxError::Protocol(format!(
                "Invalid SOCKS version: expected 5, got {}",
                buf[0]
            )));
        }

        let nmethods = buf[1] as usize;
        if nmethods == 0 {
            return Err(FynxError::Protocol(
                "No authentication methods provided".to_string(),
            ));
        }

        stream.read_exact(&mut buf[..nmethods]).await?;

        // Send method selection: [version, method]
        // 0x00 = no authentication required
        stream.write_all(&[5, 0]).await?;

        // Read request: [version, command, reserved, address_type, ...]
        stream.read_exact(&mut buf[..4]).await?;

        if buf[0] != 5 {
            return Err(FynxError::Protocol(
                "Invalid SOCKS version in request".to_string(),
            ));
        }

        if buf[1] != 1 {
            // CONNECT command
            return Err(FynxError::Protocol(format!(
                "Unsupported SOCKS command: {} (only CONNECT supported)",
                buf[1]
            )));
        }

        // Parse target address
        let address_type = buf[3];
        let (host, port) = match address_type {
            1 => {
                // IPv4
                stream.read_exact(&mut buf[..6]).await?;
                let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                (ip, port)
            }
            3 => {
                // Domain name
                stream.read_exact(&mut buf[..1]).await?;
                let len = buf[0] as usize;
                stream.read_exact(&mut buf[..len + 2]).await?;
                let host = String::from_utf8_lossy(&buf[..len]).to_string();
                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                (host, port)
            }
            4 => {
                // IPv6
                stream.read_exact(&mut buf[..18]).await?;
                let ip = format!(
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    buf[0], buf[1], buf[2], buf[3],
                    buf[4], buf[5], buf[6], buf[7],
                    buf[8], buf[9], buf[10], buf[11],
                    buf[12], buf[13], buf[14], buf[15]
                );
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                (ip, port)
            }
            _ => {
                return Err(FynxError::Protocol(format!(
                    "Invalid address type: {}",
                    address_type
                )))
            }
        };

        debug!("SOCKS5 request: {}:{}", host, port);

        Ok((host, port))
    }

    /// Sends SOCKS5 success response.
    async fn socks5_send_success(stream: &mut TcpStream) -> FynxResult<()> {
        // [version, status, reserved, address_type, bound_address, bound_port]
        // Status 0 = succeeded
        stream
            .write_all(&[
                5, 0, 0, 1, // version, success, reserved, IPv4
                0, 0, 0, 0, // Bound address (0.0.0.0)
                0, 0, // Bound port (0)
            ])
            .await?;
        Ok(())
    }

    /// Sends SOCKS5 error response.
    async fn socks5_send_error(stream: &mut TcpStream, error_code: u8) -> FynxResult<()> {
        // Common error codes:
        // 0x01 = general failure
        // 0x02 = connection not allowed by ruleset
        // 0x03 = network unreachable
        // 0x04 = host unreachable
        // 0x05 = connection refused
        stream
            .write_all(&[
                5, error_code, 0, 1, // version, error, reserved, IPv4
                0, 0, 0, 0, // Bound address
                0, 0, // Bound port
            ])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_addr_dynamic() {
        // Test ForwardAddr methods since we can't easily test DynamicForward
        // without mocking connection and dispatcher
        let local_addr = ForwardAddr::new("127.0.0.1".to_string(), 1080);

        assert_eq!(local_addr.host, "127.0.0.1");
        assert_eq!(local_addr.port, 1080);
    }

    // TODO: Add integration tests when full SOCKS5 support is complete
    // Full tests require:
    // 1. Mock or real SOCKS5 client
    // 2. Connection and dispatcher setup
    // 3. End-to-end SOCKS5 forwarding validation

    // TODO: Add SOCKS5 protocol tests
}
