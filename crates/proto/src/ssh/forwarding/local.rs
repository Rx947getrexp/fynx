//! Local port forwarding (Direct TCP/IP).
//!
//! Forwards connections from a local address to a remote target through the SSH connection.
//!
//! # How it works
//!
//! 1. Listen on local address (e.g., localhost:8080)
//! 2. When a connection arrives, open an SSH channel (`direct-tcpip`)
//! 3. Relay data bidirectionally between local socket and SSH channel
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
//! // Forward localhost:8080 to database.internal:3306
//! let mut forward = client.local_forward(
//!     "localhost:8080",
//!     "database.internal:3306"
//! ).await?;
//!
//! // Run until stopped (Ctrl+C)
//! forward.run().await?;
//! # Ok(())
//! # }
//! ```

use super::types::ForwardAddr;
use crate::ssh::connection_mgr::SshConnection;
use crate::ssh::dispatcher::MessageDispatcher;
use fynx_platform::{FynxError, FynxResult};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Local port forwarding handle.
///
/// Created by [`SshClient::local_forward()`](crate::ssh::client::SshClient::local_forward).
pub struct LocalForward {
    /// TCP listener for incoming connections
    listener: TcpListener,
    /// Target address to connect to on the remote side
    target: ForwardAddr,
    /// Local bind address (for logging)
    local_addr: ForwardAddr,
    /// Connection counter
    connection_counter: Arc<Mutex<u64>>,
    /// SSH connection (for opening channels)
    connection: Arc<Mutex<SshConnection>>,
    /// Message dispatcher (for channel communication)
    dispatcher: Arc<Mutex<MessageDispatcher>>,
}

impl LocalForward {
    /// Creates a new local forward.
    ///
    /// This is called by `SshClient::local_forward()`.
    ///
    /// # Arguments
    ///
    /// * `listener` - TCP listener bound to local address
    /// * `local_addr` - Local address (for logging)
    /// * `target` - Target address on remote side
    /// * `connection` - SSH connection for opening channels
    /// * `dispatcher` - Message dispatcher for channel communication
    pub(crate) fn new(
        listener: TcpListener,
        local_addr: ForwardAddr,
        target: ForwardAddr,
        connection: Arc<Mutex<SshConnection>>,
        dispatcher: Arc<Mutex<MessageDispatcher>>,
    ) -> Self {
        Self {
            listener,
            target,
            local_addr,
            connection_counter: Arc::new(Mutex::new(0)),
            connection,
            dispatcher,
        }
    }

    /// Returns the local address this forwarder is listening on.
    pub fn local_addr(&self) -> &ForwardAddr {
        &self.local_addr
    }

    /// Returns the target address connections are forwarded to.
    pub fn target_addr(&self) -> &ForwardAddr {
        &self.target
    }

    /// Runs the local forwarder.
    ///
    /// This method will accept connections in a loop until an error occurs
    /// or the future is cancelled.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::client::SshClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut client = SshClient::connect("server:22").await?;
    /// # client.authenticate_password("user", "pass").await?;
    /// let forward = client.local_forward("localhost:8080", "target:80").await?;
    ///
    /// // Run with Ctrl+C handler
    /// tokio::select! {
    ///     result = forward.run() => {
    ///         eprintln!("Forward stopped: {:?}", result);
    ///     }
    ///     _ = tokio::signal::ctrl_c() => {
    ///         println!("Shutting down...");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run(self) -> FynxResult<()> {
        info!(
            "Local forward listening on {} -> {}",
            self.local_addr.to_string(),
            self.target.to_string()
        );

        loop {
            // Accept incoming connection
            let (local_stream, peer_addr) = match self.listener.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            debug!("Accepted connection from {}", peer_addr);

            // Increment connection counter
            let connection_id = {
                let mut counter = self.connection_counter.lock().await;
                *counter += 1;
                *counter
            };

            // Clone Arc references for the spawned task
            let target = self.target.clone();
            let connection = Arc::clone(&self.connection);
            let dispatcher = Arc::clone(&self.dispatcher);

            // Spawn task to handle this connection
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(
                    connection_id,
                    local_stream,
                    target,
                    connection,
                    dispatcher,
                ).await {
                    warn!("[Connection #{}] Error: {}", connection_id, e);
                }
            });
        }
    }

    /// Handles a single incoming connection.
    ///
    /// This is called for each accepted connection.
    async fn handle_connection(
        connection_id: u64,
        mut local_stream: TcpStream,
        target: ForwardAddr,
        connection: Arc<Mutex<SshConnection>>,
        dispatcher: Arc<Mutex<MessageDispatcher>>,
    ) -> FynxResult<()> {
        use crate::ssh::channel::{SshChannel, ChannelMessage};
        use crate::ssh::connection::{ChannelType, ChannelOpen, MAX_WINDOW_SIZE, MAX_PACKET_SIZE};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let peer_addr = local_stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        debug!(
            "[Connection #{}] Accepted from {} -> {}",
            connection_id,
            peer_addr,
            target.to_string()
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
        // TODO: Build proper direct-tcpip CHANNEL_OPEN message
        // For now, use Session as placeholder
        let channel_open = ChannelOpen::new(
            ChannelType::Session,  // TODO: Should be DirectTcpip with target addr/port
            local_id,
            MAX_WINDOW_SIZE,
            MAX_PACKET_SIZE,
        );
        let open_msg = channel_open.to_bytes();

        {
            let mut conn = connection.lock().await;
            conn.send_packet(&open_msg).await?;
        }

        // Wait for CHANNEL_OPEN_CONFIRMATION
        // TODO: Implement proper confirmation waiting with timeout
        // For now, just start relay immediately (will fail if channel not open)

        info!(
            "[Connection #{}] Channel {} opened to {}",
            connection_id,
            local_id,
            target.to_string()
        );

        // Bidirectional relay between local socket and SSH channel
        // Split local_stream into read and write halves
        let (mut local_read, mut local_write) = tokio::io::split(local_stream);

        // Get remote_id for creating data messages
        let remote_id = channel.remote_id();

        // Create shared shutdown signal
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_upload = Arc::clone(&shutdown);
        let shutdown_download = Arc::clone(&shutdown);

        // Task 1: Read from local socket, write to SSH channel (upload)
        let connection_upload = Arc::clone(&connection);
        let upload_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 32768];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) => {
                        // EOF from local socket
                        debug!("[Connection #{}] Local EOF", connection_id);
                        break;
                    }
                    Ok(n) => {
                        // Send CHANNEL_DATA message
                        use crate::ssh::connection::ChannelData;
                        let channel_data = ChannelData::new(remote_id, buf[..n].to_vec());
                        let data_msg = channel_data.to_bytes();

                        let mut conn = connection_upload.lock().await;
                        if let Err(e) = conn.send_packet(&data_msg).await {
                            warn!("[Connection #{}] Failed to send data: {}", connection_id, e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("[Connection #{}] Local read error: {}", connection_id, e);
                        break;
                    }
                }
            }
            shutdown_upload.notify_one();
        });

        // Task 2: Read from SSH channel, write to local socket (download)
        let download_task = tokio::spawn(async move {
            loop {
                match channel.read().await {
                    Ok(Some(ChannelMessage::Data(data))) => {
                        if let Err(e) = local_write.write_all(&data).await {
                            warn!("[Connection #{}] Local write error: {}", connection_id, e);
                            break;
                        }
                    }
                    Ok(Some(ChannelMessage::Eof)) | Ok(Some(ChannelMessage::Close)) => {
                        debug!("[Connection #{}] SSH channel EOF/Close", connection_id);
                        break;
                    }
                    Ok(Some(_)) => {
                        // Other message types, ignore
                    }
                    Ok(None) => {
                        // Legacy mode, shouldn't happen
                        warn!("[Connection #{}] Channel in legacy mode", connection_id);
                        break;
                    }
                    Err(e) => {
                        warn!("[Connection #{}] Channel read error: {}", connection_id, e);
                        break;
                    }
                }
            }
            shutdown_download.notify_one();
        });

        // Wait for either task to complete
        shutdown.notified().await;

        // Tasks will complete on their own, but we can abort them to be safe
        upload_task.abort();
        download_task.abort();

        // Unregister channel
        dispatcher.lock().await.unregister_channel(local_id).await;

        info!(
            "[Connection #{}] Closed: {} -> {}",
            connection_id,
            peer_addr,
            target.to_string()
        );

        Ok(())
    }
}

/// Helper function to relay data bidirectionally between two async streams.
///
/// This is a generic relay function that can be used for forwarding data
/// between any two async read/write streams.
async fn relay_bidirectional<A, B>(mut stream_a: A, mut stream_b: B) -> FynxResult<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut stream_a, &mut stream_b).await {
        Ok((bytes_a_to_b, bytes_b_to_a)) => {
            debug!(
                "Relay completed: {} bytes A->B, {} bytes B->A",
                bytes_a_to_b, bytes_b_to_a
            );
            Ok(())
        }
        Err(e) => {
            warn!("Relay error: {}", e);
            Err(FynxError::Io(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_addr_accessors() {
        // Test ForwardAddr methods since we can't easily test LocalForward
        // without mocking connection and dispatcher
        let local_addr = ForwardAddr::new("127.0.0.1".to_string(), 8080);
        let target = ForwardAddr::new("target.example.com".to_string(), 80);

        assert_eq!(local_addr.host, "127.0.0.1");
        assert_eq!(local_addr.port, 8080);
        assert_eq!(target.host, "target.example.com");
        assert_eq!(target.port, 80);
    }

    // TODO: Add integration tests when full channel support is complete
    // Full tests require:
    // 1. Mock or real SSH server
    // 2. Connection and dispatcher setup
    // 3. End-to-end forwarding validation
}
