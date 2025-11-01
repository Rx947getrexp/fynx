//! Remote port forwarding (tcpip-forward).
//!
//! Asks the SSH server to forward connections from a remote address to a local target.
//!
//! # How it works
//!
//! 1. Send global request "tcpip-forward" to server
//! 2. Server listens on the specified remote address
//! 3. When a connection arrives, server opens channel (`forwarded-tcpip`)
//! 4. Client connects to local target and relays data bidirectionally
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
//! // Forward remote:8080 to localhost:3000
//! let mut forward = client.remote_forward(
//!     "0.0.0.0:8080",
//!     "localhost:3000"
//! ).await?;
//!
//! // Handle incoming connections
//! forward.run().await?;
//! # Ok(())
//! # }
//! ```

use super::types::ForwardAddr;
use crate::ssh::connection_mgr::SshConnection;
use crate::ssh::dispatcher::MessageDispatcher;
use fynx_platform::FynxResult;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Remote port forwarding handle.
///
/// Created by [`SshClient::remote_forward()`](crate::ssh::client::SshClient::remote_forward).
pub struct RemoteForward {
    /// Address the server is listening on
    bind_addr: ForwardAddr,
    /// Local target address to forward to
    local_target: ForwardAddr,
    /// SSH connection (for channel operations)
    connection: Arc<Mutex<SshConnection>>,
    /// Message dispatcher (for channel communication)
    dispatcher: Arc<Mutex<MessageDispatcher>>,
}

impl RemoteForward {
    /// Creates a new remote forward.
    ///
    /// This is called by `SshClient::remote_forward()` after sending
    /// the tcpip-forward global request.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Address the server is listening on
    /// * `local_target` - Local address to forward connections to
    /// * `connection` - SSH connection for channel operations
    /// * `dispatcher` - Message dispatcher for channel communication
    pub(crate) fn new(
        bind_addr: ForwardAddr,
        local_target: ForwardAddr,
        connection: Arc<Mutex<SshConnection>>,
        dispatcher: Arc<Mutex<MessageDispatcher>>,
    ) -> Self {
        Self {
            bind_addr,
            local_target,
            connection,
            dispatcher,
        }
    }

    /// Returns the remote bind address.
    pub fn bind_addr(&self) -> &ForwardAddr {
        &self.bind_addr
    }

    /// Returns the local target address.
    pub fn local_target(&self) -> &ForwardAddr {
        &self.local_target
    }

    /// Runs the remote forwarder.
    ///
    /// This method handles incoming `forwarded-tcpip` channels from the server.
    ///
    /// When the SSH server receives a connection on the remote address, it will
    /// send a CHANNEL_OPEN message with type "forwarded-tcpip". This method waits
    /// for those messages and handles each incoming connection.
    pub async fn run(self) -> FynxResult<()> {
        info!(
            "Remote forward active: {} -> {}",
            self.bind_addr.to_string(),
            self.local_target.to_string()
        );

        // TODO: Implement forwarded-tcpip channel handling
        //
        // This requires:
        // 1. Listen for global messages from dispatcher
        // 2. Parse CHANNEL_OPEN (forwarded-tcpip) messages
        // 3. For each channel:
        //    - Send CHANNEL_OPEN_CONFIRMATION
        //    - Connect to local target (TcpStream::connect)
        //    - Relay data bidirectionally (similar to LocalForward)
        //
        // The challenge is that CHANNEL_OPEN messages arrive via the dispatcher's
        // global message channel, which we need to access.

        loop {
            // Wait for forwarded-tcpip CHANNEL_OPEN from server
            let global_msg = match self.dispatcher.lock().await.receive_global().await {
                Some(msg) => msg,
                None => {
                    warn!("Global message channel closed");
                    break;
                }
            };

            if global_msg.is_empty() {
                continue;
            }

            // Check if this is a CHANNEL_OPEN message
            use crate::ssh::message::MessageType;
            if global_msg[0] != MessageType::ChannelOpen as u8 {
                // Not a CHANNEL_OPEN, ignore
                debug!(
                    "Received non-CHANNEL_OPEN global message: {}",
                    global_msg[0]
                );
                continue;
            }

            // Parse CHANNEL_OPEN message
            // TODO: Proper parsing of forwarded-tcpip CHANNEL_OPEN
            // For now, log that we received it

            info!(
                "Received CHANNEL_OPEN message, forwarded-tcpip handling not yet fully implemented"
            );

            // TODO:
            // 1. Parse channel parameters (sender_channel, window_size, etc.)
            // 2. Connect to local target
            // 3. Send CHANNEL_OPEN_CONFIRMATION
            // 4. Spawn task to handle bidirectional relay
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_addr_remote() {
        // Test ForwardAddr methods since we can't easily test RemoteForward
        // without mocking connection and dispatcher
        let bind = ForwardAddr::new("0.0.0.0".to_string(), 8080);
        let target = ForwardAddr::new("localhost".to_string(), 3000);

        assert_eq!(bind.host, "0.0.0.0");
        assert_eq!(bind.port, 8080);
        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, 3000);
    }

    // TODO: Add integration tests when full forwarded-tcpip support is complete
    // Full tests require:
    // 1. Mock or real SSH server that supports tcpip-forward
    // 2. Connection and dispatcher setup
    // 3. End-to-end remote forwarding validation
}
