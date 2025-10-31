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
use fynx_platform::{FynxError, FynxResult};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Local port forwarding handle.
///
/// Created by [`SshClient::local_forward()`](crate::ssh::client::SshClient::local_forward).
#[derive(Debug)]
pub struct LocalForward {
    /// TCP listener for incoming connections
    listener: TcpListener,
    /// Target address to connect to on the remote side
    target: ForwardAddr,
    /// Local bind address (for logging)
    local_addr: ForwardAddr,
    /// Connection counter
    connection_counter: Arc<Mutex<u64>>,
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
    pub(crate) fn new(
        listener: TcpListener,
        local_addr: ForwardAddr,
        target: ForwardAddr,
    ) -> Self {
        Self {
            listener,
            target,
            local_addr,
            connection_counter: Arc::new(Mutex::new(0)),
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

        // NOTE: This is a placeholder implementation.
        // The actual implementation requires access to SshClient to open channels,
        // which needs to be passed in or stored in the struct.
        //
        // For now, we'll return an error indicating this is not yet implemented.
        Err(FynxError::NotImplemented(
            "Local forward not yet fully implemented - requires channel management".to_string()
        ))
    }

    /// Handles a single incoming connection.
    ///
    /// This is called for each accepted connection.
    async fn handle_connection(
        connection_id: u64,
        local_stream: TcpStream,
        target: ForwardAddr,
    ) -> FynxResult<()> {
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

        // TODO: Open SSH channel (direct-tcpip) to target
        // This requires access to SshClient's transport layer
        //
        // Placeholder:
        // let mut channel = ssh_client.open_direct_tcpip(&target.host, target.port).await?;

        // TODO: Bidirectional relay
        // tokio::io::copy_bidirectional(&mut local_stream, &mut channel).await?;

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

    #[tokio::test]
    async fn test_local_forward_creation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = ForwardAddr::new("127.0.0.1".to_string(), 8080);
        let target = ForwardAddr::new("target.example.com".to_string(), 80);

        let forward = LocalForward::new(listener, local_addr.clone(), target.clone());

        assert_eq!(forward.local_addr(), &local_addr);
        assert_eq!(forward.target_addr(), &target);
    }

    // TODO: Add more tests when channel integration is complete
}
