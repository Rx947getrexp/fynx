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
use fynx_platform::{FynxError, FynxResult};
use tracing::info;

/// Remote port forwarding handle.
///
/// Created by [`SshClient::remote_forward()`](crate::ssh::client::SshClient::remote_forward).
#[derive(Debug)]
pub struct RemoteForward {
    /// Address the server is listening on
    bind_addr: ForwardAddr,
    /// Local target address to forward to
    local_target: ForwardAddr,
}

impl RemoteForward {
    /// Creates a new remote forward.
    ///
    /// This is called by `SshClient::remote_forward()` after sending
    /// the tcpip-forward global request.
    pub(crate) fn new(bind_addr: ForwardAddr, local_target: ForwardAddr) -> Self {
        Self {
            bind_addr,
            local_target,
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
    pub async fn run(self) -> FynxResult<()> {
        info!(
            "Remote forward active: {} -> {}",
            self.bind_addr.to_string(),
            self.local_target.to_string()
        );

        // TODO: Implement channel handling loop
        // This requires integration with SshClient's message handling

        Err(FynxError::NotImplemented(
            "Remote forward not yet implemented - requires global request support".to_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_forward_creation() {
        let bind = ForwardAddr::new("0.0.0.0".to_string(), 8080);
        let target = ForwardAddr::new("localhost".to_string(), 3000);

        let forward = RemoteForward::new(bind.clone(), target.clone());

        assert_eq!(forward.bind_addr(), &bind);
        assert_eq!(forward.local_target(), &target);
    }
}
