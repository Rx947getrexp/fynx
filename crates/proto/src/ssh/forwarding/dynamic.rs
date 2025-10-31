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
use fynx_platform::{FynxError, FynxResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

/// Dynamic port forwarding (SOCKS5 proxy) handle.
///
/// Created by [`SshClient::dynamic_forward()`](crate::ssh::client::SshClient::dynamic_forward).
#[derive(Debug)]
pub struct DynamicForward {
    /// TCP listener for SOCKS5 connections
    listener: TcpListener,
    /// Local bind address
    local_addr: ForwardAddr,
}

impl DynamicForward {
    /// Creates a new dynamic forward (SOCKS5 proxy).
    ///
    /// This is called by `SshClient::dynamic_forward()`.
    pub(crate) fn new(listener: TcpListener, local_addr: ForwardAddr) -> Self {
        Self {
            listener,
            local_addr,
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

        // TODO: Implement SOCKS5 server loop
        // This requires integration with SshClient to open channels

        Err(FynxError::NotImplemented(
            "Dynamic forward (SOCKS5) not yet implemented".to_string()
        ))
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
            return Err(FynxError::Protocol("No authentication methods provided".to_string()));
        }

        stream.read_exact(&mut buf[..nmethods]).await?;

        // Send method selection: [version, method]
        // 0x00 = no authentication required
        stream.write_all(&[5, 0]).await?;

        // Read request: [version, command, reserved, address_type, ...]
        stream.read_exact(&mut buf[..4]).await?;

        if buf[0] != 5 {
            return Err(FynxError::Protocol("Invalid SOCKS version in request".to_string()));
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

    #[tokio::test]
    async fn test_dynamic_forward_creation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = ForwardAddr::new("127.0.0.1".to_string(), 1080);

        let forward = DynamicForward::new(listener, local_addr.clone());

        assert_eq!(forward.local_addr(), &local_addr);
    }

    // TODO: Add SOCKS5 protocol tests
}
