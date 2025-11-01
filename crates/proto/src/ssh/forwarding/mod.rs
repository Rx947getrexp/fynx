//! SSH Port Forwarding
//!
//! This module implements SSH port forwarding in three modes:
//! - **Local Forward**: Forward local ports to remote destinations (Direct TCP/IP)
//! - **Remote Forward**: Forward remote ports to local destinations (tcpip-forward)
//! - **Dynamic Forward**: SOCKS5 proxy for dynamic port forwarding
//!
//! # Local Forward Example
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
//! let forward = client.local_forward("localhost:8080", "database.internal:3306").await?;
//! forward.run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Remote Forward Example
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
//! let forward = client.remote_forward("0.0.0.0:8080", "localhost:3000").await?;
//! forward.run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Dynamic Forward Example
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
//! let proxy = client.dynamic_forward("localhost:1080").await?;
//! proxy.run().await?;
//! # Ok(())
//! # }
//! ```

pub mod dynamic;
pub mod local;
pub mod remote;
pub mod types;

pub use dynamic::DynamicForward;
pub use local::LocalForward;
pub use remote::RemoteForward;
pub use types::{parse_forward_addr, ForwardAddr};
