//! SSH Session management.
//!
//! This module provides session management features including:
//! - Keep-alive heartbeat (preventing idle timeouts)
//! - Automatic reconnection (handling network interruptions)
//! - Connection pooling (reusing connections)

pub mod keepalive;

pub use keepalive::{create_keepalive_message, KeepaliveTask};
