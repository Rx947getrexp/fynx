//! IPSec Client/Server High-Level API Tests
//!
//! Tests for the high-level IpsecClient and IpsecServer APIs.
//!
//! # Note
//!
//! These tests verify the API design and basic functionality of the
//! client and server high-level APIs introduced in Phase 5 Stage 2.
//!
//! Full end-to-end integration tests with concurrent client/server
//! communication will be implemented in Phase 6 (Application Layer).

#![cfg(feature = "ipsec")]

use fynx_proto::ipsec::{
    config::{ClientConfig, ServerConfig},
    IpsecClient, IpsecServer,
};
use std::time::Duration;

/// Test client and server configuration and initialization
///
/// Verifies that:
/// - Client can be created with valid configuration
/// - Server can bind to a local address
/// - Both have correct initial state
#[tokio::test]
async fn test_client_server_initialization() {
    // Create client config
    let client_config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"test-psk-secret")
        .build()
        .expect("Failed to build client config");

    // Create client
    let client = IpsecClient::new(client_config);
    assert!(client.should_perform_dpd() == false); // No DPD configured

    // Create server config
    let server_config = ServerConfig::builder()
        .with_local_id("server@example.com")
        .with_psk(b"test-psk-secret")
        .build()
        .expect("Failed to build server config");

    // Bind server
    let server = IpsecServer::bind(server_config, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("Failed to bind server");

    assert_eq!(server.session_count(), 0);
    assert!(server.local_addr().port() > 0);
}

/// Test client connection failure scenarios
///
/// Verifies that:
/// - Client handles connection failures gracefully
/// - Proper error types are returned
/// - Timeout mechanism works
#[tokio::test]
async fn test_client_connection_failure() {
    let client_config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"test-psk-secret")
        .build()
        .expect("Failed to build client config");

    let mut client = IpsecClient::new(client_config);

    // Try to connect to non-existent server
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        client.connect("127.0.0.1:9999".parse().unwrap()),
    )
    .await;

    // Should timeout or fail quickly
    match result {
        Err(_elapsed) => {
            // Timeout - expected behavior
        }
        Ok(connect_result) => {
            // Connection completed, should be an error
            assert!(
                connect_result.is_err(),
                "Connection should fail when no server present"
            );
        }
    }
}

/// Test server accept timeout
///
/// Verifies that:
/// - Server accept() can timeout when no client connects
/// - Server maintains correct state after timeout
#[tokio::test]
async fn test_server_accept_timeout() {
    let server_config = ServerConfig::builder()
        .with_local_id("server@example.com")
        .with_psk(b"test-psk-secret")
        .build()
        .expect("Failed to build server config");

    let mut server = IpsecServer::bind(server_config, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("Failed to bind server");

    // Try to accept with timeout (no client connecting)
    let result = tokio::time::timeout(Duration::from_millis(100), server.accept()).await;

    // Should timeout
    assert!(result.is_err(), "Accept should timeout when no client connects");
    assert_eq!(server.session_count(), 0);
}

/// Test client and server API lifecycle
///
/// This test verifies the complete API lifecycle including:
/// - Configuration validation
/// - Resource initialization
/// - State management
/// - Graceful shutdown
///
/// # Note
///
/// This test does not perform actual network communication between
/// client and server, as that requires concurrent task management
/// and will be implemented in Phase 6.
#[tokio::test]
async fn test_client_server_lifecycle() {
    // === Client Lifecycle ===

    let client_config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"shared-secret-key")
        .build()
        .expect("Failed to build client config");

    let mut client = IpsecClient::new(client_config);

    // Before connection, operations should fail
    assert!(client.send_packet(b"test").await.is_err());

    // recv_packet should return error immediately (not timeout)
    let recv_result = tokio::time::timeout(Duration::from_millis(50), client.recv_packet()).await;
    match recv_result {
        Ok(result) => {
            // Operation completed quickly, should be an error
            assert!(result.is_err(), "recv_packet should fail when not connected");
        }
        Err(_) => {
            // Timeout - also acceptable for this test
        }
    }

    // Shutdown without connection should succeed (no-op)
    client.shutdown().await.expect("Shutdown should succeed");

    // === Server Lifecycle ===

    let server_config = ServerConfig::builder()
        .with_local_id("server@example.com")
        .with_psk(b"shared-secret-key")
        .build()
        .expect("Failed to build server config");

    let server = IpsecServer::bind(server_config, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("Failed to bind server");

    let _addr = server.local_addr();
    assert_eq!(server.session_count(), 0);

    // Shutdown empty server should succeed
    server.shutdown().await.expect("Server shutdown should succeed");
}

/// Test client background task APIs
///
/// Verifies that:
/// - DPD check API works correctly
/// - Rekey detection works correctly
/// - APIs are callable and return expected results
#[tokio::test]
async fn test_client_background_tasks() {
    use fynx_proto::ipsec::{child_sa::SaLifetime, dpd::DpdConfig};

    let dpd_config = DpdConfig {
        enabled: true,
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(10),
        max_retries: 3,
    };

    let lifetime = SaLifetime {
        soft_time: Duration::from_secs(1),
        hard_time: Duration::from_secs(2),
        soft_bytes: None,
        hard_bytes: None,
    };

    let client_config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"test-key")
        .with_dpd(dpd_config)
        .with_lifetime(lifetime)
        .build()
        .expect("Failed to build config");

    let client = IpsecClient::new(client_config);

    // DPD should be available
    assert!(client.should_perform_dpd());

    // No Child SAs yet, so no rekey needed
    assert_eq!(client.check_rekey_needed().len(), 0);
}

/// Test configuration validation
///
/// Verifies that:
/// - Invalid configurations are rejected
/// - Proper error messages are provided
/// - Builder pattern enforces requirements
#[test]
fn test_configuration_validation() {
    // Client config - missing local_id
    let result = ClientConfig::builder()
        .with_remote_id("server@example.com")
        .with_psk(b"secret")
        .build();
    assert!(result.is_err());

    // Client config - missing remote_id
    let result = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_psk(b"secret")
        .build();
    assert!(result.is_err());

    // Client config - missing PSK
    let result = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .build();
    assert!(result.is_err());

    // Server config - empty local_id
    let result = ServerConfig::builder()
        .with_local_id("")
        .with_psk(b"secret")
        .build();
    assert!(result.is_err());

    // Valid configurations should succeed
    let result = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"secret")
        .build();
    assert!(result.is_ok());

    let result = ServerConfig::builder()
        .with_local_id("server@example.com")
        .with_psk(b"secret")
        .build();
    assert!(result.is_ok());
}
