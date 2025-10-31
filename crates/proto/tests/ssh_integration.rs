//! Integration tests for SSH client-server communication.
//!
//! These tests validate the complete SSH protocol flow including:
//! - Version exchange
//! - Key exchange with signature verification
//! - Authentication
//! - Command execution

use fynx_platform::FynxResult;
use fynx_proto::ssh::client::{SshClient, SshClientConfig};
use fynx_proto::ssh::hostkey::{Ed25519HostKey, HostKey};
use fynx_proto::ssh::known_hosts::StrictHostKeyChecking;
use fynx_proto::ssh::server::{SessionHandler, SshServer};
use std::sync::Arc;
use tokio::time::{timeout, Duration};

/// Helper function to create a test client config that accepts all hosts.
/// For integration tests, we use `No` to skip host key verification and file I/O.
fn test_client_config() -> SshClientConfig {
    let mut config = SshClientConfig::default();
    config.strict_host_key_checking = StrictHostKeyChecking::No;
    config
}

/// Simple test handler that echoes commands.
struct TestHandler;

#[async_trait::async_trait]
impl SessionHandler for TestHandler {
    async fn handle_exec(&mut self, command: &str) -> FynxResult<Vec<u8>> {
        Ok(format!("Executed: {}", command).into_bytes())
    }
}

/// Test basic version exchange between client and server.
#[tokio::test]
async fn test_version_exchange() -> Result<(), Box<dyn std::error::Error>> {
    // Start server
    let server = SshServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr()?;

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        let session = server.accept().await;
        session
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client
    let client = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    // Verify client connected successfully
    assert_eq!(
        client.server_address(),
        &format!("127.0.0.1:{}", server_addr.port())
    );

    // Wait for server to complete
    let session_result = timeout(Duration::from_secs(5), server_handle).await??;
    assert!(session_result.is_ok());

    Ok(())
}

/// Test key exchange with Ed25519 signature verification.
#[tokio::test]
async fn test_kex_with_signature_verification() -> Result<(), Box<dyn std::error::Error>> {
    // Generate Ed25519 host key
    let host_key = Arc::new(Ed25519HostKey::generate()?);
    let host_key_fingerprint = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&host_key.public_key_bytes());
        format!("SHA256:{}", hex::encode(hasher.finalize()))
    };

    // Start server with the host key
    let mut server_config = fynx_proto::ssh::server::SshServerConfig::default();
    server_config.server_version = "TestServer_1.0".to_string();

    let server =
        SshServer::bind_with_config("127.0.0.1:0", server_config, host_key.clone()).await?;
    let server_addr = server.local_addr()?;

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        let session = server.accept().await;
        session
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client - this performs version exchange and KEX
    let client = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    // Verify client received and verified the host key
    assert!(client.server_host_key().is_some());

    // Verify the host key algorithm is Ed25519
    assert_eq!(
        client.server_host_key_algorithm(),
        Some(fynx_proto::ssh::hostkey::HostKeyAlgorithm::SshEd25519)
    );

    // Verify the fingerprint matches
    assert_eq!(
        client.server_host_key_fingerprint(),
        Some(host_key_fingerprint)
    );

    // Wait for server to complete
    let session_result = timeout(Duration::from_secs(5), server_handle).await??;
    assert!(session_result.is_ok());

    Ok(())
}

/// Test complete authentication flow.
#[tokio::test]
async fn test_authentication_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Generate host key
    let host_key = Arc::new(Ed25519HostKey::generate()?);

    // Start server with authentication
    let mut server = SshServer::bind_with_config(
        "127.0.0.1:0",
        fynx_proto::ssh::server::SshServerConfig::default(),
        host_key,
    )
    .await?;

    // Set up auth callback: accept "testuser" with password "testpass"
    server.set_auth_callback(Arc::new(|username, password| {
        username == "testuser" && password == "testpass"
    }));

    let server_addr = server.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut session = server.accept().await?;
        session.authenticate().await?;
        assert!(session.is_authenticated());
        assert_eq!(session.username(), Some("testuser"));
        Ok::<_, fynx_platform::FynxError>(())
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect and authenticate
    let mut client = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    // Authenticate with correct credentials
    timeout(
        Duration::from_secs(5),
        client.authenticate_password("testuser", "testpass"),
    )
    .await??;

    // Verify authentication succeeded
    assert!(client.is_authenticated());
    assert_eq!(client.username(), Some("testuser"));

    // Wait for server to complete
    let _ = timeout(Duration::from_secs(5), server_handle).await??;

    Ok(())
}

/// Test complete flow: connection, KEX, authentication, and command execution.
#[tokio::test]
async fn test_full_ssh_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Generate host key
    let host_key = Arc::new(Ed25519HostKey::generate()?);

    // Start server
    let mut server = SshServer::bind_with_config(
        "127.0.0.1:0",
        fynx_proto::ssh::server::SshServerConfig::default(),
        host_key,
    )
    .await?;

    server.set_auth_callback(Arc::new(|username, password| {
        username == "admin" && password == "secret"
    }));

    let server_addr = server.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut session = server.accept().await?;
        session.authenticate().await?;

        let mut handler = TestHandler;
        session.handle_session(&mut handler).await?;

        Ok::<_, fynx_platform::FynxError>(())
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client: connect, authenticate, execute command
    let mut client = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    timeout(
        Duration::from_secs(5),
        client.authenticate_password("admin", "secret"),
    )
    .await??;

    // Execute a command
    let output = timeout(Duration::from_secs(5), client.execute("whoami")).await??;

    // Verify output
    assert_eq!(String::from_utf8_lossy(&output), "Executed: whoami");

    // Wait for server to complete
    let _ = timeout(Duration::from_secs(5), server_handle).await;

    Ok(())
}

/// Test that authentication fails with wrong credentials.
#[tokio::test]
async fn test_authentication_failure() -> Result<(), Box<dyn std::error::Error>> {
    // Generate host key
    let host_key = Arc::new(Ed25519HostKey::generate()?);

    // Start server
    let mut server = SshServer::bind_with_config(
        "127.0.0.1:0",
        fynx_proto::ssh::server::SshServerConfig::default(),
        host_key,
    )
    .await?;

    server.set_auth_callback(Arc::new(|username, password| {
        username == "admin" && password == "correct"
    }));

    let server_addr = server.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut session = server.accept().await?;
        // This should fail
        let result = session.authenticate().await;
        assert!(result.is_err());
        Ok::<_, fynx_platform::FynxError>(())
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client
    let mut client = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    // Try to authenticate with wrong password
    let auth_result = timeout(
        Duration::from_secs(5),
        client.authenticate_password("admin", "wrong"),
    )
    .await?;

    // Should fail
    assert!(auth_result.is_err());
    assert!(!client.is_authenticated());

    // Wait for server
    let _ = timeout(Duration::from_secs(5), server_handle).await;

    Ok(())
}

/// Test exchange hash computation is consistent.
#[tokio::test]
async fn test_exchange_hash_consistency() -> Result<(), Box<dyn std::error::Error>> {
    // Generate two different host keys
    let host_key1 = Arc::new(Ed25519HostKey::generate()?);
    let host_key2 = Arc::new(Ed25519HostKey::generate()?);

    // Start server with first host key
    let server1 = SshServer::bind_with_config(
        "127.0.0.1:0",
        fynx_proto::ssh::server::SshServerConfig::default(),
        host_key1.clone(),
    )
    .await?;
    let server1_addr = server1.local_addr()?;

    let server1_handle = tokio::spawn(async move {
        let _session = server1.accept().await?;
        Ok::<_, fynx_platform::FynxError>(())
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect first client
    let client1 = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server1_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    let fingerprint1 = client1.server_host_key_fingerprint();

    // Wait for first server
    let _ = timeout(Duration::from_secs(5), server1_handle).await;

    // Start second server with different host key
    let server2 = SshServer::bind_with_config(
        "127.0.0.1:0",
        fynx_proto::ssh::server::SshServerConfig::default(),
        host_key2.clone(),
    )
    .await?;
    let server2_addr = server2.local_addr()?;

    let server2_handle = tokio::spawn(async move {
        let _session = server2.accept().await?;
        Ok::<_, fynx_platform::FynxError>(())
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect second client
    let client2 = timeout(
        Duration::from_secs(5),
        SshClient::connect_with_config(
            &format!("127.0.0.1:{}", server2_addr.port()),
            test_client_config(),
        ),
    )
    .await??;

    let fingerprint2 = client2.server_host_key_fingerprint();

    // Wait for second server
    let _ = timeout(Duration::from_secs(5), server2_handle).await;

    // Different host keys should produce different fingerprints
    assert_ne!(fingerprint1, fingerprint2);

    Ok(())
}
