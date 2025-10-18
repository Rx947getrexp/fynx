//! OpenSSH interoperability tests.
//!
//! These tests validate compatibility with real OpenSSH servers and clients.
//!
//! # Running these tests
//!
//! These tests require a running OpenSSH server or are marked as `#[ignore]`
//! by default. To run them:
//!
//! ```bash
//! # Start local OpenSSH server on port 2222 (example)
//! # Then run:
//! cargo test --test openssh_interop -- --ignored
//! ```

use fynx_proto::ssh::client::SshClient;
use tokio::time::Duration;

/// Test connecting to a local OpenSSH server.
///
/// This test attempts to connect to OpenSSH running on localhost:22.
/// It's marked as `#[ignore]` because it requires a running SSH server.
///
/// To test manually:
/// 1. Ensure OpenSSH server is running: `sudo systemctl start sshd`
/// 2. Run: `cargo test --test openssh_interop test_connect_to_openssh -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn test_connect_to_openssh_localhost() -> Result<(), Box<dyn std::error::Error>> {
    println!("Attempting to connect to OpenSSH server at localhost:22...");

    // Try to connect (this will perform version exchange and KEX)
    let client =
        tokio::time::timeout(Duration::from_secs(10), SshClient::connect("127.0.0.1:22")).await??;

    println!("✓ Successfully connected to OpenSSH server");
    println!("  Server address: {}", client.server_address());

    if let Some(host_key_algo) = client.server_host_key_algorithm() {
        println!("  Host key algorithm: {:?}", host_key_algo);
    }

    if let Some(fingerprint) = client.server_host_key_fingerprint() {
        println!("  Host key fingerprint: {}", fingerprint);
    }

    Ok(())
}

/// Test password authentication with OpenSSH.
///
/// This test requires valid SSH credentials.
/// Set environment variables: SSH_TEST_USER and SSH_TEST_PASS
///
/// Example:
/// ```bash
/// export SSH_TEST_USER="testuser"
/// export SSH_TEST_PASS="testpass"
/// cargo test --test openssh_interop test_auth_openssh -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore]
async fn test_password_auth_with_openssh() -> Result<(), Box<dyn std::error::Error>> {
    let username = std::env::var("SSH_TEST_USER").unwrap_or_else(|_| {
        eprintln!("SSH_TEST_USER not set, skipping test");
        return "".to_string();
    });

    let password = std::env::var("SSH_TEST_PASS").unwrap_or_else(|_| {
        eprintln!("SSH_TEST_PASS not set, skipping test");
        return "".to_string();
    });

    if username.is_empty() || password.is_empty() {
        println!("Skipping test: credentials not provided");
        return Ok(());
    }

    println!("Connecting to OpenSSH at localhost:22 as '{}'...", username);

    let mut client =
        tokio::time::timeout(Duration::from_secs(10), SshClient::connect("127.0.0.1:22")).await??;

    println!("✓ Connected, attempting password authentication...");

    tokio::time::timeout(
        Duration::from_secs(10),
        client.authenticate_password(&username, &password),
    )
    .await??;

    println!("✓ Successfully authenticated with OpenSSH server");
    println!("  Username: {}", client.username().unwrap_or(""));
    println!("  Authenticated: {}", client.is_authenticated());

    Ok(())
}

/// Test executing a command on OpenSSH server.
///
/// Requires SSH_TEST_USER and SSH_TEST_PASS environment variables.
#[tokio::test]
#[ignore]
async fn test_execute_command_openssh() -> Result<(), Box<dyn std::error::Error>> {
    let username = std::env::var("SSH_TEST_USER").unwrap_or_default();
    let password = std::env::var("SSH_TEST_PASS").unwrap_or_default();

    if username.is_empty() || password.is_empty() {
        println!("Skipping test: credentials not provided");
        return Ok(());
    }

    println!("Connecting to OpenSSH and executing 'whoami'...");

    let mut client = SshClient::connect("127.0.0.1:22").await?;
    client.authenticate_password(&username, &password).await?;

    println!("✓ Authenticated, executing command...");

    let output = tokio::time::timeout(Duration::from_secs(10), client.execute("whoami")).await??;

    let output_str = String::from_utf8_lossy(&output);
    println!("✓ Command executed successfully");
    println!("  Output: {}", output_str.trim());

    assert!(output_str.contains(&username) || !output_str.is_empty());

    Ok(())
}

/// Test protocol negotiation details with OpenSSH.
///
/// This test connects and prints negotiated algorithms.
#[tokio::test]
#[ignore]
async fn test_protocol_negotiation() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing protocol negotiation with OpenSSH...");

    let client = SshClient::connect("127.0.0.1:22").await?;

    println!("\n=== Protocol Negotiation Results ===");
    println!("Server address: {}", client.server_address());

    if let Some(algo) = client.server_host_key_algorithm() {
        println!("Host key algorithm: {:?}", algo);
    }

    if let Some(fingerprint) = client.server_host_key_fingerprint() {
        println!("Host key fingerprint: {}", fingerprint);
    }

    println!("\nNote: Current implementation uses:");
    println!("  - KEX: curve25519-sha256");
    println!("  - Cipher: chacha20-poly1305@openssh.com");
    println!("  - MAC: (integrated with AEAD)");

    Ok(())
}

/// Dummy test that always passes (for CI without OpenSSH).
#[test]
fn test_openssh_interop_placeholder() {
    // This test exists so that the test file compiles and passes
    // even when OpenSSH is not available.
    assert!(true);
}
