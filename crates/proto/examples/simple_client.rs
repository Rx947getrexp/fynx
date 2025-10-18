//! Simple SSH Client Example
//!
//! This example demonstrates how to:
//! - Connect to an SSH server
//! - Authenticate with username/password
//! - Execute a remote command
//! - Handle the response
//!
//! Usage:
//!   cargo run --example simple_client <host:port> <username> <password> <command>
//!
//! Example:
//!   cargo run --example simple_client 127.0.0.1:22 admin secret "whoami"

use fynx_proto::ssh::client::SshClient;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "Usage: {} <host:port> <username> <password> <command>",
            args[0]
        );
        eprintln!("Example: {} 127.0.0.1:22 admin secret \"whoami\"", args[0]);
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let username = &args[2];
    let password = &args[3];
    let command = &args[4];

    println!("Connecting to SSH server at {}...", server_addr);

    // Step 1: Connect to the SSH server
    // This performs:
    // - TCP connection establishment
    // - SSH version exchange
    // - Key exchange (KEX) with Curve25519
    // - Host key verification with Ed25519 signatures
    let mut client = SshClient::connect(server_addr).await?;

    println!("✓ Connected successfully");
    println!("  Server address: {}", client.server_address());

    // Display host key information for security verification
    if let Some(fingerprint) = client.server_host_key_fingerprint() {
        println!("  Host key fingerprint: {}", fingerprint);
    }
    if let Some(algorithm) = client.server_host_key_algorithm() {
        println!("  Host key algorithm: {:?}", algorithm);
    }

    println!();
    println!("Authenticating as user '{}'...", username);

    // Step 2: Authenticate with username and password
    // This performs the SSH userauth protocol flow:
    // - Sends SSH_MSG_USERAUTH_REQUEST with password method
    // - Waits for SSH_MSG_USERAUTH_SUCCESS or SSH_MSG_USERAUTH_FAILURE
    client.authenticate_password(username, password).await?;

    println!("✓ Authentication successful");
    println!(
        "  Authenticated user: {}",
        client.username().unwrap_or("unknown")
    );

    println!();
    println!("Executing command: {}", command);

    // Step 3: Execute the remote command
    // This performs:
    // - Opens a new SSH channel
    // - Sends SSH_MSG_CHANNEL_REQUEST with "exec" request
    // - Collects command output
    // - Closes the channel
    let output = client.execute(command).await?;

    println!("✓ Command executed successfully");
    println!();
    println!("--- Output ---");
    println!("{}", String::from_utf8_lossy(&output));
    println!("--- End of Output ---");

    // Step 4: Disconnect gracefully
    // The client automatically sends SSH_MSG_DISCONNECT when dropped
    println!();
    println!("Disconnecting...");
    drop(client);
    println!("✓ Disconnected");

    Ok(())
}
