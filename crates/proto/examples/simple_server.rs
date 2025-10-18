//! Simple SSH Server Example
//!
//! This example demonstrates how to:
//! - Create an SSH server with Ed25519 host key
//! - Accept client connections
//! - Authenticate users with password
//! - Handle command execution requests
//!
//! Usage:
//!   cargo run --example simple_server [bind_address]
//!
//! Example:
//!   cargo run --example simple_server 127.0.0.1:2222
//!
//! Then connect with a client:
//!   cargo run --example simple_client 127.0.0.1:2222 testuser testpass "whoami"

use fynx_platform::FynxResult;
use fynx_proto::ssh::hostkey::{Ed25519HostKey, HostKey};
use fynx_proto::ssh::server::{SessionHandler, SshServer, SshServerConfig};
use std::env;
use std::sync::Arc;

/// Simple command handler that echoes commands and provides basic responses
struct SimpleHandler {
    username: String,
}

#[async_trait::async_trait]
impl SessionHandler for SimpleHandler {
    async fn handle_exec(&mut self, command: &str) -> FynxResult<Vec<u8>> {
        println!("  Executing command: {}", command);

        // Handle common commands
        let output = match command.trim() {
            "whoami" => {
                format!("{}\n", self.username)
            }
            "pwd" => "/home/user\n".to_string(),
            "hostname" => "ssh-server-example\n".to_string(),
            "uname" | "uname -a" => "Fynx SSH Server Example v1.0\n".to_string(),
            cmd if cmd.starts_with("echo ") => {
                let text = &cmd[5..]; // Skip "echo "
                format!("{}\n", text)
            }
            _ => {
                // For unknown commands, echo what was requested
                format!("Command executed: {}\n", command)
            }
        };

        Ok(output.into_bytes())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse bind address from command line or use default
    let args: Vec<String> = env::args().collect();
    let bind_addr = if args.len() > 1 {
        args[1].clone()
    } else {
        "127.0.0.1:2222".to_string()
    };

    println!("=== Fynx SSH Server Example ===");
    println!();

    // Step 1: Generate Ed25519 host key
    // In production, you should load a persistent host key from disk
    // to maintain a consistent server identity across restarts
    println!("Generating Ed25519 host key...");
    let host_key = Arc::new(Ed25519HostKey::generate()?);

    // Display host key fingerprint for client verification
    let host_key_fingerprint = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&host_key.public_key_bytes());
        format!("SHA256:{}", hex::encode(hasher.finalize()))
    };

    println!("✓ Host key generated");
    println!("  Algorithm: ssh-ed25519");
    println!("  Fingerprint: {}", host_key_fingerprint);
    println!();

    // Step 2: Configure the SSH server
    let mut config = SshServerConfig::default();
    config.server_version = "SSH-2.0-FynxServer_Example_1.0".to_string();

    println!("Server configuration:");
    println!("  Version: {}", config.server_version);
    println!("  Supported KEX: curve25519-sha256");
    println!("  Supported host key: ssh-ed25519");
    println!("  Supported auth: password");
    println!();

    // Step 3: Create and bind the SSH server
    println!("Binding server to {}...", bind_addr);
    let mut server = SshServer::bind_with_config(&bind_addr, config, host_key).await?;

    // Step 4: Set up authentication callback
    // This example accepts two users:
    // - Username: "testuser", Password: "testpass"
    // - Username: "admin", Password: "secret"
    server.set_auth_callback(Arc::new(|username, password| {
        println!(
            "  Authentication attempt: username='{}', password='***'",
            username
        );
        let result = (username == "testuser" && password == "testpass")
            || (username == "admin" && password == "secret");
        if result {
            println!("  ✓ Authentication successful for '{}'", username);
        } else {
            println!("  ✗ Authentication failed for '{}'", username);
        }
        result
    }));

    let local_addr = server.local_addr()?;
    println!("✓ Server listening on {}", local_addr);
    println!();
    println!("Accepted credentials:");
    println!("  - testuser / testpass");
    println!("  - admin / secret");
    println!();
    println!("Waiting for connections... (Press Ctrl+C to stop)");
    println!("─────────────────────────────────────────────────────");
    println!();

    // Step 5: Accept and handle client connections
    loop {
        // Accept a new client connection
        match server.accept().await {
            Ok(mut session) => {
                let peer_addr = session.peer_address().to_string();
                println!("[{}] New connection", peer_addr);

                // Spawn a task to handle this session
                tokio::spawn(async move {
                    // Perform authentication
                    println!("[{}] Waiting for authentication...", peer_addr);
                    match session.authenticate().await {
                        Ok(_) => {
                            let username = session.username().unwrap_or("unknown").to_string();
                            println!("[{}] ✓ Authenticated as '{}'", peer_addr, username);

                            // Create session handler
                            let mut handler = SimpleHandler {
                                username: username.clone(),
                            };

                            // Handle session commands
                            println!("[{}] Session started for '{}'", peer_addr, username);
                            match session.handle_session(&mut handler).await {
                                Ok(_) => {
                                    println!("[{}] Session completed successfully", peer_addr);
                                }
                                Err(e) => {
                                    println!("[{}] Session error: {}", peer_addr, e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("[{}] ✗ Authentication failed: {}", peer_addr, e);
                        }
                    }

                    println!("[{}] Connection closed", peer_addr);
                    println!();
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}
