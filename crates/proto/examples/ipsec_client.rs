//! IPSec VPN Client Example
//!
//! This example demonstrates how to create a simple IPSec VPN client using the
//! fynx-proto library. It establishes an IPSec tunnel to a server, sends encrypted
//! data, and receives responses.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example ipsec_client --features ipsec -- <server_addr> <local_id> <remote_id> <psk>
//! ```
//!
//! # Example
//!
//! ```bash
//! cargo run --example ipsec_client --features ipsec -- 10.0.0.1:500 client@example.com server@example.com "my-secret-key"
//! ```
//!
//! # Prerequisites
//!
//! - A running IPSec server (use the `ipsec_server` example or strongSwan)
//! - Matching Pre-Shared Key (PSK) on both sides
//! - Firewall rules allowing UDP port 500 (and 4500 for NAT-T)

use fynx_proto::ipsec::{ClientConfig, IpsecClient};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <server_addr> <local_id> <remote_id> <psk>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} 10.0.0.1:500 client@example.com server@example.com \"my-secret-key\"", args[0]);
        eprintln!();
        eprintln!("Environment variables:");
        eprintln!("  RUST_LOG=debug    Enable debug logging");
        eprintln!("  RUST_LOG=trace    Enable trace logging");
        std::process::exit(1);
    }

    let server_addr: SocketAddr = args[1].parse()?;
    let local_id = &args[2];
    let remote_id = &args[3];
    let psk = args[4].as_bytes();

    println!("IPSec VPN Client Example");
    println!("========================");
    println!("Server:    {}", server_addr);
    println!("Local ID:  {}", local_id);
    println!("Remote ID: {}", remote_id);
    println!("PSK:       {} bytes", psk.len());
    println!();

    // Step 1: Configure the client
    println!("[1/5] Configuring client...");
    let config = ClientConfig::builder()
        .with_local_id(local_id)
        .with_remote_id(remote_id)
        .with_psk(psk)
        .build()?;

    println!("✓ Configuration created");
    println!();

    // Step 2: Create client instance
    println!("[2/5] Creating client instance...");
    let mut client = IpsecClient::new(config);
    println!("✓ Client created");
    println!();

    // Step 3: Connect to the server (performs IKE_SA_INIT and IKE_AUTH)
    println!("[3/5] Connecting to server...");
    println!("  → Performing IKE_SA_INIT handshake...");
    println!("  → Performing IKE_AUTH authentication...");

    match timeout(Duration::from_secs(30), client.connect(server_addr)).await {
        Ok(Ok(())) => {
            println!("✓ Connected successfully!");
            println!("  IKE SA established");
            println!("  Child SA established");
            println!();
        }
        Ok(Err(e)) => {
            eprintln!("✗ Connection failed: {}", e);
            eprintln!();
            eprintln!("Troubleshooting:");
            eprintln!("  1. Check if server is running");
            eprintln!("  2. Verify PSK matches on both sides");
            eprintln!("  3. Check firewall rules (UDP 500)");
            eprintln!("  4. Enable debug logging: RUST_LOG=debug");
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("✗ Connection timeout after 30 seconds");
            eprintln!();
            eprintln!("Troubleshooting:");
            eprintln!("  1. Check network connectivity");
            eprintln!("  2. Verify server address is correct");
            eprintln!("  3. Check if server is listening on {}", server_addr);
            return Err("Connection timeout".into());
        }
    }

    // Step 4: Send encrypted data through the tunnel
    println!("[4/5] Sending encrypted data...");
    let test_messages = vec![
        b"Hello from IPSec client!".to_vec(),
        b"This is a test message.".to_vec(),
        b"IPSec tunnel is working!".to_vec(),
    ];

    for (i, message) in test_messages.iter().enumerate() {
        println!("  Sending message {}/{}...", i + 1, test_messages.len());

        match client.send_packet(message).await {
            Ok(()) => {
                println!("  ✓ Message {} sent ({} bytes)", i + 1, message.len());
            }
            Err(e) => {
                eprintln!("  ✗ Failed to send message {}: {}", i + 1, e);
                continue;
            }
        }

        // Try to receive response (with timeout)
        match timeout(Duration::from_secs(5), client.recv_packet()).await {
            Ok(Ok(response)) => {
                println!(
                    "  ✓ Received response: {} bytes",
                    response.len()
                );
                if let Ok(text) = String::from_utf8(response) {
                    println!("    Content: \"{}\"", text);
                }
            }
            Ok(Err(e)) => {
                println!("  ⚠ No response received: {}", e);
            }
            Err(_) => {
                println!("  ⚠ Response timeout (may be expected)");
            }
        }
    }
    println!();

    // Step 5: Graceful shutdown
    println!("[5/5] Shutting down...");
    match timeout(Duration::from_secs(10), client.shutdown()).await {
        Ok(Ok(())) => {
            println!("✓ Graceful shutdown complete");
            println!("  Sent DELETE notification to server");
        }
        Ok(Err(e)) => {
            println!("⚠ Shutdown error (not critical): {}", e);
        }
        Err(_) => {
            println!("⚠ Shutdown timeout (not critical)");
        }
    }
    println!();

    println!("IPSec VPN session complete!");
    println!();
    println!("Summary:");
    println!("  - IKE SA established: ✓");
    println!("  - Child SA established: ✓");
    println!("  - Messages sent: {}", test_messages.len());
    println!("  - Tunnel closed: ✓");

    Ok(())
}
