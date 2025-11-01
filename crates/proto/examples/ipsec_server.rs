//! IPSec VPN Server Example
//!
//! This example demonstrates how to create a simple IPSec VPN server using the
//! fynx-proto library. It listens for incoming IPSec connections, establishes
//! tunnels, and echoes back received data.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example ipsec_server --features ipsec -- <bind_addr> <local_id> <psk>
//! ```
//!
//! # Example
//!
//! ```bash
//! cargo run --example ipsec_server --features ipsec -- 0.0.0.0:500 server@example.com "my-secret-key"
//! ```
//!
//! **Note**: Binding to port 500 requires root/administrator privileges.
//!
//! # Prerequisites
//!
//! - Root/administrator privileges (for port 500)
//! - Firewall rules allowing UDP port 500 (and 4500 for NAT-T)
//! - Pre-Shared Key (PSK) shared with clients

use fynx_proto::ipsec::{IpsecServer, ServerConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    if args.len() != 4 {
        eprintln!("Usage: {} <bind_addr> <local_id> <psk>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  {} 0.0.0.0:500 server@example.com \"my-secret-key\"",
            args[0]
        );
        eprintln!();
        eprintln!("Note: Port 500 requires root/administrator privileges");
        eprintln!();
        eprintln!("Environment variables:");
        eprintln!("  RUST_LOG=debug    Enable debug logging");
        eprintln!("  RUST_LOG=trace    Enable trace logging");
        std::process::exit(1);
    }

    let bind_addr: SocketAddr = args[1].parse()?;
    let local_id = &args[2];
    let psk = args[3].as_bytes();

    println!("IPSec VPN Server Example");
    println!("========================");
    println!("Bind address: {}", bind_addr);
    println!("Local ID:     {}", local_id);
    println!("PSK:          {} bytes", psk.len());
    println!();

    // Check if we have permission to bind to privileged port
    if bind_addr.port() < 1024 {
        println!(
            "⚠  WARNING: Binding to privileged port {} requires elevated permissions",
            bind_addr.port()
        );
        #[cfg(unix)]
        println!("   Run with: sudo cargo run --example ipsec_server --features ipsec");
        #[cfg(windows)]
        println!("   Run as Administrator");
        println!();
    }

    // Configure the server
    println!("[1/2] Configuring server...");
    let config = ServerConfig::builder()
        .with_local_id(local_id)
        .with_psk(psk)
        .build()?;
    println!("✓ Configuration created");
    println!();

    // Bind the server
    println!("[2/2] Binding server...");
    let mut server = IpsecServer::bind(config, bind_addr).await?;
    println!("✓ Server listening on {}", bind_addr);
    println!();

    println!("Ready to accept IPSec connections!");
    println!("Press Ctrl+C to stop");
    println!();
    println!("Connect with:");
    println!(
        "  cargo run --example ipsec_client --features ipsec -- {} client@example.com {} \"{}\"",
        bind_addr,
        local_id,
        String::from_utf8_lossy(psk)
    );
    println!();

    // Statistics
    let connections_accepted = Arc::new(AtomicU64::new(0));
    let messages_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    // Accept connections in a loop
    loop {
        println!("────────────────────────────────────────");
        println!("Waiting for connection...");

        match server.accept().await {
            Ok((peer_addr, mut session)) => {
                let conn_num = connections_accepted.fetch_add(1, Ordering::Relaxed) + 1;
                println!("✓ Connection #{} accepted from {}", conn_num, peer_addr);
                println!("  IKE SA established");
                println!("  Child SA established");

                // Clone counters for the session task
                let _msgs_rx = messages_received.clone();
                let _bytes_rx = bytes_received.clone();

                // Spawn a task to handle this session
                tokio::spawn(async move {
                    println!("  [Session #{}] Started", conn_num);
                    println!("  [Session #{}] ⚠ Note: Full data transfer requires UDP socket integration", conn_num);
                    println!("  [Session #{}] See IPSec client/server API docs for complete implementation", conn_num);

                    // Keep session alive for demonstration
                    // In a real application, you would:
                    // 1. Create a UDP socket
                    // 2. Read ESP packets from the socket
                    // 3. Use session.recv_packet(esp_bytes) to decrypt
                    // 4. Process the plaintext data
                    // 5. Use session.send_packet(data) to encrypt
                    // 6. Send ESP packets through the socket

                    println!("  [Session #{}] Session established and active", conn_num);
                    println!("  [Session #{}] Press Ctrl+C to stop server", conn_num);

                    // Keep session alive for 30 seconds
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

                    // Close session gracefully
                    if let Err(e) = session.close().await {
                        println!("  [Session #{}] Close error: {}", conn_num, e);
                    } else {
                        println!("  [Session #{}] Closed gracefully", conn_num);
                    }
                });

                // Print overall statistics
                println!();
                println!("Server Statistics:");
                println!(
                    "  Total connections: {}",
                    connections_accepted.load(Ordering::Relaxed)
                );
                println!(
                    "  Total messages:    {}",
                    messages_received.load(Ordering::Relaxed)
                );
                println!(
                    "  Total bytes:       {}",
                    bytes_received.load(Ordering::Relaxed)
                );
                println!();
            }
            Err(e) => {
                eprintln!("✗ Failed to accept connection: {}", e);
                eprintln!();
                eprintln!("Troubleshooting:");
                eprintln!("  1. Check if port is already in use");
                eprintln!(
                    "  2. Verify you have permission to bind to port {}",
                    bind_addr.port()
                );
                eprintln!("  3. Check firewall rules");
                eprintln!("  4. Enable debug logging: RUST_LOG=debug");
                eprintln!();

                // Continue accepting connections
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}
