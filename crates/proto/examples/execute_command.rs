//! Non-Interactive Command Execution Example
//!
//! This example demonstrates how to execute commands on a remote SSH server
//! in a non-interactive manner, similar to `ssh user@host command`.
//!
//! Key features:
//! - Connection pooling for multiple commands
//! - Error handling and retry logic
//! - Timeout handling
//! - Output parsing and display
//!
//! Usage:
//!   cargo run --example execute_command <host:port> <username> <password> <command1> [command2] [...]
//!
//! Example:
//!   cargo run --example execute_command 127.0.0.1:2222 admin secret "whoami" "pwd" "hostname"

use fynx_proto::ssh::client::SshClient;
use std::env;
use std::time::Duration;
use tokio::time::timeout;

/// Execute a single command and display the result
async fn execute_command(
    client: &mut SshClient,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("$ {}", command);

    // Execute with timeout to prevent hanging
    let result = timeout(Duration::from_secs(10), client.execute(command)).await;

    match result {
        Ok(Ok(output)) => {
            // Command executed successfully
            let output_str = String::from_utf8_lossy(&output);
            print!("{}", output_str);
            if !output_str.ends_with('\n') {
                println!();
            }
            Ok(())
        }
        Ok(Err(e)) => {
            // Command failed
            eprintln!("Error executing command: {}", e);
            Err(e.into())
        }
        Err(_) => {
            // Timeout
            eprintln!("Command timed out after 10 seconds");
            Err("Command timeout".into())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "Usage: {} <host:port> <username> <password> <command1> [command2] [...]",
            args[0]
        );
        eprintln!(
            "Example: {} 127.0.0.1:2222 admin secret \"whoami\" \"pwd\" \"hostname\"",
            args[0]
        );
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let username = &args[2];
    let password = &args[3];
    let commands: Vec<&String> = args.iter().skip(4).collect();

    println!("=== SSH Command Execution ===");
    println!("Server: {}", server_addr);
    println!("User: {}", username);
    println!("Commands to execute: {}", commands.len());
    println!();

    // Step 1: Establish connection with timeout
    println!("Connecting to {}...", server_addr);
    let client_result = timeout(Duration::from_secs(10), SshClient::connect(server_addr)).await;

    let mut client = match client_result {
        Ok(Ok(client)) => {
            println!("✓ Connected");
            client
        }
        Ok(Err(e)) => {
            eprintln!("✗ Connection failed: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("✗ Connection timed out");
            return Err("Connection timeout".into());
        }
    };

    // Display connection information
    if let Some(fingerprint) = client.server_host_key_fingerprint() {
        println!("  Host key: {}", fingerprint);
    }
    println!();

    // Step 2: Authenticate with timeout
    println!("Authenticating as '{}'...", username);
    let auth_result = timeout(
        Duration::from_secs(10),
        client.authenticate_password(username, password),
    )
    .await;

    match auth_result {
        Ok(Ok(_)) => {
            println!("✓ Authenticated");
        }
        Ok(Err(e)) => {
            eprintln!("✗ Authentication failed: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("✗ Authentication timed out");
            return Err("Authentication timeout".into());
        }
    }
    println!();

    // Step 3: Execute all commands
    println!("Executing {} command(s)...", commands.len());
    println!("─────────────────────────────────────────");
    println!();

    let mut success_count = 0;
    let mut failure_count = 0;

    for (index, command) in commands.iter().enumerate() {
        if index > 0 {
            println!();
        }

        match execute_command(&mut client, command).await {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }

    // Step 4: Display summary
    println!();
    println!("─────────────────────────────────────────");
    println!("Execution Summary:");
    println!("  Total commands: {}", commands.len());
    println!("  Successful: {}", success_count);
    println!("  Failed: {}", failure_count);

    // Step 5: Disconnect
    println!();
    println!("Disconnecting...");
    drop(client);
    println!("✓ Disconnected");

    // Exit with error code if any commands failed
    if failure_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}
