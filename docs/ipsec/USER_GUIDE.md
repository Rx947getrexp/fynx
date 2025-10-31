# Fynx IPSec User Guide

**Version**: 0.1.0-alpha.1
**Last Updated**: 2025-10-31

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Advanced Usage](#advanced-usage)
6. [Monitoring & Observability](#monitoring--observability)
7. [Common Pitfalls](#common-pitfalls)
8. [Troubleshooting](#troubleshooting)
9. [Security Considerations](#security-considerations)
10. [API Reference](#api-reference)

---

## Introduction

Fynx IPSec is a pure-Rust implementation of the IPSec protocol suite (IKEv2 + ESP) designed for secure VPN tunnels and encrypted communication.

### What is IPSec?

IPSec (Internet Protocol Security) provides:
- **Confidentiality**: Encryption of IP packets using AES-GCM or ChaCha20-Poly1305
- **Authentication**: Verification of packet origin using PSK (Pre-Shared Key)
- **Integrity**: Detection of packet tampering
- **Anti-replay Protection**: Prevention of replay attacks

### Use Cases

- **VPN Tunnels**: Secure site-to-site or client-to-gateway connections
- **Encrypted Communication**: Protection of sensitive data in transit
- **Network Security**: Layer 3 security for IP networks
- **IoT Security**: Lightweight VPN for embedded devices

### Features

✅ **IKEv2 Protocol** (RFC 7296)
✅ **ESP Protocol** (RFC 4303)
✅ **PSK Authentication**
✅ **NAT Traversal** (NAT-T)
✅ **Dead Peer Detection** (DPD)
✅ **Automatic SA Rekeying**
✅ **Anti-Replay Protection**
✅ **Production Hardening** (Logging, Metrics, Error Handling)

---

## Installation

### Add Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
fynx-proto = { version = "0.1.0-alpha.1", features = ["ipsec"] }
tokio = { version = "1.35", features = ["full"] }
```

### Feature Flags

- `ipsec`: Enables IPSec implementation (required)

### Platform Support

- ✅ **Linux**: Full support
- ✅ **macOS**: Full support
- ✅ **Windows**: Full support

---

## Quick Start

### Client Example

```rust
use fynx_proto::ipsec::{IpsecClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure client
    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"my-secret-key-at-least-32-bytes-long")
        .build()?;

    // 2. Create and connect
    let mut client = IpsecClient::new(config);
    client.connect("10.0.0.1:500".parse()?).await?;
    println!("Connected to IPSec server!");

    // 3. Send encrypted data
    client.send_packet(b"Hello, secure world!").await?;

    // 4. Receive encrypted data
    let response = client.recv_packet().await?;
    println!("Received: {:?}", String::from_utf8_lossy(&response));

    // 5. Graceful shutdown
    client.shutdown().await?;

    Ok(())
}
```

### Server Example

```rust
use fynx_proto::ipsec::{IpsecServer, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure server
    let config = ServerConfig::builder()
        .with_local_id("server@example.com")
        .with_psk(b"my-secret-key-at-least-32-bytes-long")
        .build()?;

    // 2. Bind to address
    let mut server = IpsecServer::bind(config, "0.0.0.0:500".parse()?).await?;
    println!("IPSec server listening on 0.0.0.0:500");

    // 3. Accept connections
    loop {
        match server.accept().await {
            Ok((peer_addr, session)) => {
                println!("Client connected: {}", peer_addr);

                // Handle in separate task
                tokio::spawn(async move {
                    handle_session(session).await;
                });
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_session(mut session: IpsecSession) {
    // Echo server logic
    loop {
        match session.recv_packet().await {
            Ok(data) => {
                println!("Received {} bytes", data.len());
                if let Err(e) = session.send_packet(&data).await {
                    eprintln!("Send error: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
                break;
            }
        }
    }

    let _ = session.close().await;
}
```

---

## Configuration

### Client Configuration

```rust
use fynx_proto::ipsec::{ClientConfig, child_sa::SaLifetime, dpd::DpdConfig};
use std::time::Duration;

let config = ClientConfig::builder()
    // Required: Identity configuration
    .with_local_id("client@example.com")
    .with_remote_id("server@example.com")
    .with_psk(b"your-secret-key")

    // Optional: Cipher suite selection
    .with_ike_proposals(vec![
        // Use AES-256-GCM for IKE
        Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm256))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14))
    ])

    // Optional: Dead Peer Detection
    .with_dpd(DpdConfig {
        enabled: true,
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(10),
        max_retries: 3,
    })

    // Optional: SA Lifetime
    .with_lifetime(SaLifetime {
        soft_time: Duration::from_secs(3600),  // Rekey after 1 hour
        hard_time: Duration::from_secs(3900),  // Force delete after 65 min
        soft_bytes: Some(100_000_000),          // Rekey after 100 MB
        hard_bytes: Some(110_000_000),          // Delete after 110 MB
    })

    .build()?;
```

### Server Configuration

```rust
let config = ServerConfig::builder()
    .with_local_id("server@example.com")
    .with_psk(b"your-secret-key")
    .with_ike_proposals(/* ... */)
    .with_esp_proposals(/* ... */)
    .with_dpd(dpd_config)
    .with_lifetime(lifetime)
    .build()?;
```

### Cipher Suites

#### IKE Proposals (Control Plane)

```rust
use fynx_proto::ipsec::ikev2::proposal::*;

// AES-128-GCM with Curve25519 (Recommended)
let ike_proposal = Proposal::new(1, ProtocolId::Ike)
    .add_transform(Transform::encr(EncrTransformId::AesGcm128))
    .add_transform(Transform::prf(PrfTransformId::HmacSha256))
    .add_transform(Transform::dh(DhTransformId::Curve25519));

// AES-256-GCM with DH Group 14 (Conservative)
let ike_proposal = Proposal::new(1, ProtocolId::Ike)
    .add_transform(Transform::encr(EncrTransformId::AesGcm256))
    .add_transform(Transform::prf(PrfTransformId::HmacSha384))
    .add_transform(Transform::dh(DhTransformId::Group14));
```

#### ESP Proposals (Data Plane)

```rust
// AES-128-GCM (Fastest)
let esp_proposal = Proposal::new(1, ProtocolId::Esp)
    .add_transform(Transform::encr(EncrTransformId::AesGcm128))
    .add_transform(Transform::new(TransformType::Esn, 0));

// ChaCha20-Poly1305 (Software-optimized)
let esp_proposal = Proposal::new(1, ProtocolId::Esp)
    .add_transform(Transform::encr(EncrTransformId::ChaCha20Poly1305))
    .add_transform(Transform::new(TransformType::Esn, 0));
```

---

## Advanced Usage

### Background Tasks

The client automatically runs background tasks for:
- **Dead Peer Detection**: Check peer liveness
- **SA Rekeying**: Renew Security Associations before expiration

#### Manual DPD Check

```rust
if client.should_perform_dpd() {
    match client.perform_dpd_check().await {
        Ok(()) => println!("Peer is alive"),
        Err(e) => eprintln!("DPD failed: {}", e),
    }
}
```

#### Manual Rekey

```rust
let sas_to_rekey = client.check_rekey_needed();
for spi in sas_to_rekey {
    client.rekey_child_sa(spi).await?;
}
```

### Multiple Concurrent Connections (Server)

```rust
use tokio::sync::Mutex;
use std::sync::Arc;

let server = Arc::new(Mutex::new(server));

loop {
    let server_clone = Arc::clone(&server);

    tokio::spawn(async move {
        let mut server = server_clone.lock().await;
        if let Ok((addr, session)) = server.accept().await {
            tokio::spawn(handle_session(session));
        }
    });
}
```

---

## Monitoring & Observability

### Structured Logging

Enable debug logging:

```rust
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_env_filter("fynx_proto::ipsec=debug")
    .init();
```

### Metrics Collection

```rust
use fynx_proto::ipsec::metrics::IpsecMetrics;

let metrics = IpsecMetrics::new();

// Metrics are updated automatically during operations
// Get snapshot for monitoring
let snapshot = metrics.snapshot();

println!("IKE Handshakes: {}", snapshot.ike_handshakes_total);
println!("Success Rate: {:.2}%", snapshot.handshake_success_rate() * 100.0);
println!("ESP Packets Encrypted: {}", snapshot.esp_packets_encrypted);
println!("ESP Bytes Encrypted: {}", snapshot.esp_bytes_encrypted);
println!("Active Child SAs: {}", snapshot.child_sa_active);
```

### Error Handling

```rust
use fynx_proto::ipsec::error::{Error, ErrorCode};

match client.connect(addr).await {
    Ok(()) => println!("Connected"),
    Err(e) => {
        // Get error code for programmatic handling
        if let Some(code) = e.code() {
            eprintln!("Error code: {} ({})", code.as_u32(), code.category());
        }

        // Check if retryable
        if e.is_retryable() {
            eprintln!("Retrying connection...");
        }

        // Add context
        let e_with_context = e.with_context("initial connection");
        eprintln!("Error: {}", e_with_context);
    }
}
```

---

## Common Pitfalls

### 1. **Port 500 Requires Root/Administrator**

**Problem**: Binding to UDP port 500 requires elevated privileges.

**Solution**:
- **Linux**: Use `sudo` or `setcap`
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' /path/to/binary
  ```
- **Windows**: Run as Administrator
- **Alternative**: Use non-standard port (e.g., 4500) for testing

### 2. **Firewall Blocking UDP 500/4500**

**Problem**: Firewall blocks IKE (500) or NAT-T (4500) ports.

**Solution**:
- **Linux**:
  ```bash
  sudo ufw allow 500/udp
  sudo ufw allow 4500/udp
  ```
- **Windows**: Add firewall rules via Windows Defender

### 3. **PSK Mismatch**

**Problem**: Client and server use different pre-shared keys.

**Solution**: Ensure both sides use identical PSK (case-sensitive).

### 4. **Proposal Negotiation Failure**

**Problem**: No common cipher suite between client and server.

**Solution**: Ensure at least one matching proposal in both client and server configs.

### 5. **NAT Traversal Issues**

**Problem**: Connection fails behind NAT router.

**Solution**: NAT-T is automatic. Ensure UDP 4500 is not blocked.

---

## Troubleshooting

### Enable Debug Logging

```rust
tracing_subscriber::fmt()
    .with_env_filter("fynx_proto::ipsec=trace")
    .with_line_number(true)
    .init();
```

### Check Metrics

```rust
let metrics = client.metrics();
let snapshot = metrics.snapshot();

println!("Handshake failures: {}", snapshot.ike_handshake_failures);
println!("Authentication failures: {}", snapshot.authentication_failed);
println!("Proposal negotiation failures: {}", snapshot.proposal_negotiation_failed);
println!("Replay attacks detected: {}", snapshot.esp_replay_detected);
```

### Common Error Messages

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `NO_PROPOSAL_CHOSEN` | No matching cipher suite | Add common proposal to both sides |
| `AUTHENTICATION_FAILED` | PSK mismatch | Verify PSK is identical on both sides |
| `Network I/O error: timeout` | Peer not responding | Check network connectivity, firewall rules |
| `Replay attack detected` | Duplicate packet received | Normal - packet is rejected automatically |
| `Invalid state transition` | Protocol violation | Check for corrupted packets or implementation bugs |

### Packet Capture

For deep debugging, capture IKE packets:

```bash
# Linux/macOS
sudo tcpdump -i any -w ipsec.pcap udp port 500 or udp port 4500

# Analyze with Wireshark
wireshark ipsec.pcap
```

---

## Security Considerations

### 1. **Pre-Shared Key (PSK) Strength**

- **Minimum length**: 32 bytes (256 bits)
- **Use cryptographically random keys**:
  ```rust
  use rand::RngCore;
  let mut psk = [0u8; 32];
  rand::thread_rng().fill_bytes(&mut psk);
  ```

### 2. **Cipher Suite Selection**

**Recommended** (as of 2025):
- **IKE**: AES-256-GCM + HMAC-SHA384 + Curve25519
- **ESP**: AES-256-GCM

**Avoid**:
- DES, 3DES (deprecated)
- MD5 (broken)
- SHA1 (weak)

### 3. **SA Lifetime**

Set reasonable lifetimes:
- **Soft time**: 3600 seconds (1 hour)
- **Hard time**: 3900 seconds (5% longer than soft)
- **Soft bytes**: 100 MB - 1 GB
- **Hard bytes**: 10% more than soft

### 4. **Dead Peer Detection (DPD)**

Enable DPD to detect failed peers:
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Max retries**: 3

### 5. **Replay Protection**

Anti-replay is enabled by default. Do not disable!

### 6. **Logging Sensitive Data**

Avoid logging:
- Pre-shared keys
- Encryption keys
- Packet payloads

Use structured logging with appropriate log levels.

---

## API Reference

### Core Types

- **`IpsecClient`**: Client for initiating IPSec tunnels
- **`IpsecServer`**: Server for accepting IPSec connections
- **`IpsecSession`**: Represents a client session on the server
- **`ClientConfig`** / **`ServerConfig`**: Configuration builders
- **`IpsecMetrics`**: Metrics collection
- **`Error`** / **`Result`**: Error handling

### Client Methods

- `new(config)`: Create client
- `connect(addr)`: Connect to server
- `send_packet(data)`: Send encrypted data
- `recv_packet()`: Receive encrypted data
- `shutdown()`: Graceful shutdown
- `should_perform_dpd()`: Check if DPD needed
- `perform_dpd_check()`: Perform DPD check
- `check_rekey_needed()`: Get SAs needing rekey
- `rekey_child_sa(spi)`: Rekey specific SA

### Server Methods

- `bind(config, addr)`: Bind server
- `accept()`: Accept client connection
- `shutdown()`: Shutdown server

### Session Methods

- `send_packet(data)`: Send to client
- `recv_packet()`: Receive from client
- `close()`: Close session

---

## Examples

See the [examples/](../../examples/) directory for more examples:

- `ipsec_client.rs` - Full-featured client
- `ipsec_server.rs` - Production server
- `ipsec_echo.rs` - Echo server/client
- `ipsec_metrics.rs` - Metrics collection
- `ipsec_logging.rs` - Structured logging

---

## Support

- **Documentation**: https://docs.rs/fynx-proto
- **Issues**: https://github.com/Rx947getrexp/fynx/issues
- **Discussions**: https://github.com/Rx947getrexp/fynx/discussions

---

**Copyright © 2025 Fynx Project**
**License**: MIT OR Apache-2.0
