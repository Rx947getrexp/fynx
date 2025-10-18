# Fynx Proto - SSH Protocol Implementation

A secure, production-ready SSH protocol implementation in Rust, designed for the Fynx security ecosystem.

## Features

### Protocol Support
- **SSH Transport Layer Protocol (RFC 4253)**: Complete implementation with version exchange, key exchange, and packet encryption
- **Curve25519 Key Exchange**: Modern elliptic curve Diffie-Hellman (curve25519-sha256)
- **Ed25519 Host Keys**: Fast and secure digital signatures (ssh-ed25519)
- **Password Authentication**: Username/password authentication (RFC 4252)
- **Command Execution**: Remote command execution via SSH channels

### Security Features
- **Cryptographic Verification**: Full Ed25519 signature verification for host key authentication
- **Exchange Hash Computation**: RFC-compliant exchange hash for key verification
- **Secure Key Generation**: High-quality random key generation using `ring`
- **Memory Safety**: Rust's memory safety guarantees prevent common vulnerabilities
- **Zeroization**: Sensitive data (private keys, passwords) is securely wiped from memory

### Performance & Reliability
- **Async/Await**: Built on Tokio for high-performance asynchronous I/O
- **Zero-Copy Operations**: Efficient buffer handling with `bytes` crate
- **Type Safety**: Strong typing prevents protocol state machine errors
- **Comprehensive Testing**: 175+ tests including unit, integration, and doc tests

## Quick Start

### Client Example

Connect to an SSH server and execute a command:

```rust
use fynx_proto::ssh::client::SshClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to server
    let mut client = SshClient::connect("127.0.0.1:22").await?;

    // Authenticate
    client.authenticate_password("username", "password").await?;

    // Execute command
    let output = client.execute("whoami").await?;
    println!("Output: {}", String::from_utf8_lossy(&output));

    Ok(())
}
```

Run the example:
```bash
cargo run --example simple_client 127.0.0.1:22 username password "whoami"
```

### Server Example

Create a simple SSH server:

```rust
use fynx_proto::ssh::server::{SshServer, SessionHandler};
use fynx_proto::ssh::hostkey::{Ed25519HostKey, HostKey};
use fynx_platform::FynxResult;
use std::sync::Arc;

struct MyHandler;

#[async_trait::async_trait]
impl SessionHandler for MyHandler {
    async fn handle_exec(&mut self, command: &str) -> FynxResult<Vec<u8>> {
        Ok(format!("Executed: {}\n", command).into_bytes())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate host key
    let host_key = Arc::new(Ed25519HostKey::generate()?);

    // Create server
    let mut server = SshServer::bind_with_config(
        "127.0.0.1:2222",
        Default::default(),
        host_key,
    ).await?;

    // Set authentication callback
    server.set_auth_callback(Arc::new(|user, pass| {
        user == "admin" && pass == "secret"
    }));

    // Accept connections
    loop {
        let mut session = server.accept().await?;
        tokio::spawn(async move {
            session.authenticate().await?;
            let mut handler = MyHandler;
            session.handle_session(&mut handler).await
        });
    }
}
```

Run the example:
```bash
cargo run --example simple_server 127.0.0.1:2222
```

## Examples

The `examples/` directory contains several complete examples:

- **`simple_client.rs`**: Basic SSH client demonstrating connection, authentication, and command execution
- **`simple_server.rs`**: Basic SSH server with password authentication and command handling
- **`execute_command.rs`**: Non-interactive command execution with timeout handling and error recovery

Run any example with:
```bash
cargo run --example <example_name> -- [arguments]
```

## Architecture

### Core Components

```
fynx-proto/
├── src/ssh/
│   ├── client.rs          # SSH client implementation
│   ├── server.rs          # SSH server implementation
│   ├── transport.rs       # Transport layer state machine
│   ├── packet.rs          # SSH packet encoding/decoding
│   ├── kex.rs             # Key exchange algorithms (Curve25519)
│   ├── hostkey.rs         # Host key algorithms (Ed25519)
│   ├── auth.rs            # Authentication methods (password)
│   ├── channel.rs         # SSH channel management
│   ├── cipher.rs          # Encryption algorithms (ChaCha20-Poly1305, AES-GCM)
│   ├── mac.rs             # MAC algorithms (HMAC-SHA2)
│   └── crypto.rs          # Cryptographic primitives
├── tests/
│   └── ssh_integration.rs # Integration tests
└── examples/              # Usage examples
```

### Protocol Flow

```
Client                                    Server
  │                                         │
  ├──────── Version Exchange ──────────────>│
  │<─────── SSH-2.0-FynxServer ─────────────┤
  │                                         │
  ├──────── SSH_MSG_KEXINIT ───────────────>│
  │<─────── SSH_MSG_KEXINIT ────────────────┤
  │                                         │
  ├──────── SSH_MSG_KEX_ECDH_INIT ─────────>│
  │<─────── SSH_MSG_KEX_ECDH_REPLY ─────────┤ (includes signature)
  │         (verify host key signature)     │
  │                                         │
  ├──────── SSH_MSG_NEWKEYS ───────────────>│
  │<─────── SSH_MSG_NEWKEYS ────────────────┤
  │                                         │
  ├──────── SSH_MSG_SERVICE_REQUEST ───────>│
  │<─────── SSH_MSG_SERVICE_ACCEPT ─────────┤
  │                                         │
  ├──────── SSH_MSG_USERAUTH_REQUEST ──────>│
  │<─────── SSH_MSG_USERAUTH_SUCCESS ───────┤
  │                                         │
  ├──────── SSH_MSG_CHANNEL_OPEN ──────────>│
  │<─────── SSH_MSG_CHANNEL_OPEN_CONFIRM ───┤
  │                                         │
  ├──────── SSH_MSG_CHANNEL_REQUEST ───────>│ (exec)
  │<─────── SSH_MSG_CHANNEL_DATA ───────────┤ (output)
  │<─────── SSH_MSG_CHANNEL_EOF ────────────┤
  │<─────── SSH_MSG_CHANNEL_CLOSE ──────────┤
  │                                         │
```

## Cryptographic Algorithms

### Key Exchange
- **curve25519-sha256**: Elliptic Curve Diffie-Hellman with Curve25519

### Host Key Algorithms
- **ssh-ed25519**: Ed25519 digital signatures

### Encryption (AEAD)
- **chacha20-poly1305@openssh.com**: ChaCha20-Poly1305 authenticated encryption
- **aes128-gcm@openssh.com**: AES-128-GCM authenticated encryption
- **aes256-gcm@openssh.com**: AES-256-GCM authenticated encryption

### MAC Algorithms
- **hmac-sha2-256**: HMAC with SHA-256
- **hmac-sha2-512**: HMAC with SHA-512

### Authentication
- **password**: Username/password authentication (RFC 4252)

## Security Best Practices

### For Clients

1. **Verify Host Keys**: Always verify the server's host key fingerprint on first connection
   ```rust
   if let Some(fingerprint) = client.server_host_key_fingerprint() {
       println!("Server fingerprint: {}", fingerprint);
       // Compare with known fingerprint
   }
   ```

2. **Use Strong Passwords**: Ensure passwords are strong and not reused
   ```rust
   // Consider using public key authentication when available
   client.authenticate_password(username, strong_password).await?;
   ```

3. **Handle Timeouts**: Set appropriate timeouts to prevent hanging connections
   ```rust
   use tokio::time::{timeout, Duration};

   timeout(Duration::from_secs(30), client.connect(addr)).await??;
   ```

4. **Secure Credential Storage**: Never hardcode credentials
   ```rust
   // Read from secure storage or environment
   let password = env::var("SSH_PASSWORD")?;
   ```

### For Servers

1. **Use Persistent Host Keys**: Generate and store host keys persistently
   ```rust
   // Load from disk on startup
   let host_key = Ed25519HostKey::from_file("host_key")?;
   // Or generate once and save
   let host_key = Ed25519HostKey::generate()?;
   host_key.save_to_file("host_key")?;
   ```

2. **Implement Strong Authentication**: Use secure password policies
   ```rust
   server.set_auth_callback(Arc::new(|username, password| {
       // Validate against secure credential store
       // Consider rate limiting and account lockout
       verify_credentials(username, password)
   }));
   ```

3. **Limit Session Resources**: Prevent resource exhaustion
   ```rust
   // Set timeout for authentication
   tokio::time::timeout(Duration::from_secs(30), session.authenticate()).await??;

   // Limit concurrent sessions
   let semaphore = Arc::new(Semaphore::new(100));
   ```

4. **Log Security Events**: Monitor authentication attempts and failures
   ```rust
   server.set_auth_callback(Arc::new(|username, password| {
       let result = verify_credentials(username, password);
       if !result {
           log::warn!("Failed auth attempt for user: {}", username);
       }
       result
   }));
   ```

### General Recommendations

- **Keep Dependencies Updated**: Regularly update cryptographic dependencies
- **Enable All Tests**: Run `cargo test` before deployment
- **Review Security Advisories**: Monitor RustSec advisories for dependencies
- **Use TLS for Metadata**: Consider TLS for protocol metadata if needed
- **Implement Rate Limiting**: Prevent brute-force attacks
- **Use Audit Logging**: Log all security-relevant events

## Testing

Run all tests:
```bash
# All tests (175+ tests)
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test '*'

# Doc tests only
cargo test --doc

# With output
cargo test -- --nocapture

# Specific test
cargo test test_kex_with_signature_verification
```

### Test Coverage

- **Unit Tests**: 119 tests covering individual components
- **Integration Tests**: 6 comprehensive end-to-end tests
- **Doc Tests**: 50 documentation example tests
- **Total**: 175 tests with 100% pass rate

## Performance Considerations

### Async Runtime
- Built on Tokio for efficient async I/O
- Supports thousands of concurrent connections
- Non-blocking operations throughout

### Memory Efficiency
- Zero-copy buffer operations where possible
- Efficient packet parsing with `bytes` crate
- Automatic memory cleanup with RAII

### Optimization Tips

1. **Reuse Connections**: Keep connections alive for multiple commands
2. **Batch Operations**: Execute multiple commands per connection
3. **Tune Buffer Sizes**: Adjust based on workload
4. **Monitor Resource Usage**: Profile with `tokio-console`

## Dependencies

Core dependencies:
- `tokio`: Async runtime (features: `net`, `io-util`, `sync`, `time`, `rt`)
- `ring`: Cryptographic operations
- `ed25519-dalek`: Ed25519 signatures
- `x25519-dalek`: Curve25519 key exchange
- `sha2`: SHA-256/512 hashing
- `bytes`: Efficient buffer management
- `zeroize`: Secure memory wiping

See `Cargo.toml` for complete dependency list.

## Feature Flags

```toml
[features]
default = ["ssh"]
ssh = []      # SSH protocol support
dtls = []     # DTLS protocol support (future)
ipsec = []    # IPSec support (future)
```

## Roadmap

- [x] SSH Transport Layer (RFC 4253)
- [x] Curve25519 Key Exchange
- [x] Ed25519 Host Keys
- [x] Password Authentication
- [x] Command Execution
- [x] Integration Tests
- [x] Examples & Documentation
- [ ] Public Key Authentication
- [ ] Interactive Shell Support
- [ ] Port Forwarding
- [ ] SFTP Support
- [ ] Known Hosts Management
- [ ] AES-CTR Encryption
- [ ] NIST P-Curve KEX

## Contributing

Contributions are welcome! Please see `CONTRIBUTING.md` for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/fynx-project/fynx
cd fynx/crates/proto

# Build
cargo build

# Run tests
cargo test

# Run clippy
cargo clippy

# Format code
cargo fmt
```

## License

Dual-licensed under MIT or Apache-2.0.

## References

- [RFC 4253 - SSH Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
- [RFC 4252 - SSH Authentication Protocol](https://tools.ietf.org/html/rfc4252)
- [RFC 4254 - SSH Connection Protocol](https://tools.ietf.org/html/rfc4254)
- [RFC 8709 - Ed25519 and Ed448 Public Key Algorithms for SSH](https://tools.ietf.org/html/rfc8709)
- [Curve25519-SHA256](https://tools.ietf.org/html/rfc8731)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/fynx-project/fynx/issues
- Documentation: https://docs.rs/fynx-proto

---

**Note**: This is a security-focused implementation. Please review the Security Best Practices section and conduct proper security audits before production deployment.
