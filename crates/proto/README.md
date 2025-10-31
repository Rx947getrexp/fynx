# Fynx Proto - Network Security Protocols

[![Crates.io](https://img.shields.io/crates/v/fynx-proto)](https://crates.io/crates/fynx-proto)
[![Documentation](https://docs.rs/fynx-proto/badge.svg)](https://docs.rs/fynx-proto)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)

Production-ready SSH and IPSec protocol implementations in Rust, designed for the Fynx security ecosystem.

## 🎯 Protocols

### SSH (Secure Shell) ✅ Production Ready

Complete SSH protocol implementation with modern cryptography:

- **SSH Transport Layer** (RFC 4253): Version exchange, key exchange, packet encryption
- **Key Exchange**: Curve25519 (curve25519-sha256), DH Groups 14/15
- **Host Keys**: Ed25519, RSA, ECDSA (P-256/384/521)
- **Authentication**: Password, public key (Ed25519, RSA, ECDSA)
- **Encryption**: ChaCha20-Poly1305, AES-128/256-GCM
- **Advanced**: Private key loading (PEM, OpenSSH), known_hosts, authorized_keys
- **Testing**: 178 tests passing (100%)

### IPSec/IKEv2 (IP Security) ✅ Production Ready

Enterprise-grade VPN protocol with comprehensive features:

- **IKEv2 Protocol** (RFC 7296): IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA
- **ESP Protocol** (RFC 4303): Transport & Tunnel modes
- **Encryption**: AES-128/256-GCM, ChaCha20-Poly1305 (AEAD)
- **Authentication**: Pre-Shared Keys (PSK)
- **Advanced**: NAT-T (RFC 3948), Dead Peer Detection (DPD), SA Rekeying
- **High-Level APIs**: IpsecClient, IpsecServer with builder pattern
- **Production**: Structured logging (tracing), metrics (18 counters), error handling
- **Testing**: 567 tests passing + 12 benchmarks + 10 interop tests

## ⚡ Quick Start

### SSH Client

Add to your `Cargo.toml`:
```toml
[dependencies]
fynx-proto = { version = "0.1.0-alpha.1", features = ["ssh"] }
tokio = { version = "1.35", features = ["full"] }
```

Connect to an SSH server:
```rust
use fynx_proto::ssh::client::SshClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect and authenticate
    let mut client = SshClient::connect("127.0.0.1:22").await?;
    client.authenticate_password("username", "password").await?;

    // Execute command
    let output = client.execute("whoami").await?;
    println!("Output: {}", String::from_utf8_lossy(&output));

    Ok(())
}
```

### IPSec VPN Client

Add to your `Cargo.toml`:
```toml
[dependencies]
fynx-proto = { version = "0.1.0-alpha.1", features = ["ipsec"] }
tokio = { version = "1.35", features = ["full"] }
```

Create a VPN connection:
```rust
use fynx_proto::ipsec::{IpsecClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure client
    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(b"my-secret-key")
        .build()?;

    // Connect to VPN server
    let mut client = IpsecClient::new(config);
    client.connect("10.0.0.1:500".parse()?).await?;

    // Send encrypted data
    client.send_packet(b"Hello, VPN!").await?;
    let response = client.recv_packet().await?;
    println!("Received: {:?}", response);

    // Graceful shutdown
    client.shutdown().await?;
    Ok(())
}
```

## 📚 Features

### SSH Protocol Features

#### Core Protocol
- ✅ RFC 4253: SSH Transport Layer Protocol
- ✅ RFC 4252: Authentication Protocol
- ✅ RFC 4254: Connection Protocol
- ✅ Version exchange and algorithm negotiation
- ✅ Key exchange with signature verification
- ✅ Encrypted packet transport

#### Key Exchange
- ✅ Curve25519-SHA256 (modern, recommended)
- ✅ Diffie-Hellman Group 14 (2048-bit)
- ✅ Diffie-Hellman Group 15 (3072-bit)

#### Host Key Algorithms
- ✅ ssh-ed25519 (Ed25519 signatures)
- ✅ rsa-sha2-256, rsa-sha2-512 (RSA with SHA-2)
- ✅ ecdsa-sha2-nistp256/384/521 (ECDSA)

#### Authentication
- ✅ Password authentication (RFC 4252)
- ✅ Public key authentication (Ed25519, RSA, ECDSA)
- ✅ Private key loading (PEM, PKCS#1, PKCS#8, OpenSSH formats)
- ✅ Encrypted private keys (AES-128/192/256, bcrypt-pbkdf)
- ✅ authorized_keys file parsing
- ✅ known_hosts management (add, verify, update)
- ✅ StrictHostKeyChecking modes

#### Encryption (AEAD)
- ✅ chacha20-poly1305@openssh.com (recommended)
- ✅ aes128-gcm@openssh.com
- ✅ aes256-gcm@openssh.com

#### MAC Algorithms
- ✅ hmac-sha2-256
- ✅ hmac-sha2-512

### IPSec Protocol Features

#### IKEv2 Protocol (RFC 7296)
- ✅ IKE_SA_INIT: Initial handshake + DH key exchange
- ✅ IKE_AUTH: PSK authentication + first Child SA
- ✅ CREATE_CHILD_SA: Rekeying and new tunnels
- ✅ INFORMATIONAL: DELETE notifications, DPD

#### ESP Protocol (RFC 4303)
- ✅ Transport mode (host-to-host)
- ✅ Tunnel mode (network-to-network VPN)
- ✅ Anti-replay protection (sequence numbers)
- ✅ Automatic rekeying before SA expiration

#### Encryption Algorithms
- ✅ AES-128-GCM (AEAD)
- ✅ AES-256-GCM (AEAD)
- ✅ ChaCha20-Poly1305 (AEAD, RFC 8750)

#### Key Exchange
- ✅ Diffie-Hellman Group 14 (2048-bit MODP)
- ✅ Diffie-Hellman Group 15 (3072-bit MODP)
- ✅ Curve25519 (ECDH)

#### Advanced Features
- ✅ NAT Traversal (NAT-T, RFC 3948)
- ✅ Dead Peer Detection (DPD)
- ✅ Traffic Selectors (subnet-based tunnels)
- ✅ Multiple cipher suite negotiation
- ✅ Cookie-based DoS protection

#### Production Features
- ✅ High-level APIs (IpsecClient, IpsecServer)
- ✅ Configuration builders with validation
- ✅ Structured logging (tracing, 20+ instrumented functions)
- ✅ Metrics collection (18 atomic counters)
- ✅ Enhanced error handling (error codes, context, retry detection)
- ✅ Comprehensive documentation (500+ lines user guide)

## 🏗️ Architecture

```
fynx-proto/
├── src/
│   ├── ssh/                    # SSH Protocol (178 tests)
│   │   ├── client.rs           # SSH client with host key verification
│   │   ├── server.rs           # SSH server with authentication
│   │   ├── transport.rs        # Transport layer state machine
│   │   ├── kex.rs              # Key exchange (Curve25519, DH)
│   │   ├── hostkey.rs          # Host keys (Ed25519, RSA, ECDSA)
│   │   ├── auth.rs             # Authentication (password, pubkey)
│   │   ├── privatekey.rs       # Private key loading
│   │   ├── known_hosts.rs      # known_hosts file management
│   │   ├── authorized_keys.rs  # authorized_keys parsing
│   │   └── crypto.rs           # Cryptographic primitives
│   │
│   └── ipsec/                  # IPSec Protocol (567 tests)
│       ├── client.rs           # High-level IpsecClient API
│       ├── server.rs           # High-level IpsecServer API
│       ├── config.rs           # Configuration builders
│       ├── ikev2/              # IKEv2 protocol implementation
│       ├── esp/                # ESP protocol implementation
│       ├── crypto/             # AEAD ciphers, key derivation
│       ├── logging.rs          # Structured logging
│       └── metrics.rs          # Performance metrics
│
├── tests/
│   ├── ssh_integration.rs      # SSH integration tests (6 tests)
│   ├── ipsec_integration.rs    # IPSec integration tests (25 tests)
│   ├── ipsec_client_server.rs  # API tests (6 tests)
│   └── interop_strongswan.rs   # strongSwan interop (10 tests, ignored)
│
├── benches/
│   └── ipsec_bench.rs          # IPSec benchmarks (12 benchmarks)
│
└── docs/
    ├── ssh/                    # SSH documentation
    └── ipsec/                  # IPSec documentation
```

## 🧪 Testing

Comprehensive test coverage with 745+ tests:

```bash
# Run all tests
cargo test --all-features

# SSH tests (178 passing)
cargo test --features ssh

# IPSec tests (567 passing)
cargo test --features ipsec

# Run benchmarks
cargo bench --features ipsec

# With output
cargo test -- --nocapture
```

### Test Breakdown

| Category | Tests | Status |
|----------|-------|--------|
| **SSH Unit Tests** | 172 | ✅ 100% |
| **SSH Integration** | 6 | ✅ 100% |
| **IPSec Unit Tests** | 536 | ✅ 100% |
| **IPSec Integration** | 25 | ✅ 100% |
| **IPSec API Tests** | 6 | ✅ 100% |
| **Total Library Tests** | **745** | **✅ 100%** |
| **IPSec Benchmarks** | 12+ | ✅ Running |
| **Interop Tests** | 10 | 📋 Framework ready |

## 🔒 Security

### Memory Safety
- **Zero unsafe code**: 100% safe Rust
- **Zeroization**: Sensitive data (keys, passwords) securely wiped
- **No memory leaks**: RAII and automatic cleanup

### Cryptographic Security
- **Modern algorithms**: Curve25519, Ed25519, ChaCha20-Poly1305
- **Constant-time operations**: Timing attack resistant
- **Strong RNG**: Using `ring` for cryptographic randomness
- **Anti-replay protection**: Sequence number validation in ESP

### Protocol Security
- **Host key verification**: Prevent MITM attacks (SSH)
- **Signature verification**: Authenticate server identity (SSH, IKEv2)
- **Cookie-based DoS protection**: Resist resource exhaustion (IKEv2)
- **Dead Peer Detection**: Detect unresponsive peers (IPSec)

## 📖 Documentation

- **API Documentation**: [docs.rs/fynx-proto](https://docs.rs/fynx-proto)
- **SSH User Guide**: [docs/ssh/README.md](https://github.com/Rx947getrexp/fynx/blob/main/docs/ssh/README.md)
- **IPSec User Guide**: [docs/ipsec/USER_GUIDE.md](https://github.com/Rx947getrexp/fynx/blob/main/docs/ipsec/USER_GUIDE.md)
- **IPSec Architecture**: [docs/ipsec/ARCHITECTURE.md](https://github.com/Rx947getrexp/fynx/blob/main/docs/ipsec/ARCHITECTURE.md)
- **Examples**: See `examples/` directory

### Examples

Run examples with:
```bash
# SSH client example
cargo run --example simple_client --features ssh

# IPSec examples (coming soon)
cargo run --example ipsec_client --features ipsec
```

## ⚙️ Feature Flags

```toml
[features]
default = ["ssh"]

# SSH protocol support (RFC 4253/4252/4254)
# - 178 tests, production-ready
# - Client, server, authentication
ssh = []

# IPSec/IKEv2 VPN protocol (RFC 7296, RFC 4303)
# - 567 tests, production-ready
# - IKEv2 key exchange, ESP encryption
# - High-level APIs, metrics, logging
ipsec = []

# DTLS protocol (planned)
dtls = []

# TTY password input for SSH
tty-password = ["rpassword"]
```

## 🚀 Performance

### Benchmarks (IPSec)

Run with: `cargo bench --features ipsec --bench ipsec_bench`

- **IKE Handshake**: Complete IKE_SA_INIT + IKE_AUTH exchange
- **ESP Encryption**: 64B, 512B, 1500B packet throughput
- **ESP Decryption**: 64B, 1500B packet throughput
- **Key Derivation**: IKE SA and Child SA key generation
- **Serialization**: Packet encoding/decoding performance

### Async Runtime
- Built on Tokio for efficient async I/O
- Non-blocking operations throughout
- Supports thousands of concurrent connections

### Memory Efficiency
- Zero-copy buffer operations with `bytes` crate
- Efficient packet parsing
- Automatic cleanup with RAII

## 📋 Roadmap

### Completed ✅
- [x] SSH Transport Layer (RFC 4253)
- [x] SSH Authentication (password, public key)
- [x] SSH Connection Protocol (command execution)
- [x] Private key loading (PEM, OpenSSH formats)
- [x] known_hosts management
- [x] authorized_keys parsing
- [x] IKEv2 Protocol (RFC 7296)
- [x] ESP Protocol (RFC 4303)
- [x] NAT Traversal (NAT-T)
- [x] Dead Peer Detection (DPD)
- [x] High-level IPSec APIs
- [x] Production hardening (logging, metrics)

### Planned 📋
- [ ] SSH: Port forwarding (Local, Remote, Dynamic)
- [ ] SSH: SFTP protocol
- [ ] SSH: Session management (multiplexing, connection pool)
- [ ] SSH: ssh-agent support
- [ ] SSH: SCP support
- [ ] IPSec: X.509 certificate authentication
- [ ] IPSec: Additional cipher suites
- [ ] IPSec: MOBIKE (RFC 4555)
- [ ] DTLS: Protocol implementation

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/Rx947getrexp/fynx
cd fynx/crates/proto

# Build
cargo build --all-features

# Run tests
cargo test --all-features

# Run specific protocol tests
cargo test --features ssh
cargo test --features ipsec

# Run clippy
cargo clippy --all-features

# Format code
cargo fmt

# Generate documentation
cargo doc --all-features --open
```

## 📄 License

Dual-licensed under MIT or Apache-2.0.

- MIT License: [LICENSE-MIT](LICENSE-MIT)
- Apache License 2.0: [LICENSE-APACHE](LICENSE-APACHE)

## 🔗 References

### SSH
- [RFC 4253](https://tools.ietf.org/html/rfc4253) - SSH Transport Layer Protocol
- [RFC 4252](https://tools.ietf.org/html/rfc4252) - SSH Authentication Protocol
- [RFC 4254](https://tools.ietf.org/html/rfc4254) - SSH Connection Protocol
- [RFC 8709](https://tools.ietf.org/html/rfc8709) - Ed25519 for SSH

### IPSec
- [RFC 7296](https://tools.ietf.org/html/rfc7296) - IKEv2 Protocol
- [RFC 4303](https://tools.ietf.org/html/rfc4303) - ESP Protocol
- [RFC 3948](https://tools.ietf.org/html/rfc3948) - NAT Traversal
- [RFC 4106](https://tools.ietf.org/html/rfc4106) - AES-GCM for ESP
- [RFC 8750](https://tools.ietf.org/html/rfc8750) - ChaCha20-Poly1305 for IPSec

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/Rx947getrexp/fynx/issues)
- **Documentation**: [docs.rs/fynx-proto](https://docs.rs/fynx-proto)
- **Repository**: [github.com/Rx947getrexp/fynx](https://github.com/Rx947getrexp/fynx)

---

**Note**: This is an alpha release. While extensively tested, please conduct security audits before production deployment.
