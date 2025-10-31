# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] - 2025-10-31

### Added

#### SSH Protocol (178 tests ✅)
- **Transport Layer (RFC 4253)**: Version exchange, key exchange, packet encryption/decryption
- **Key Exchange Algorithms**:
  - Curve25519-SHA256 (modern, recommended)
  - Diffie-Hellman Group 14 (2048-bit MODP)
  - Diffie-Hellman Group 15 (3072-bit MODP)
- **Host Key Algorithms**:
  - Ed25519 (ssh-ed25519)
  - RSA with SHA-2 (rsa-sha2-256, rsa-sha2-512)
  - ECDSA (ecdsa-sha2-nistp256/384/521)
- **Authentication Methods**:
  - Password authentication (RFC 4252)
  - Public key authentication (Ed25519, RSA, ECDSA)
- **Private Key Support**:
  - PEM format (PKCS#1, PKCS#8, SEC1)
  - OpenSSH format (encrypted and unencrypted)
  - Encrypted keys (AES-128/192/256-CBC/CTR, bcrypt-pbkdf)
- **Host Key Management**:
  - known_hosts file support (OpenSSH-compatible)
  - StrictHostKeyChecking modes (Strict, Ask, AcceptNew, No)
  - Host key verification and MITM detection
  - Fingerprint computation (MD5, SHA256)
- **Authorized Keys**:
  - authorized_keys file parsing
  - Public key lookup and verification
  - Options and comments support
- **Encryption (AEAD)**:
  - chacha20-poly1305@openssh.com (recommended)
  - aes128-gcm@openssh.com
  - aes256-gcm@openssh.com
- **MAC Algorithms**:
  - hmac-sha2-256
  - hmac-sha2-512
- **Connection Protocol (RFC 4254)**:
  - Channel management
  - Command execution
  - Session handling

#### IPSec/IKEv2 Protocol (567 tests ✅)
- **IKEv2 Protocol (RFC 7296)**:
  - IKE_SA_INIT: Initial handshake with DH key exchange
  - IKE_AUTH: Pre-Shared Key (PSK) authentication
  - CREATE_CHILD_SA: Security Association rekeying and new tunnels
  - INFORMATIONAL: DELETE notifications, liveness checks
- **ESP Protocol (RFC 4303)**:
  - Transport mode (host-to-host communication)
  - Tunnel mode (network-to-network VPN)
  - Anti-replay protection with sequence number validation
  - Automatic rekeying before SA lifetime expiration
- **Encryption Algorithms (AEAD)**:
  - AES-128-GCM (RFC 4106)
  - AES-256-GCM (RFC 4106)
  - ChaCha20-Poly1305 (RFC 8750)
- **Key Exchange**:
  - Diffie-Hellman Group 14 (2048-bit MODP)
  - Diffie-Hellman Group 15 (3072-bit MODP)
  - Curve25519 (Elliptic Curve DH)
- **Advanced Features**:
  - NAT Traversal (NAT-T, RFC 3948) with automatic detection
  - Dead Peer Detection (DPD) for liveness monitoring
  - Traffic Selectors for subnet-based tunnel configuration
  - Multiple cipher suite negotiation
  - Cookie-based DoS protection
- **High-Level APIs**:
  - IpsecClient: Async client with connect(), send_packet(), recv_packet()
  - IpsecServer: Async server with bind(), accept()
  - IpsecSession: Per-client session management
  - Configuration builders with validation (ClientConfig, ServerConfig)
- **Production Features**:
  - Structured logging with tracing (20+ instrumented functions)
  - Metrics collection (18 atomic counters for monitoring)
  - Enhanced error handling (error codes, context propagation, retry detection)
  - Performance benchmarks (12+ Criterion.rs benchmarks)
  - Interoperability testing framework (10 strongSwan tests)
- **Comprehensive Documentation**:
  - USER_GUIDE.md (500+ lines)
  - ARCHITECTURE.md (system architecture)
  - STAGE4_INTEROP_GUIDE.md (strongSwan interop)
  - API documentation with examples

### Security
- **Zero unsafe code**: 100% safe Rust implementation
- **Memory zeroization**: Sensitive data (keys, passwords) securely wiped using `zeroize`
- **Constant-time operations**: Cryptographic operations resistant to timing attacks
- **Strong random number generation**: Using `ring` for cryptographic-quality RNG
- **Comprehensive input validation**: Protocol message validation and bounds checking
- **Anti-replay protection**: Sequence number validation in ESP
- **Signature verification**: Host key and IKEv2 authentication verification

### Testing
- **745 total tests passing** (100% pass rate):
  - SSH: 172 unit tests + 6 integration tests
  - IPSec: 536 unit tests + 25 integration tests + 6 API tests
- **12+ performance benchmarks** for IPSec
- **10 interoperability tests** with strongSwan (framework ready)
- **Zero compilation warnings**

### Performance
- Built on Tokio async runtime for high-performance I/O
- Zero-copy buffer operations with `bytes` crate
- Efficient packet parsing and serialization
- Lock-free atomic metrics collection
- Benchmarked cryptographic operations

### Documentation
- Complete API documentation with examples
- Protocol-specific user guides (SSH, IPSec)
- Architecture documentation
- Interoperability testing guide
- Security best practices
- Contributing guidelines

### Dependencies
- Core: `tokio`, `ring`, `ed25519-dalek`, `x25519-dalek`, `bytes`, `zeroize`
- Cryptography: `aes-gcm`, `chacha20poly1305`, `hmac`, `sha2`
- Key formats: `pkcs1`, `pkcs8`, `sec1`, `rsa`
- Testing: `criterion`, `proptest`, `tracing-subscriber`

## [Unreleased]

### Planned
- SSH: Port forwarding (Local, Remote, Dynamic)
- SSH: SFTP protocol
- SSH: Session management and connection pooling
- SSH: ssh-agent support
- SSH: SCP support
- IPSec: X.509 certificate authentication
- IPSec: Additional cipher suites
- IPSec: MOBIKE (RFC 4555)
- DTLS: Protocol implementation

---

[0.1.0-alpha.1]: https://github.com/Rx947getrexp/fynx/releases/tag/fynx-proto-v0.1.0-alpha.1
