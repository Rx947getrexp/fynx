# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Next Release: v0.1.0 (Target: 2025-12-15)

**Major Features Planned:**
- Public key authentication (RSA, Ed25519, ECDSA)
- known_hosts support (MITM prevention)
- authorized_keys support (server-side public key auth)
- keyboard-interactive authentication (MFA support)
- Security enhancements (rate limiting, connection limits)
- Audit logging

See [ROADMAP_REVISED.md](./ROADMAP_REVISED.md) for details.

---

## [0.0.1-alpha] - 2025-10-18

**Status**: 🔬 **Technical Preview - NOT FOR PRODUCTION USE**

### ⚠️ Important Limitations

This is an alpha release for testing and feedback only. **DO NOT use in production.**

**Missing Critical Features:**
- ❌ No public key authentication (password only)
- ❌ No known_hosts verification (security risk!)
- ❌ No SFTP/file transfer
- ❌ No port forwarding

**Use Cases:**
- ✅ Technical evaluation
- ✅ Testing and feedback
- ✅ Development and experimentation
- ❌ Production deployments
- ❌ Automated scripts (no public key auth)

### Documentation
- Added comprehensive feature comparison (FEATURE_COMPARISON.md)
- Added revised roadmap (ROADMAP_REVISED.md)
- Added OpenSSH interoperability test suite
- Added detailed testing guide (OPENSSH_TESTING.md)
- Added interoperability results template
- Added Phase 1 completion report
- Added release checklist

### Added - Phase 1: Core SSH Protocol ✅

#### Stage 1: SSH Packet Layer (2025-01-17)
- Binary packet protocol (RFC 4253 Section 6)
- Packet encryption/decryption support
- Padding and MAC handling
- Size limit validation (max 35KB payload)
- 15 tests (10 unit + 5 doc)

#### Stage 2: SSH Transport Layer (2025-01-17)
- Version exchange (SSH-2.0 protocol)
- Message type definitions (all RFC 4253 messages)
- KEXINIT message and algorithm negotiation
- Curve25519-SHA256 key exchange (primary)
- DH Group14-SHA256 key exchange (2048-bit MODP)
- Key derivation functions (RFC 4253 Section 7.2)
- 68 tests (42 unit + 26 doc)

#### Stage 3: SSH Authentication Protocol (2025-10-17)
- Complete authentication protocol (RFC 4252)
- Authentication methods: none, password, publickey (framework)
- All message types: USERAUTH_REQUEST/FAILURE/SUCCESS/BANNER
- Constant-time password comparison (timing attack prevention)
- Password zeroization on drop
- Partial success handling (MFA framework)
- 11 tests (8 unit + 3 doc)

#### Stage 4: SSH Connection Protocol (2025-10-17)
- Complete connection protocol (RFC 4254)
- Channel types: session, direct-tcpip, forwarded-tcpip
- Channel request types: exec, shell, pty-req, env, subsystem, exit-status, exit-signal
- Window size and packet size validation (DoS prevention)
- Flow control support (window adjustment)
- 20 tests (19 unit + 1 doc)

#### Stage 5: Client & Server APIs (2025-10-18)

**Cryptographic Module:**
- AEAD ciphers: ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM
- Stream ciphers: AES-128-CTR, AES-256-CTR (defined, not implemented)
- MAC algorithms: HMAC-SHA256, HMAC-SHA512
- Automatic nonce management (packet sequence-based)
- Constant-time MAC verification
- Memory zeroization on drop
- 9 unit tests

**Transport State Machine:**
- 5 states: VersionExchange → KexInit → KeyExchange → NewKeys → Encrypted
- State transition validation
- Encryption parameter management
- Automatic rekey tracking (bytes and time based)
- 19 unit tests

**SSH Client (SshClient):**
- Complete implementation (1,215 lines)
- Full TCP network I/O with tokio async
- Methods: connect, authenticate_password, execute, disconnect
- Version exchange implementation
- Curve25519 key exchange with signature verification
- Host key parsing and verification (Ed25519, RSA, ECDSA)
- RFC 4253 Section 7.2 key derivation (C->S and S->C)
- Complete AEAD encryption/decryption
- Password authentication (SERVICE_REQUEST → USERAUTH)
- Command execution with channel management
- Connection timeout support
- 2 unit tests + extensive integration coverage

**SSH Server (SshSession):**
- Complete implementation (905 lines)
- TCP listener with bind/accept
- Version exchange (server side)
- Curve25519 key exchange with host key signing
- RFC 4253 Section 7.2 key derivation (server perspective)
- Complete AEAD encryption/decryption
- Authentication handling with callback support
- Session management with SessionHandler trait
- Channel lifecycle management
- Configurable authentication attempt limits
- 2 unit tests

**Host Key Support:**
- Ed25519 key generation, signing, verification
- RSA-SHA2-256/512 signing, verification
- ECDSA-P256/P384/P521 signing, verification
- Host key fingerprint computation (SHA256)

**Integration Tests:**
- 6 comprehensive integration tests
- test_version_exchange - Version negotiation
- test_kex_with_signature_verification - KEX with host key verification
- test_exchange_hash_consistency - Hash computation validation
- test_authentication_failure - Failed authentication handling
- test_authentication_flow - Complete password authentication
- test_full_ssh_flow - End-to-end: connect → auth → execute

**Examples:**
- simple_client.rs - Basic SSH client usage
- simple_server.rs - Basic SSH server setup
- execute_command.rs - Non-interactive command execution

**Documentation:**
- Complete README with quick start
- Full rustdoc API documentation
- Security best practices guide
- Implementation plan (5 stages)

### Fixed

- Packet parsing integer underflow in packet.rs:334 (2025-10-18)
- Server encryption/decryption support in send_packet/receive_packet (2025-10-18)
- Server key derivation in perform_curve25519_kex (2025-10-18)
- Unused import warnings in hostkey.rs (2025-10-18)

### Security

- Zero unsafe code blocks (100% safe Rust)
- Constant-time MAC verification (timing attack prevention)
- Password zeroization on drop
- Private key zeroization on drop
- No compression support (CRIME attack prevention)
- Modern cryptographic algorithms only

### Testing

- 175+ tests total:
  - 119 unit tests
  - 50 doc tests
  - 6 integration tests
- 100% pass rate
- Zero compilation warnings
- Zero clippy warnings

### Supported Algorithms

**Key Exchange:**
- curve25519-sha256
- curve25519-sha256@libssh.org
- diffie-hellman-group14-sha256

**Host Keys:**
- ssh-ed25519 (primary)
- rsa-sha2-256
- rsa-sha2-512
- ecdsa-sha2-nistp256
- ecdsa-sha2-nistp384
- ecdsa-sha2-nistp521

**Encryption:**
- chacha20-poly1305@openssh.com (primary)
- aes128-gcm@openssh.com
- aes256-gcm@openssh.com

**MAC:**
- Integrated with AEAD ciphers
- hmac-sha2-256 (for CTR mode)
- hmac-sha2-512 (for CTR mode)

**Compression:**
- none (only - compression disabled for security)

### Known Limitations

**Not Implemented (Future Phases):**
- Public key authentication (Phase 2)
- Known_hosts file support (Phase 2)
- Authorized_keys file support (Phase 2)
- Port forwarding (Phase 3)
- X11 forwarding (Phase 3)
- Agent forwarding (Phase 3)
- SFTP subsystem (Phase 3/4)
- SCP protocol (Phase 3/4)
- Compression support (intentionally disabled)

**Security Limitations:**
- Host key verification accepts any key (insecure - needs known_hosts)
- No authentication rate limiting
- No connection limits
- Strict host key checking not enabled by default

**Compatibility:**
- Requires modern OpenSSH (6.5+) for ChaCha20-Poly1305
- May need AES-CTR for older servers (Stage 6 - optional)

### Platform Support

- Linux (tested)
- macOS (should work, not tested)
- Windows (should work, not tested)

### Dependencies

**Core:**
- tokio = "1.35" (async runtime)
- ring = "0.17" (cryptography)
- ed25519-dalek = "2.1" (Ed25519)
- x25519-dalek = "2.0" (Curve25519)
- rsa = "0.9" (RSA)
- sha2 = "0.10" (hashing)
- hmac = "0.12" (HMAC)
- zeroize = "1.7" (secure memory)
- bytes = "1.5" (buffer management)

**Testing:**
- hex = "0.4"
- hex-literal = "0.4"

### Breaking Changes

- N/A (initial release)

---

## [0.0.0] - Development

Initial development phase. No public releases.

---

## Release Types

- **Major (x.0.0)**: Breaking API changes
- **Minor (0.x.0)**: New features, backward compatible
- **Patch (0.0.x)**: Bug fixes, backward compatible

## Version Support

- **v0.1.x**: Supported until v0.2.0 release + 3 months
- Security patches provided for current and previous minor version

---

[Unreleased]: https://github.com/fynx/fynx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fynx/fynx/releases/tag/v0.1.0
