# SSH Feature Comparison: fynx-proto vs russh vs OpenSSH

**Date**: 2025-10-18
**Purpose**: Complete feature gap analysis for fynx-proto SSH implementation

---

## Executive Summary

### Current Status
- **fynx-proto**: Phase 1 (v0.1.0) - Framework implementation complete, needs network I/O integration
- **Completeness**: ~60% of Phase 1 features, ~30% of full SSH protocol
- **Critical Gaps**: Host key verification, signature verification, actual network I/O, integration tests

---

## 1. Key Exchange Algorithms

### russh (Reference Implementation)
- ✅ curve25519-sha256@libssh.org (Modern ECDH)
- ✅ ecdh-sha2-nistp256 (NIST P-256)
- ✅ ecdh-sha2-nistp384 (NIST P-384)
- ✅ ecdh-sha2-nistp521 (NIST P-521)
- ✅ diffie-hellman-group1-sha1 (Legacy 1024-bit)
- ✅ diffie-hellman-group14-sha256 (2048-bit MODP)
- ✅ diffie-hellman-group16-sha512 (4096-bit MODP)

### fynx-proto (Current Implementation)
- ✅ curve25519-sha256 (X25519 via `ring`)
- ✅ diffie-hellman-group14-sha256 (2048-bit MODP)
- ❌ NIST P-curves (P-256, P-384, P-521) - NOT IMPLEMENTED
- ❌ DH Group16 (4096-bit) - NOT IMPLEMENTED
- ❌ DH Group1 (Legacy, intentionally omitted for security)

**Gap Analysis**:
- **Missing**: NIST P-curve ECDH variants (needed for OpenSSH compatibility)
- **Missing**: DH Group16 (stronger 4096-bit option)
- **Status**: Core KEX algorithms present (Curve25519 + DH-14) ✅

---

## 2. Encryption Ciphers

### russh
- ✅ chacha20-poly1305@openssh.com (AEAD)
- ✅ aes128-gcm@openssh.com (AEAD)
- ✅ aes256-gcm@openssh.com (AEAD)
- ✅ aes128-ctr (Stream cipher + MAC)
- ✅ aes192-ctr (Stream cipher + MAC)
- ✅ aes256-ctr (Stream cipher + MAC)
- ✅ aes128-cbc (Block cipher + MAC, legacy)
- ✅ aes192-cbc (Block cipher + MAC, legacy)
- ✅ aes256-cbc (Block cipher + MAC, legacy)
- ✅ 3des-cbc (Legacy, weak)

### fynx-proto
- ✅ chacha20-poly1305@openssh.com (AEAD) - **IMPLEMENTED**
- ✅ aes128-gcm@openssh.com (AEAD) - **IMPLEMENTED**
- ✅ aes256-gcm@openssh.com (AEAD) - **IMPLEMENTED**
- ⚠️  aes128-ctr - **PLACEHOLDER** (enum exists, no crypto impl)
- ⚠️  aes256-ctr - **PLACEHOLDER** (enum exists, no crypto impl)
- ❌ aes192-ctr - NOT IMPLEMENTED
- ❌ CBC modes - NOT IMPLEMENTED (intentionally omitted, weak)
- ❌ 3DES - NOT IMPLEMENTED (intentionally omitted, obsolete)

**Gap Analysis**:
- **Critical Missing**: AES-CTR implementation (needed for non-AEAD fallback)
- **Status**: AEAD ciphers complete (ChaCha20-Poly1305, AES-GCM) ✅
- **Intentional Omissions**: CBC modes (security risk), 3DES (obsolete)

---

## 3. MAC Algorithms

### russh
- ✅ hmac-sha1 (Legacy, 160-bit)
- ✅ hmac-sha2-256 (256-bit)
- ✅ hmac-sha2-512 (512-bit)
- ✅ hmac-sha1-etm@openssh.com (Encrypt-then-MAC)
- ✅ hmac-sha2-256-etm@openssh.com (Encrypt-then-MAC)
- ✅ hmac-sha2-512-etm@openssh.com (Encrypt-then-MAC)

### fynx-proto
- ✅ hmac-sha2-256 - **IMPLEMENTED** (constant-time verification)
- ✅ hmac-sha2-512 - **IMPLEMENTED** (constant-time verification)
- ❌ hmac-sha1 - NOT IMPLEMENTED (intentionally omitted, weak)
- ❌ ETM variants - NOT IMPLEMENTED

**Gap Analysis**:
- **Missing**: Encrypt-then-MAC variants (better security model)
- **Status**: Core HMAC algorithms present (SHA256/512) ✅
- **Intentional Omissions**: HMAC-SHA1 (weak)

---

## 4. Host Key Algorithms

### russh
- ✅ ssh-ed25519 (EdDSA, modern)
- ✅ rsa-sha2-256 (RSA with SHA-256)
- ✅ rsa-sha2-512 (RSA with SHA-512)
- ✅ ssh-rsa (Legacy RSA with SHA-1)
- ✅ ecdsa-sha2-nistp256 (ECDSA P-256)
- ✅ ecdsa-sha2-nistp384 (ECDSA P-384)
- ✅ ecdsa-sha2-nistp521 (ECDSA P-521)
- ✅ OpenSSH certificates (ssh-ed25519-cert-v01@openssh.com, etc.)

### fynx-proto
- ❌ **CRITICAL**: No host key algorithms implemented
- ❌ ssh-ed25519 - NOT IMPLEMENTED
- ❌ rsa-sha2-256 - NOT IMPLEMENTED
- ❌ rsa-sha2-512 - NOT IMPLEMENTED
- ❌ ECDSA variants - NOT IMPLEMENTED
- ❌ OpenSSH certificates - NOT IMPLEMENTED

**Gap Analysis**:
- **CRITICAL GAP**: No host key verification (security risk!)
- **Required for Phase 1**: ssh-ed25519, rsa-sha2-256, rsa-sha2-512
- **Status**: ❌ **INCOMPLETE** - Blocking issue for production use

---

## 5. Authentication Methods

### russh
- ✅ password (plaintext password)
- ✅ publickey (RSA, Ed25519, ECDSA)
- ✅ keyboard-interactive (challenge-response)
- ✅ none (test method)
- ✅ OpenSSH certificates

### fynx-proto
- ✅ password - **IMPLEMENTED** (constant-time comparison)
- ⚠️  publickey - **PARTIAL** (message parsing only, no signature verification)
- ❌ keyboard-interactive - NOT IMPLEMENTED
- ✅ none - **IMPLEMENTED**
- ❌ OpenSSH certificates - NOT IMPLEMENTED

**Gap Analysis**:
- **CRITICAL MISSING**: Public key signature verification (RSA, Ed25519)
- **Missing**: keyboard-interactive (needed for 2FA/MFA)
- **Status**: Password auth complete ✅, Public key auth incomplete ❌

---

## 6. Channel Types

### russh
- ✅ session (shell, exec, subsystem)
- ✅ direct-tcpip (local port forwarding)
- ✅ forwarded-tcpip (remote port forwarding)
- ✅ direct-streamlocal@openssh.com (Unix socket forwarding)
- ✅ forwarded-streamlocal@openssh.com (Unix socket reverse forwarding)

### fynx-proto
- ✅ session - **IMPLEMENTED** (message parsing)
- ✅ direct-tcpip - **IMPLEMENTED** (message parsing)
- ✅ forwarded-tcpip - **IMPLEMENTED** (message parsing)
- ❌ Unix socket forwarding - NOT IMPLEMENTED

**Gap Analysis**:
- **Status**: Core channel types implemented ✅
- **Missing**: Unix socket forwarding (OpenSSH extension)

---

## 7. Channel Requests

### russh
- ✅ pty-req (pseudoterminal allocation)
- ✅ env (environment variables)
- ✅ exec (command execution)
- ✅ shell (interactive shell)
- ✅ subsystem (SFTP, etc.)
- ✅ exit-status (command exit code)
- ✅ exit-signal (signal termination)
- ✅ window-change (terminal resize)
- ✅ signal (send signal to remote process)

### fynx-proto
- ✅ pty-req - **IMPLEMENTED**
- ✅ env - **IMPLEMENTED**
- ✅ exec - **IMPLEMENTED**
- ✅ shell - **IMPLEMENTED**
- ✅ subsystem - **IMPLEMENTED**
- ✅ exit-status - **IMPLEMENTED**
- ✅ exit-signal - **IMPLEMENTED**
- ❌ window-change - NOT IMPLEMENTED
- ❌ signal - NOT IMPLEMENTED

**Gap Analysis**:
- **Status**: Core request types implemented ✅
- **Missing**: window-change (needed for interactive shells)
- **Missing**: signal (process control)

---

## 8. Advanced Features

### russh
- ✅ SFTP subsystem (client + server)
- ✅ SSH agent forwarding (auth-agent@openssh.com)
- ✅ Keepalive requests
- ✅ Extension negotiation (server-sig-algs)
- ✅ PPK key format support (PuTTY)
- ✅ Pageant integration (Windows)
- ✅ OpenSSH certificates

### fynx-proto
- ❌ SFTP subsystem - NOT IMPLEMENTED (Phase 2)
- ❌ Agent forwarding - NOT IMPLEMENTED (Phase 2)
- ❌ Keepalive - NOT IMPLEMENTED
- ❌ Extension negotiation - NOT IMPLEMENTED
- ❌ PPK format - NOT IMPLEMENTED
- ❌ Pageant - NOT IMPLEMENTED
- ❌ OpenSSH certificates - NOT IMPLEMENTED (Phase 3)

**Gap Analysis**:
- **Status**: Advanced features deferred to Phase 2/3 ✅
- **Current Focus**: Core protocol (Phase 1)

---

## 9. Network I/O & Transport

### russh
- ✅ Full async I/O (Tokio TcpStream)
- ✅ Version exchange (network protocol)
- ✅ Key exchange flow (complete handshake)
- ✅ Packet encryption/decryption (with sequence numbers)
- ✅ MAC computation/verification
- ✅ Rekey support (automatic rekeying)
- ✅ Connection timeout handling
- ✅ Keepalive mechanism

### fynx-proto
- ❌ **CRITICAL**: Network I/O not implemented (framework only)
- ❌ Version exchange - FRAMEWORK ONLY (no actual TCP I/O)
- ❌ Key exchange flow - FRAMEWORK ONLY (no actual handshake)
- ⚠️  Packet encryption - PARTIAL (crypto implemented, no integration)
- ⚠️  MAC verification - PARTIAL (constant-time impl, no integration)
- ⚠️  Rekey tracking - IMPLEMENTED (logic ready, no network integration)
- ❌ Connection timeout - NOT IMPLEMENTED
- ❌ Keepalive - NOT IMPLEMENTED

**Gap Analysis**:
- **CRITICAL GAP**: No actual network I/O implementation
- **Status**: ❌ **BLOCKING** - Cannot connect to real SSH servers
- **Client/Server APIs**: Framework only, need full integration

---

## 10. Security Features

### russh
- ✅ Constant-time operations (timing attack prevention)
- ✅ Memory zeroization (key material)
- ✅ Host key verification
- ✅ Signature verification (RSA, Ed25519, ECDSA)
- ✅ Known hosts file support
- ✅ Strict host key checking

### fynx-proto
- ✅ Constant-time password comparison - **IMPLEMENTED**
- ✅ Memory zeroization (Drop trait) - **IMPLEMENTED**
- ❌ **CRITICAL**: Host key verification - NOT IMPLEMENTED
- ❌ **CRITICAL**: Signature verification - NOT IMPLEMENTED
- ❌ Known hosts file - NOT IMPLEMENTED
- ❌ Strict host key checking - NOT IMPLEMENTED

**Gap Analysis**:
- **CRITICAL GAPS**: Host key verification, signature verification
- **Status**: Basic security primitives ✅, Host authentication ❌

---

## 11. Testing & Quality

### russh
- ✅ Unit tests for all modules
- ✅ Integration tests (client-server)
- ✅ Interoperability tests (OpenSSH)
- ✅ Examples (simple client, PTY client, server, SFTP)
- ✅ Real-world usage (HexPatch, Sandhole, Motor OS)

### fynx-proto
- ✅ Unit tests (100 tests passing) - **IMPLEMENTED**
- ✅ Doc tests (48 tests passing) - **IMPLEMENTED**
- ❌ Integration tests - NOT IMPLEMENTED
- ❌ Interoperability tests - NOT IMPLEMENTED
- ❌ Examples - NOT IMPLEMENTED
- ❌ Real-world usage - NOT APPLICABLE (not production-ready)

**Gap Analysis**:
- **Status**: Unit testing complete ✅
- **Missing**: Integration tests, interop tests, examples

---

## Critical Gap Summary

### Blocking Issues (Must Fix for Phase 1)

1. **Host Key Algorithms** ❌ **CRITICAL**
   - Need: ssh-ed25519, rsa-sha2-256, rsa-sha2-512
   - Impact: Cannot verify server identity (MITM vulnerability)
   - Priority: **HIGHEST**

2. **Network I/O Implementation** ❌ **CRITICAL**
   - Need: Actual TCP socket I/O with tokio
   - Impact: Framework exists but cannot connect to real servers
   - Priority: **HIGHEST**

3. **Public Key Signature Verification** ❌ **CRITICAL**
   - Need: Ed25519, RSA signature verification
   - Impact: Public key authentication unusable
   - Priority: **HIGH**

4. **Protocol Flow Integration** ❌ **CRITICAL**
   - Need: Complete handshake (version → KEX → auth → channels)
   - Impact: Components exist but not integrated
   - Priority: **HIGH**

5. **Integration Tests** ❌
   - Need: Client-server localhost tests
   - Impact: Cannot verify end-to-end functionality
   - Priority: **MEDIUM**

### Non-Blocking Gaps (Can Defer)

6. **AES-CTR Implementation** ⚠️
   - Status: Enum exists, crypto missing
   - Impact: Fallback cipher for non-AEAD compatibility
   - Priority: **MEDIUM**

7. **NIST P-Curve KEX** ❌
   - Need: ecdh-sha2-nistp256/384/521
   - Impact: Some servers require these
   - Priority: **LOW** (Curve25519 + DH-14 sufficient)

8. **Encrypt-then-MAC** ❌
   - Need: HMAC-SHA2-*-ETM variants
   - Impact: Better security model
   - Priority: **LOW**

9. **keyboard-interactive Auth** ❌
   - Need: Challenge-response protocol
   - Impact: 2FA/MFA support
   - Priority: **LOW** (Phase 2)

10. **Advanced Features** ❌
    - SFTP, agent forwarding, X11 forwarding
    - Impact: Extended functionality
    - Priority: **PHASE 2/3**

---

## Recommended Implementation Order

### Stage 5A: Complete Core Infrastructure (Week 1-2)
1. ✅ Implement ssh-ed25519 host key algorithm
2. ✅ Implement rsa-sha2-256/512 host key algorithms
3. ✅ Implement Ed25519 signature verification
4. ✅ Implement RSA signature verification
5. ✅ Add host key verification logic

### Stage 5B: Network I/O Integration (Week 2-3)
6. ✅ Implement TCP socket I/O (tokio TcpStream)
7. ✅ Integrate version exchange with network
8. ✅ Integrate key exchange with network
9. ✅ Integrate authentication with network
10. ✅ Integrate channel operations with network

### Stage 5C: Integration & Testing (Week 3-4)
11. ✅ Create simple_client.rs example
12. ✅ Create simple_server.rs example
13. ✅ Write integration tests (localhost)
14. ✅ Test against OpenSSH server
15. ✅ Test OpenSSH client against fynx server

### Stage 5D: Polish & Documentation (Week 4)
16. ✅ Implement AES-CTR ciphers
17. ✅ Add window-change channel request
18. ✅ Add keepalive support
19. ✅ Write comprehensive examples
20. ✅ Complete API documentation

---

## Feature Completeness Matrix

| Feature Category | russh | fynx-proto | Gap |
|-----------------|-------|------------|-----|
| **Key Exchange** | 7 algorithms | 2 algorithms | -5 (NIST curves, DH-16) |
| **Ciphers** | 10 ciphers | 3 working + 2 placeholder | -7 (CTR modes, legacy) |
| **MAC Algorithms** | 6 MACs | 2 MACs | -4 (SHA1, ETM variants) |
| **Host Keys** | 7 types + certs | 0 types | **-7 (CRITICAL)** |
| **Auth Methods** | 4 methods + certs | 1.5 methods | **-3 (CRITICAL)** |
| **Channel Types** | 5 types | 3 types | -2 (Unix sockets) |
| **Channel Requests** | 9 types | 7 types | -2 (window-change, signal) |
| **Network I/O** | Full implementation | Framework only | **-100% (CRITICAL)** |
| **Security** | Full verification | Partial verification | **-50% (CRITICAL)** |
| **Advanced Features** | SFTP, agent, etc. | None | -100% (Phase 2) |

**Overall Completeness**: ~35% (relative to russh)
**Phase 1 Completeness**: ~60% (core protocol only)
**Production Readiness**: ❌ **NOT READY** (missing critical security features)

---

## Conclusion

### Current State
fynx-proto has successfully implemented the **message formats and data structures** for SSH protocol (Stages 1-4 complete), and created a **comprehensive framework** for client/server APIs (Stage 5 framework). However, it is **missing critical components** for production use:

1. **Host key verification** - Cannot authenticate servers (MITM risk)
2. **Network I/O** - Cannot actually connect to SSH servers
3. **Signature verification** - Public key auth doesn't work
4. **Integration** - Components exist but not connected

### Next Steps
To complete **Phase 1 (v0.1.0)**, we must implement:
1. Host key algorithms (Ed25519, RSA)
2. Signature verification
3. Network I/O integration
4. End-to-end protocol flow
5. Integration tests
6. Examples

**Estimated Effort**: 3-4 weeks of development + 1 week testing
**Target**: Functional SSH client/server that can interoperate with OpenSSH

### Long-Term Roadmap
- **Phase 1** (v0.1.0): Complete basic client/server ← **Current Focus**
- **Phase 2** (v0.2.0): SFTP, port forwarding, agent forwarding
- **Phase 3** (v0.3.0): Certificates, MFA, performance optimization
