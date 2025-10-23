# Phase 2 Implementation Plan: Advanced Authentication & Features

**Project**: Fynx SSH Implementation
**Phase**: Phase 2 (v0.2.0) - Advanced Authentication & Core Features
**Status**: 📋 Planning
**Prerequisites**: Phase 1 (v0.1.0) Complete ✅
**Target Completion**: Q2-Q3 2025

---

## Overview

Phase 2 builds on the solid foundation of Phase 1 by adding production-critical features, focusing on:
1. **Public Key Authentication** - Industry-standard auth method
2. **Host Key Management** - Secure host verification (known_hosts)
3. **Enhanced Security** - Rate limiting, connection management
4. **Basic Port Forwarding** - Local and remote forwarding

**Goal**: Make fynx SSH production-ready for real-world deployment.

---

## Stages

### Stage 6: Enhanced Cryptographic Support (Optional)

**Priority**: LOW-MEDIUM (depends on OpenSSH interop results)
**Effort**: 2-3 weeks
**Status**: ⏸️ On Hold (pending interop testing)

**Decision Criteria**:
- If OpenSSH 8.0+ works perfectly → **SKIP** this stage
- If older SSH servers needed → Implement AES-CTR only
- If enterprise requirements → Implement full stage

#### 6.1: AES-CTR Cipher Implementation
- [ ] Implement AES-128-CTR encryption/decryption
- [ ] Implement AES-256-CTR encryption/decryption
- [ ] CTR mode integration with existing packet layer
- [ ] Integration with MAC algorithms
- [ ] Unit tests (8+ tests)
- [ ] Integration tests with AES-CTR

#### 6.2: Encrypt-then-MAC (ETM) Variants
- [ ] Implement hmac-sha2-256-etm@openssh.com
- [ ] Implement hmac-sha2-512-etm@openssh.com
- [ ] ETM mode packet structure
- [ ] MAC-then-encrypt vs Encrypt-then-MAC handling
- [ ] Unit tests (6+ tests)

#### 6.3: Additional Channel Requests
- [ ] window-change request (terminal resize)
  - ChannelRequestType::WindowChange variant
  - Dimension encoding (rows, cols, width_px, height_px)
  - Client and server handlers
- [ ] signal request (process control)
  - ChannelRequestType::Signal variant
  - Signal names (TERM, KILL, HUP, etc.)
  - Server-side signal forwarding
- [ ] Unit tests (5+ tests)

#### 6.4: Keepalive Support
- [ ] SSH_MSG_GLOBAL_REQUEST (80)
- [ ] SSH_MSG_REQUEST_SUCCESS (81)
- [ ] SSH_MSG_REQUEST_FAILURE (82)
- [ ] keepalive@openssh.com request
- [ ] Configurable keepalive interval
- [ ] Automatic keepalive sending
- [ ] Unit tests (4+ tests)

#### 6.5: Enhanced Timeout Handling
- [ ] Configurable read/write timeouts
- [ ] Connection idle timeout
- [ ] Authentication timeout
- [ ] Graceful timeout handling
- [ ] Unit tests (5+ tests)

**Success Criteria**:
- AES-CTR works with legacy SSH servers
- Keepalive prevents connection drops
- window-change works for interactive shells
- All 28+ new tests passing

---

### Stage 7: Public Key Authentication 🎯 **HIGH PRIORITY**

**Priority**: HIGH (critical for production use)
**Effort**: 3-4 weeks
**Status**: 📋 Planned
**Dependencies**: Phase 1 complete

Public key authentication is the industry standard and essential for automation.

#### 7.1: Core Public Key Auth
- [ ] Implement publickey auth method (RFC 4252 Section 7)
- [ ] Public key signature generation
- [ ] Public key signature verification
- [ ] SSH2 public key format parsing
- [ ] PEM format support (ssh-rsa, ssh-ed25519, ecdsa-*)
- [ ] OpenSSH format support
- [ ] Unit tests (10+ tests)

#### 7.2: Private Key Loading
- [ ] Load private keys from files
- [ ] PEM format (RSA, Ed25519, ECDSA)
- [ ] OpenSSH private key format
- [ ] Encrypted private key support (AES-128-CBC, AES-256-CBC)
- [ ] Passphrase prompting
- [ ] Private key zeroization
- [ ] Unit tests (8+ tests)

#### 7.3: authorized_keys Support (Server)
- [ ] Parse authorized_keys file format
- [ ] Key matching algorithm
- [ ] Key options support:
  - command="..." (forced command)
  - no-port-forwarding
  - no-X11-forwarding
  - no-agent-forwarding
  - no-pty
  - from="pattern" (source restriction)
- [ ] Multi-key support
- [ ] Unit tests (12+ tests)

#### 7.4: known_hosts Support (Client)
- [ ] Parse known_hosts file format
- [ ] Host key verification
- [ ] Hash-based host matching
- [ ] Wildcard host patterns
- [ ] Add new host keys
- [ ] Update changed host keys
- [ ] Warn on unknown hosts
- [ ] Strict host key checking modes:
  - strict (reject unknown)
  - ask (prompt user)
  - accept-new (auto-add new)
  - no (accept all - insecure)
- [ ] Unit tests (10+ tests)

#### 7.5: SSH Agent Protocol (Client)
- [ ] SSH agent protocol (RFC 4253 Appendix A)
- [ ] SSH_AUTH_SOCK support
- [ ] Request identities (SSH2_AGENTC_REQUEST_IDENTITIES)
- [ ] Sign data (SSH2_AGENTC_SIGN_REQUEST)
- [ ] Agent forwarding setup
- [ ] Unit tests (8+ tests)

#### 7.6: Integration & Testing
- [ ] Client public key authentication
- [ ] Server public key authentication
- [ ] Integration tests (6+ tests)
- [ ] OpenSSH interop tests
- [ ] Documentation updates

**Success Criteria**:
- Public key auth works with client and server
- Can load standard key formats (PEM, OpenSSH)
- authorized_keys enforces key options
- known_hosts prevents MITM attacks
- All 54+ new tests passing

---

### Stage 8: Enhanced Security & Management 🔒

**Priority**: HIGH (production requirements)
**Effort**: 2-3 weeks
**Status**: 📋 Planned
**Dependencies**: Stage 7

Production deployments require robust security controls.

#### 8.1: Authentication Rate Limiting
- [ ] Configurable max auth attempts
- [ ] Per-IP rate limiting
- [ ] Exponential backoff
- [ ] Temporary IP blocking
- [ ] Failed auth logging
- [ ] Unit tests (6+ tests)

#### 8.2: Connection Management
- [ ] Max concurrent connections (global)
- [ ] Max connections per user
- [ ] Max connections per IP
- [ ] Connection queue management
- [ ] Graceful connection rejection
- [ ] Unit tests (8+ tests)

#### 8.3: Session Management
- [ ] Session timeout configuration
- [ ] Idle session detection
- [ ] Session termination
- [ ] Force disconnect capability
- [ ] Session logging
- [ ] Unit tests (5+ tests)

#### 8.4: Audit Logging
- [ ] Structured logging framework
- [ ] Connection events (connect, disconnect)
- [ ] Authentication events (success, failure)
- [ ] Command execution logging
- [ ] File transfer logging (future)
- [ ] Log rotation support
- [ ] Unit tests (6+ tests)

#### 8.5: Security Hardening
- [ ] Banner support (pre-auth message)
- [ ] Login grace time
- [ ] Client alive interval
- [ ] Client alive count max
- [ ] Disable empty passwords
- [ ] Permit root login control
- [ ] Unit tests (5+ tests)

**Success Criteria**:
- Rate limiting prevents brute force
- Connection limits prevent DoS
- Audit logs capture all security events
- All 30+ new tests passing

---

### Stage 9: Basic Port Forwarding 🔀

**Priority**: MEDIUM (useful feature, not critical)
**Effort**: 3-4 weeks
**Status**: 📋 Planned
**Dependencies**: Stage 7

Port forwarding is a core SSH feature for secure tunneling.

#### 9.1: Local Port Forwarding (Client → Server → Remote)
- [ ] SSH_MSG_CHANNEL_OPEN for direct-tcpip
- [ ] Local port listener
- [ ] Connection forwarding
- [ ] Error handling
- [ ] Integration tests (4+ tests)

#### 9.2: Remote Port Forwarding (Server → Client → Local)
- [ ] SSH_MSG_GLOBAL_REQUEST for tcpip-forward
- [ ] Remote port listener (server side)
- [ ] Connection forwarding
- [ ] Error handling
- [ ] Integration tests (4+ tests)

#### 9.3: Dynamic Port Forwarding (SOCKS proxy)
- [ ] SOCKS4/5 protocol support
- [ ] Dynamic channel creation
- [ ] DNS resolution handling
- [ ] Integration tests (4+ tests)

#### 9.4: Port Forwarding Management
- [ ] List active forwards
- [ ] Cancel forwards
- [ ] Forward restrictions (authorized_keys)
- [ ] Unit tests (6+ tests)

**Success Criteria**:
- Local forwarding works (-L option)
- Remote forwarding works (-R option)
- Dynamic forwarding works (-D option)
- All 18+ new tests passing

---

## Testing Strategy

### Unit Tests
- Target: 80%+ code coverage
- New tests: 150+ (across all stages)
- Focus on edge cases and error handling

### Integration Tests
- Full authentication flows (password + publickey)
- Port forwarding scenarios
- Security controls (rate limiting, connection limits)
- Session management

### Interoperability Tests
- OpenSSH client → fynx server
- fynx client → OpenSSH server
- Public key formats compatibility
- Port forwarding compatibility

### Performance Tests
- Connection throughput
- Authentication latency
- Port forwarding throughput
- Memory usage under load

### Security Tests
- Brute force resistance (rate limiting)
- DoS resistance (connection limits)
- MITM prevention (known_hosts)
- Key verification

---

## Documentation Updates

### User Documentation
- [ ] Public key authentication guide
- [ ] known_hosts management guide
- [ ] authorized_keys configuration guide
- [ ] Port forwarding examples
- [ ] Security hardening guide
- [ ] Troubleshooting guide

### Developer Documentation
- [ ] Public key crypto implementation details
- [ ] Port forwarding architecture
- [ ] Security control internals
- [ ] Testing guide
- [ ] Contributing guide

### API Documentation
- [ ] rustdoc updates for all new APIs
- [ ] Migration guide from v0.1 to v0.2
- [ ] Breaking changes documentation

---

## Dependencies & Crates

### New Dependencies (Potential)
- **ssh-key** - SSH key format parsing
- **ssh-encoding** - SSH wire format
- **pem** - PEM file parsing (if not using ssh-key)
- **bcrypt-pbkdf** - Encrypted key decryption
- **socks** - SOCKS proxy support (Stage 9)

### Dependency Audit
- Review all new dependencies for security
- Check maintenance status
- Verify license compatibility
- Run cargo-audit

---

## Migration Path from v0.1 to v0.2

### Breaking Changes (Anticipated)
- ClientConfig may add new required fields
- ServerConfig may add new required fields
- New error variants

### Deprecations
- None anticipated (v0.1 is new)

### Migration Guide
- Document all breaking changes
- Provide code examples
- Automated migration tool (optional)

---

## Success Metrics

### Functional
- [ ] Public key auth works with standard key formats
- [ ] known_hosts prevents MITM
- [ ] authorized_keys enforces restrictions
- [ ] Rate limiting blocks brute force
- [ ] Port forwarding works in all modes

### Quality
- [ ] 150+ new tests, all passing
- [ ] Zero unsafe code (maintained)
- [ ] Zero clippy warnings
- [ ] 80%+ code coverage
- [ ] Full rustdoc coverage

### Performance
- [ ] Auth latency < 100ms
- [ ] Port forwarding throughput > 100MB/s
- [ ] Max 1000 concurrent connections
- [ ] Memory usage < 10MB per connection

### Security
- [ ] External security audit passed
- [ ] No critical vulnerabilities
- [ ] OpenSSF Best Practices (passing)
- [ ] cargo-audit clean

---

## Timeline

### Month 1: Stage 6 (Optional) + Stage 7.1-7.3
- Week 1: OpenSSH interop testing, decide on Stage 6
- Week 2-3: Core public key auth + private key loading
- Week 4: authorized_keys support

### Month 2: Stage 7.4-7.6 + Stage 8.1-8.3
- Week 1-2: known_hosts + SSH agent
- Week 3: Public key auth integration tests
- Week 4: Authentication rate limiting + connection management

### Month 3: Stage 8.4-8.5 + Stage 9 (if time)
- Week 1: Audit logging + security hardening
- Week 2-3: Port forwarding (if in scope)
- Week 4: Testing, documentation, release prep

**Total Estimated Time**: 2-3 months (depends on Stage 6 decision and Stage 9 inclusion)

---

## Risks & Mitigation

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Key format compatibility issues | High | Medium | Extensive testing with OpenSSH keys |
| Performance degradation | Medium | Low | Benchmark early and often |
| Security vulnerabilities | High | Medium | External audit, fuzzing |
| OpenSSH incompatibility | High | Low | Rigorous interop testing |

### Schedule Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Underestimated complexity | Medium | Buffer time in schedule |
| Scope creep | High | Strict scope definition |
| Dependency issues | Medium | Evaluate dependencies early |

---

## Phase 2 Deliverables

### Code
- [ ] Public key authentication (client & server)
- [ ] Host key management (known_hosts)
- [ ] Authorized key management (authorized_keys)
- [ ] Security controls (rate limiting, connection limits)
- [ ] Audit logging
- [ ] Port forwarding (optional - Stage 9)
- [ ] 150+ new tests

### Documentation
- [ ] Public key auth guide
- [ ] Security hardening guide
- [ ] API documentation updates
- [ ] Migration guide
- [ ] CHANGELOG updates

### Release
- [ ] v0.2.0 published to crates.io
- [ ] GitHub release with artifacts
- [ ] Security audit report
- [ ] Blog post announcement

---

## Next Steps After Phase 2

### Phase 3: Advanced Features (v0.3.0)
- X11 forwarding
- Agent forwarding
- Advanced port forwarding (X11, agent)
- SFTP subsystem
- SCP protocol

### Phase 4: Enterprise & Integration (v0.4.0)
- PKCS#11 support
- HSM integration
- Certificate-based auth
- OpenID Connect integration
- Kerberos/GSSAPI support

---

**Plan Created**: 2025-10-18
**Last Updated**: 2025-10-18
**Next Review**: After v0.1.0 release
**Owner**: Fynx Development Team
