# IPSec Protocol Implementation Plan

**Protocol**: IPSec (IKEv2 + ESP)
**Target Version**: fynx-proto v0.2.0
**Start Date**: 2025-10-24
**Estimated Completion**: 2025-12-31 (10 weeks)

---

## Executive Summary

Implement a complete IPSec protocol stack including:
- **IKEv2** (Internet Key Exchange v2) - RFC 7296
- **ESP** (Encapsulating Security Payload) - RFC 4303
- **NAT-T** (NAT Traversal) - RFC 3948

This will be Rust's first pure-Rust IPSec implementation, filling a critical gap in the ecosystem.

---

## Goals

### Primary Goals
1. ✅ Complete IKEv2 implementation (SA negotiation, authentication, rekeying)
2. ✅ Complete ESP implementation (transport & tunnel modes)
3. ✅ NAT-T support for real-world deployments
4. ✅ Interoperability with strongSwan, libreswan
5. ✅ Production-ready code quality (zero unsafe, 100% tested)

### Non-Goals (Future Phases)
- ❌ AH (Authentication Header) - rarely used
- ❌ IKEv1 - deprecated
- ❌ L2TP/IPSec - can be added later
- ❌ Certificate management GUI - CLI only

---

## Technical Overview

### Protocol Stack

```
Application Layer
       ↓
  IKEv2 Control Plane (UDP 500/4500)
  ├── SA Negotiation
  ├── Authentication
  └── Key Management
       ↓
  ESP Data Plane (IP Protocol 50)
  ├── Encryption (AES-GCM, ChaCha20-Poly1305)
  ├── Authentication (HMAC-SHA2)
  └── Anti-Replay Protection
       ↓
  IP Layer (Transport/Tunnel Mode)
```

### Key Components

1. **IKEv2 Module** (`src/ipsec/ikev2/`)
   - Message parser/serializer
   - State machine (INIT, AUTH, CREATE_CHILD_SA)
   - Proposal negotiation
   - Authentication (PSK, X.509)
   - Key derivation (PRF+)

2. **ESP Module** (`src/ipsec/esp/`)
   - Packet encapsulation/decapsulation
   - Encryption/decryption
   - Sequence number management
   - Anti-replay window

3. **Crypto Module** (`src/ipsec/crypto/`)
   - Reuse SSH crypto primitives
   - Add IPSec-specific algorithms
   - Key derivation functions

4. **SA Database** (`src/ipsec/sa/`)
   - Security Association storage
   - Lifetime management
   - Rekeying logic

---

## Implementation Stages

### Stage 1: Foundation & IKEv2 Protocol Parsing (Week 1-2) ✅ COMPLETED

**Status**: ✅ Completed on 2025-10-24
**Commits**: dcc2834, 4f553d0, 3b22338, 7b0f31c, a178158, 7c00d51

**Goal**: Parse and serialize IKEv2 messages according to RFC 7296

**Deliverables**:
- [x] IKEv2 message structure (header + payloads)
- [x] Payload types (SA, KE, Nonce, ID, AUTH, NOTIFY, DELETE, VENDOR_ID)
- [x] Binary encoding/decoding
- [x] Complete message parsing with payload chains
- [x] Error and status notifications (NOTIFY payload)
- [x] SA deletion support (DELETE payload)
- [x] Vendor identification (VENDOR_ID payload)
- [x] Unit tests (69 payload tests - exceeds target of 30+)

**Success Criteria**:
- ✅ Parse IKE messages with header + payloads
- ✅ Serialize messages with automatic length calculation
- ✅ Support all common payload types
- ✅ NOTIFY payload for error/status reporting
- ✅ DELETE payload for SA termination
- ✅ VENDOR_ID payload for implementation identification
- ✅ 100% test coverage on all payloads (69/69 tests passing)

**Actual Implementation**:
- Part 1 (dcc2834): IKEv2 foundation (constants, message header, error handling) - 16 tests
- Part 2 (4f553d0): Payload structures (PayloadHeader, Nonce, KE, SA) - 11 tests
- Part 3 (3b22338): Complete message parsing with payload chains - 8 integration tests
- Part 4 (7b0f31c): ID and AUTH payloads - 10 tests
- Part 5 (a178158): NOTIFY payload for error/status notifications - 12 tests
- Part 6 (7c00d51): DELETE and VENDOR_ID payloads - 12 tests
- Total: 69 payload tests + 11 message tests = 80 core tests, all passing

**Complete Payload Set**:
- ✅ SA (Security Association) - Proposal negotiation
- ✅ KE (Key Exchange) - Diffie-Hellman public keys
- ✅ Nonce - Random values for replay protection
- ✅ IDi/IDr (Identification) - Peer identification
- ✅ AUTH (Authentication) - PSK and signature authentication
- ✅ N (Notify) - 27 error/status notification types
- ✅ D (Delete) - SA deletion with multiple SPI support
- ✅ V (Vendor ID) - Implementation identification

**Files to Create**:
```
crates/proto/src/ipsec/
├── mod.rs
├── ikev2/
│   ├── mod.rs
│   ├── message.rs      # IKEv2 message structure
│   ├── payload.rs      # Payload types
│   ├── proposal.rs     # SA proposals
│   ├── transform.rs    # Transform sets
│   └── constants.rs    # RFC constants
└── error.rs            # IPSec error types
```

**Technical Details**:
```rust
// Example: IKEv2 message structure
pub struct IkeMessage {
    pub header: IkeHeader,
    pub payloads: Vec<IkePayload>,
}

pub struct IkeHeader {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub next_payload: PayloadType,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: IkeFlags,
    pub message_id: u32,
    pub length: u32,
}

pub enum IkePayload {
    SA(SaPayload),
    KE(KeyExchangePayload),
    Nonce(NoncePayload),
    // ... more payload types
}
```

**Tests**:
```rust
#[test]
fn test_parse_ike_sa_init_request() {
    let raw = include_bytes!("../test_data/ike_sa_init.bin");
    let msg = IkeMessage::from_bytes(raw).unwrap();
    assert_eq!(msg.header.exchange_type, ExchangeType::IKE_SA_INIT);
}
```

---

### Stage 2: IKEv2 State Machine & SA Negotiation (Week 3-4) ✅ PARTIALLY COMPLETED

**Status**: ✅ Core components completed
**Commits**: 862f3a5, 2c28ce9, 9a45913, 7b0f31c

**Goal**: Implement IKE_SA_INIT and IKE_AUTH exchanges

**Deliverables**:
- [x] IKEv2 state machine
- [ ] IKE_SA_INIT exchange (initial handshake) - payloads ready
- [ ] IKE_AUTH exchange (authentication) - payloads ready
- [x] Proposal selection algorithm
- [ ] Cookie mechanism (DoS protection) - deferred
- [x] Unit tests (20 tests - core logic)

**Success Criteria**:
- ✅ State machine handles Initiator/Responder flows
- ✅ Support multiple cipher suites via Proposal/Transform
- ✅ Handle invalid proposals gracefully (NoProposalChosen error)

**Actual Implementation**:
- Part 1 (862f3a5): IKE SA state machine - 9 tests
- Part 2 (2c28ce9): Proposal/Transform structures - 11 tests
- Part 3 (9a45913): SA Payload enhancement - 2 tests
- Part 4 (7b0f31c): ID and AUTH payloads - 10 tests
- Total: 32 tests (20 state/negotiation + 12 payload)

**State Machine**:
```
IDLE
  ↓ (send IKE_SA_INIT request)
INIT_SENT
  ↓ (recv IKE_SA_INIT response)
INIT_DONE
  ↓ (send IKE_AUTH request)
AUTH_SENT
  ↓ (recv IKE_AUTH response)
ESTABLISHED
  ↓
(Handle CREATE_CHILD_SA, INFORMATIONAL)
```

**Files to Create**:
```
crates/proto/src/ipsec/ikev2/
├── state.rs           # State machine
├── exchange.rs        # Exchange handlers
├── negotiation.rs     # Proposal selection
└── cookie.rs          # Cookie mechanism
```

**Key Algorithms**:
```rust
// Proposal selection (RFC 7296 Section 2.7)
fn select_proposal(
    offered: &[Proposal],
    configured: &[Proposal],
) -> Result<Proposal> {
    // Find first acceptable proposal
    for offer in offered {
        if is_acceptable(offer, configured) {
            return Ok(offer.clone());
        }
    }
    Err(Error::NoProposalChosen)
}
```

---

### Stage 3: Cryptographic Operations & Key Derivation (Week 5) ✅ PARTIALLY COMPLETED

**Status**: ✅ PRF and key derivation completed
**Commits**: 4a110d7

**Goal**: Implement IKEv2 cryptographic operations

**Deliverables**:
- [ ] Diffie-Hellman key exchange (reuse from SSH) - deferred, can reuse SSH DH
- [x] PRF (Pseudo-Random Function)
- [x] Key derivation (SKEYSEED, SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr)
- [ ] AEAD encryption for IKE messages - deferred to exchange implementation
- [x] Unit tests (9 tests - core crypto)

**Success Criteria**:
- ✅ Derive keys using RFC 7296 algorithm
- ✅ Support HMAC-SHA2-256/384/512
- ✅ prf+ key expansion working correctly

**Actual Implementation**:
- Part 1 (4a110d7): PRF and KeyMaterial derivation - 9 tests
- Implemented: PrfAlgorithm, prf+, KeyMaterial::derive()

**Files to Create**:
```
crates/proto/src/ipsec/crypto/
├── mod.rs
├── prf.rs             # PRF functions
├── kdf.rs             # Key derivation
├── dh.rs              # DH groups (reuse SSH)
└── aead.rs            # AEAD for IKE messages
```

**Key Derivation Chain** (RFC 7296 Section 2.14):
```
SKEYSEED = prf(Ni | Nr, g^ir)

{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
    = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
```

**Code Example**:
```rust
pub fn derive_keys(
    prf_alg: PrfAlgorithm,
    nonce_i: &[u8],
    nonce_r: &[u8],
    shared_secret: &[u8],
    spi_i: &[u8; 8],
    spi_r: &[u8; 8],
) -> KeyMaterial {
    // Step 1: Compute SKEYSEED
    let key = [nonce_i, nonce_r].concat();
    let skeyseed = prf_alg.compute(&key, shared_secret);

    // Step 2: Derive SK_* keys
    let seed = [nonce_i, nonce_r, spi_i, spi_r].concat();
    let keymat = prf_plus(&skeyseed, &seed, total_key_length);

    // Step 3: Split into individual keys
    KeyMaterial::from_bytes(&keymat)
}
```

---

### Stage 4: Authentication (PSK & Certificates) (Week 6) ✅ PARTIALLY COMPLETED

**Status**: ✅ PSK authentication completed
**Commits**: 4709061

**Goal**: Implement IKEv2 authentication methods

**Deliverables**:
- [x] PSK (Pre-Shared Key) authentication
- [x] AUTH payload generation/verification
- [x] Constant-time comparison for security
- [x] Initiator/Responder signed octets construction
- [ ] Digital signature authentication (RSA, ECDSA) - deferred
- [ ] Certificate validation (X.509) - deferred
- [x] Unit tests (10 tests - PSK authentication)

**Success Criteria**:
- ✅ Compute AUTH payload according to RFC 7296 Section 2.15
- ✅ Verify AUTH with constant-time comparison
- ✅ Support all PRF algorithms (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
- ⏳ Authenticate with strongSwan using PSK (requires exchange implementation)
- ⏳ Authenticate with strongSwan using certificates (deferred)

**Actual Implementation** (4709061):
- PSK authentication module with 10 comprehensive tests
- `compute_psk_auth()` - AUTH payload computation
- `verify_psk_auth()` - Constant-time verification
- `construct_initiator_signed_octets()` - Initiator authentication data
- `construct_responder_signed_octets()` - Responder authentication data

**Files Created**:
```
crates/proto/src/ipsec/ikev2/
└── auth.rs            # PSK authentication (333 lines, 10 tests)
```

**AUTH Payload Computation** (RFC 7296 Section 2.15):
```rust
// AUTH = prf(prf(SK_p, "Key Pad for IKEv2"), <SignedOctets>)
pub fn compute_psk_auth(
    prf_alg: PrfAlgorithm,
    sk_p: &[u8],
    signed_octets: &[u8],
) -> AuthPayload {
    let prf1 = prf_alg.compute(sk_p, KEY_PAD_IKEV2);
    let auth_data = prf_alg.compute(&prf1, signed_octets);
    AuthPayload::new(AuthMethod::SharedKeyMic, auth_data)
}

// InitiatorSignedOctets = RealMessage1 | NonceR | prf(SK_pi, IDi')
// ResponderSignedOctets = RealMessage2 | NonceI | prf(SK_pr, IDr')
```

**Security Features**:
- Constant-time comparison prevents timing attacks
- Proper length validation before comparison
- Zero unsafe code

---

### Stage 5: ESP Protocol Implementation (Week 7-8)

**Goal**: Implement ESP packet processing

**Deliverables**:
- [ ] ESP packet structure (SPI, Sequence, IV, Payload, Padding, ICV)
- [ ] Encapsulation (plaintext → ESP packet)
- [ ] Decapsulation (ESP packet → plaintext)
- [ ] Sequence number management
- [ ] Anti-replay window (64-bit bitmap)
- [ ] Transport mode
- [ ] Tunnel mode
- [ ] Unit tests (25+)

**Success Criteria**:
- Encrypt/decrypt ESP packets correctly
- Prevent replay attacks
- Interoperate with strongSwan ESP

**Files to Create**:
```
crates/proto/src/ipsec/esp/
├── mod.rs
├── packet.rs          # ESP packet structure
├── encap.rs           # Encapsulation
├── decap.rs           # Decapsulation
├── seq.rs             # Sequence number
└── replay.rs          # Anti-replay window
```

**ESP Packet Format**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Security Parameters Index (SPI)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Data (variable)                    |
~                                                               ~
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |     Padding (0-255 bytes)                     |
+-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  Pad Length   | Next Header   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Integrity Check Value-ICV   (variable)                |
~                                                               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Anti-Replay Algorithm**:
```rust
pub struct ReplayWindow {
    window_size: u32,
    highest_seq: u64,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false; // Reject seq 0
        }

        let diff = self.highest_seq.saturating_sub(seq);

        if diff >= self.window_size as u64 {
            return false; // Too old
        }

        if seq > self.highest_seq {
            // Advance window
            let shift = seq - self.highest_seq;
            self.bitmap <<= shift;
            self.bitmap |= 1;
            self.highest_seq = seq;
            true
        } else {
            // Check if already seen
            let bit = 1u64 << diff;
            if self.bitmap & bit != 0 {
                false // Replay
            } else {
                self.bitmap |= bit;
                true
            }
        }
    }
}
```

---

### Stage 6: SA Database & Lifetime Management (Week 9)

**Goal**: Implement Security Association management

**Deliverables**:
- [ ] SA database (IKE SA + Child SA storage)
- [ ] SA lifetime tracking (time & byte limits)
- [ ] Automatic rekeying (CREATE_CHILD_SA)
- [ ] SA deletion (DELETE payload)
- [ ] Unit tests (15+)

**Success Criteria**:
- SAs expire and rekey automatically
- Handle simultaneous rekeying gracefully

**Files to Create**:
```
crates/proto/src/ipsec/sa/
├── mod.rs
├── database.rs        # SA storage
├── lifetime.rs        # Lifetime tracking
├── rekey.rs           # Rekeying logic
└── selector.rs        # Traffic selectors
```

**SA Lifecycle**:
```
CREATING → ESTABLISHED → REKEYING → DELETING → DELETED
            ↓ (soft lifetime)
            └→ CREATE_CHILD_SA
```

---

### Stage 7: NAT Traversal & Production Hardening (Week 10)

**Goal**: NAT-T support and production readiness

**Deliverables**:
- [ ] NAT detection (NAT_DETECTION_*_IP payloads)
- [ ] UDP encapsulation (port 4500)
- [ ] Keepalive packets
- [ ] Error handling improvements
- [ ] Performance optimization
- [ ] Comprehensive integration tests (20+)

**Success Criteria**:
- Work behind NAT with strongSwan
- Handle all error conditions gracefully
- Performance: >500 Mbps throughput (ESP)

**Files to Create**:
```
crates/proto/src/ipsec/
├── nat.rs             # NAT traversal
├── keepalive.rs       # Keepalive mechanism
└── perf.rs            # Performance optimizations
```

**NAT Detection**:
```rust
// Compute NAT_DETECTION hash
let hash = prf(
    SK_*,
    SPIi | SPIr | IP_src | Port_src
);

// If hash doesn't match, NAT detected
```

---

## Code Reuse from SSH Module

### Direct Reuse (70%)

| Component | SSH Module | IPSec Usage |
|-----------|------------|-------------|
| **Crypto** | `ssh/crypto.rs` | ESP encryption |
| ChaCha20-Poly1305 | ✅ | ESP AEAD |
| AES-GCM | ✅ | ESP AEAD, IKE encryption |
| HMAC-SHA2 | ✅ | PRF, integrity |
| **Key Exchange** | `ssh/kex.rs` | IKEv2 DH |
| Curve25519 | ✅ | DH Group 31 |
| DH Group14 | ✅ | DH Group 14 |
| **Encoding** | `ssh/packet.rs` | IKE message encoding |
| Binary parsing | ✅ | Payload parsing |
| **Async I/O** | `ssh/client.rs` | IKE/ESP I/O |
| Tokio UDP | ✅ (adapt from TCP) | IKE transport |

### New Components (30%)

- IKEv2 specific payloads
- ESP packet structure
- SA database
- Traffic selectors
- NAT traversal

---

## Testing Strategy

### Unit Tests (150+ tests)
- Protocol parsing/serialization
- Cryptographic operations
- State machine transitions
- SA lifecycle

### Integration Tests (30+ tests)
- Full IKE_SA_INIT exchange
- Full IKE_AUTH exchange
- ESP encapsulation/decapsulation
- Rekeying scenarios
- Error conditions

### Interoperability Tests
Test against:
- strongSwan 5.9+
- libreswan 4.x
- Cisco IOS

Test scenarios:
```bash
# strongSwan configuration
conn fynx-test
    keyexchange=ikev2
    ike=aes256gcm16-prfsha256-ecp256!
    esp=aes256gcm16!
    authby=secret
    left=%any
    right=192.168.1.100
    auto=add
```

### Performance Benchmarks
```rust
#[bench]
fn bench_esp_encrypt(b: &mut Bencher) {
    let mut esp = EspSession::new(/* ... */);
    let data = vec![0u8; 1400]; // MTU-sized packet

    b.iter(|| {
        esp.encrypt(&data)
    });
}
```

Target: >500 Mbps for ESP on modern CPU

---

## Dependencies

### New Dependencies

```toml
[dependencies]
# Existing (from SSH)
tokio = { version = "1.35", features = ["net", "sync", "time"] }
bytes = "1.5"
ring = "0.17"
sha2 = "0.10"
hmac = "0.12"

# New for IPSec
x509-parser = "0.16"       # Certificate parsing
der-parser = "9.0"         # DER encoding
oid-registry = "0.7"       # OID handling
```

### Optional Dependencies
```toml
[dev-dependencies]
criterion = "0.5"          # Benchmarking
hex = "0.4"                # Test utilities
```

---

## Supported Algorithms

### IKEv2 Algorithms

**Encryption**:
- ✅ AES-128-GCM-16
- ✅ AES-256-GCM-16
- ✅ ChaCha20-Poly1305

**PRF**:
- ✅ PRF-HMAC-SHA2-256
- ✅ PRF-HMAC-SHA2-512

**Integrity** (for non-AEAD):
- ✅ HMAC-SHA2-256-128
- ✅ HMAC-SHA2-512-256

**DH Groups**:
- ✅ Group 14 (2048-bit MODP)
- ✅ Group 31 (Curve25519)

### ESP Algorithms

**Combined Mode** (AEAD):
- ✅ AES-128-GCM-16
- ✅ AES-256-GCM-16
- ✅ ChaCha20-Poly1305

**Encryption + Integrity**:
- ✅ AES-128-CBC + HMAC-SHA2-256
- ✅ AES-256-CBC + HMAC-SHA2-512

---

## Risk Assessment

### Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| RFC complexity | High | Medium | Incremental implementation, extensive testing |
| Interop issues | High | Medium | Early testing with strongSwan |
| Performance | Medium | Low | Benchmark early, optimize later |
| Crypto bugs | Critical | Low | Reuse vetted libraries, fuzz testing |

### Schedule Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Underestimated complexity | Medium | 20% buffer time built in |
| Testing delays | Low | Continuous integration testing |

---

## Success Metrics

### Functional Metrics
- ✅ 100% RFC 7296 compliance (IKEv2 core features)
- ✅ 100% RFC 4303 compliance (ESP)
- ✅ Interop with strongSwan, libreswan
- ✅ All test cases passing

### Quality Metrics
- ✅ Zero unsafe code
- ✅ >90% code coverage
- ✅ Zero clippy warnings
- ✅ 100% rustdoc coverage

### Performance Metrics
- ✅ IKE handshake: <200ms (localhost)
- ✅ ESP throughput: >500 Mbps (AES-GCM)
- ✅ Memory: <20MB per SA pair

---

## Deliverables

### Code Artifacts
```
crates/proto/src/ipsec/
├── mod.rs                 # Module root
├── error.rs               # Error types
├── ikev2/                 # IKEv2 implementation
│   ├── mod.rs
│   ├── message.rs
│   ├── payload.rs
│   ├── state.rs
│   ├── exchange.rs
│   ├── auth.rs
│   └── ...
├── esp/                   # ESP implementation
│   ├── mod.rs
│   ├── packet.rs
│   ├── encap.rs
│   ├── decap.rs
│   └── ...
├── crypto/                # Crypto operations
│   ├── mod.rs
│   ├── prf.rs
│   ├── kdf.rs
│   └── ...
├── sa/                    # SA management
│   ├── mod.rs
│   ├── database.rs
│   └── ...
└── nat.rs                 # NAT traversal

crates/proto/examples/
├── ipsec_client.rs        # Example VPN client
└── ipsec_server.rs        # Example VPN server

crates/proto/tests/
└── ipsec_integration.rs   # Integration tests
```

### Documentation
- ✅ API documentation (rustdoc)
- ✅ User guide (docs/ipsec/USER_GUIDE.md)
- ✅ Interop testing report (docs/ipsec/INTEROP.md)
- ✅ Performance benchmarks (docs/ipsec/BENCHMARKS.md)

---

## Timeline Summary

| Week | Stage | Deliverable | Tests |
|------|-------|-------------|-------|
| 1-2  | Stage 1 | IKEv2 parsing | 30+ |
| 3-4  | Stage 2 | State machine | 15+ |
| 5    | Stage 3 | Crypto/KDF | 20+ |
| 6    | Stage 4 | Authentication | 12+ |
| 7-8  | Stage 5 | ESP protocol | 25+ |
| 9    | Stage 6 | SA management | 15+ |
| 10   | Stage 7 | NAT-T & polish | 20+ |

**Total**: 137+ unit tests, 30+ integration tests

---

## References

### RFCs
- [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296) - IKEv2 Protocol
- [RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303) - ESP Protocol
- [RFC 3948](https://datatracker.ietf.org/doc/html/rfc3948) - NAT Traversal
- [RFC 5996](https://datatracker.ietf.org/doc/html/rfc5996) - IKEv2 (obsoleted by 7296)
- [RFC 4106](https://datatracker.ietf.org/doc/html/rfc4106) - AES-GCM for ESP

### Implementation References
- [strongSwan](https://www.strongswan.org/) - Open source IPSec
- [libreswan](https://libreswan.org/) - Linux IPSec
- [VPP IPSec](https://fd.io/) - High-performance IPSec

### Testing Tools
- `ip xfrm` - Linux kernel IPSec interface
- `tcpdump` - Packet capture
- `wireshark` - Protocol analysis

---

**Document Version**: 1.0
**Created**: 2025-10-24
**Last Updated**: 2025-10-24
**Status**: ✅ Ready for Implementation
