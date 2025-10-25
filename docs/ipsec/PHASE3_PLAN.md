# IPSec Phase 3 Implementation Plan

**Date**: 2025-10-25
**Phase**: Phase 3 - Child SA and ESP Protocol
**Status**: 📋 Planning

---

## Executive Summary

Phase 3 will implement Child SA management and the ESP (Encapsulating Security Payload) protocol, completing the core IPSec data plane functionality. This builds upon the IKE control plane established in Phases 1 and 2.

**Key Deliverables**:
1. Child SA structure and lifecycle management
2. CREATE_CHILD_SA exchange implementation
3. ESP protocol (packet encapsulation/decapsulation)
4. Child SA rekeying mechanism

---

## Prerequisites (Completed in Phase 2)

✅ IKE_SA_INIT exchange (Phase 1)
✅ IKE_AUTH exchange (Phase 2)
✅ SK_d key derivation (for Child SA keys)
✅ Traffic Selector negotiation
✅ PSK authentication

---

## Goals

### Primary Goals
1. Implement Child SA structure and storage
2. Implement CREATE_CHILD_SA exchange handlers
3. Implement ESP packet format and processing
4. Implement Child SA key derivation from SK_d
5. Implement anti-replay protection
6. Implement Child SA rekeying

### Non-Goals (Deferred to Phase 4)
- NAT-T (NAT traversal)
- INFORMATIONAL exchange
- Configuration payloads
- Certificate authentication
- IKE SA rekeying

---

## Architecture Overview

### Component Hierarchy

```
IKE SA (Control Plane - UDP 500)
  ├── IKE_SA_INIT exchange (Phase 1) ✅
  ├── IKE_AUTH exchange (Phase 2) ✅
  ├── CREATE_CHILD_SA exchange (Phase 3) ⏳
  └── Child SAs (Data Plane - IP Protocol 50)
      ├── Inbound SA
      │   ├── SPI (Security Parameters Index)
      │   ├── Keys (SK_ei, SK_ai)
      │   ├── Sequence number tracking
      │   └── Anti-replay window
      └── Outbound SA
          ├── SPI
          ├── Keys (SK_er, SK_ar)
          └── Sequence number counter
```

### Data Structures

```rust
// Child SA structure
pub struct ChildSa {
    /// Security Parameters Index (SPI)
    pub spi: u32,

    /// Protocol (ESP = 50)
    pub protocol: u8,

    /// Encryption key
    pub sk_e: Vec<u8>,

    /// Authentication key (if non-AEAD)
    pub sk_a: Option<Vec<u8>>,

    /// Traffic selectors (initiator)
    pub ts_i: TrafficSelectorsPayload,

    /// Traffic selectors (responder)
    pub ts_r: TrafficSelectorsPayload,

    /// Selected proposal
    pub proposal: Proposal,

    /// Sequence number (outbound)
    pub seq_out: u64,

    /// Anti-replay window (inbound)
    pub replay_window: ReplayWindow,

    /// Lifetime (soft/hard)
    pub lifetime: SaLifetime,

    /// Creation time
    pub created_at: std::time::Instant,
}

// ESP packet structure
pub struct EspPacket {
    /// Security Parameters Index
    pub spi: u32,

    /// Sequence number
    pub seq: u32,

    /// Initialization Vector
    pub iv: Vec<u8>,

    /// Encrypted payload data
    pub encrypted_data: Vec<u8>,

    /// Integrity Check Value (if non-AEAD)
    pub icv: Option<Vec<u8>>,
}

// Anti-replay window
pub struct ReplayWindow {
    /// Window size (default: 64)
    window_size: u32,

    /// Highest sequence number received
    highest_seq: u64,

    /// Bitmap of received packets
    bitmap: u64,
}
```

---

## Implementation Stages

### Stage 1: Child SA Structure (2-3 hours)

**Goal**: Define Child SA data structures and lifecycle

**Deliverables**:
- Child SA structure
- SA lifetime tracking
- Child SA database/storage
- Helper methods for key access

**Files to Create**:
```
crates/proto/src/ipsec/
├── child_sa.rs           # Child SA structure and methods
└── sa_lifetime.rs        # Lifetime tracking
```

**Tests** (10+ tests):
- Child SA creation
- Key derivation from SK_d
- Lifetime tracking (time-based)
- SPI generation and uniqueness

**Success Criteria**:
- ✅ Child SA structure defined
- ✅ Lifetime calculations correct
- ✅ Keys properly derived from SK_d

---

### Stage 2: CREATE_CHILD_SA Exchange (4-6 hours)

**Goal**: Implement CREATE_CHILD_SA exchange handlers

**RFC 7296 Section 1.3**: CREATE_CHILD_SA exchange creates Child SAs or rekeys existing SAs

**Exchange Flow**:
```
Initiator                   Responder
---------                   ---------
HDR, SK {SA, Ni, [KEi],  →
         TSi, TSr}

                         ←  HDR, SK {SA, Nr, [KEr],
                                    TSi, TSr}
```

**Deliverables**:
- `CreateChildSaExchange` structure
- `create_request()` - Build encrypted request
- `process_request()` - Decrypt, validate, derive child keys
- `create_response()` - Build encrypted response with selected proposal
- `process_response()` - Decrypt, validate, derive child keys, transition

**Files to Modify**:
```
crates/proto/src/ipsec/ikev2/
└── exchange.rs           # Add CreateChildSaExchange
```

**Payload Chain**:
- **Request**: SA (child proposals), Ni (nonce), KEi (optional DH), TSi, TSr
- **Response**: SA (selected proposal), Nr (nonce), KEr (optional DH), TSi, TSr

**Tests** (15+ tests):
- Request creation
- Request processing
- Response creation
- Response processing
- Proposal negotiation
- Traffic selector narrowing
- PFS (Perfect Forward Secrecy) with KEi/KEr
- Non-PFS (reuse IKE SA keys)

**Success Criteria**:
- ✅ CREATE_CHILD_SA request/response creation
- ✅ Child SA keys derived correctly (KEYMAT)
- ✅ Traffic selectors validated and narrowed
- ✅ Optional DH exchange for PFS

**Key Derivation** (RFC 7296 Section 2.17):
```rust
// KEYMAT = prf+(SK_d, Ni | Nr)
// For PFS: KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)

pub fn derive_child_sa_keys(
    prf_alg: PrfAlgorithm,
    sk_d: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    shared_secret: Option<&[u8]>, // For PFS
    encr_key_len: usize,
    integ_key_len: usize,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let seed = if let Some(secret) = shared_secret {
        // PFS: Include new DH shared secret
        [secret, nonce_i, nonce_r].concat()
    } else {
        // No PFS: Use nonces only
        [nonce_i, nonce_r].concat()
    };

    let keymat = prf_plus(prf_alg, sk_d, &seed, total_len);

    // Split: SK_ei | SK_ai | SK_er | SK_ar
    (sk_ei, sk_ai, sk_er, sk_ar)
}
```

---

### Stage 3: ESP Protocol Implementation (3-4 hours)

**Goal**: Implement ESP packet encapsulation and decapsulation

**RFC 4303**: Encapsulating Security Payload

**ESP Packet Format**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
|               Security Parameters Index (SPI)                 |  ^
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
|                      Sequence Number                          |  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
|                  Initialization Vector (IV)                   | Auth
~                          (optional)                           ~  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
|                    Payload Data (variable)                    |  |
~                                                               ~  |
|                                                               |  |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
|               |     Padding (0-255 bytes)                     |  |
+-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
|                               |  Pad Length   | Next Header   |  v
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ---
|         Integrity Check Value-ICV   (variable)                |
~                                                               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Deliverables**:
- ESP packet structure
- `encapsulate()` - Plaintext → ESP packet
- `decapsulate()` - ESP packet → Plaintext
- Padding calculation
- ICV/AEAD tag handling

**Files to Create**:
```
crates/proto/src/ipsec/
└── esp.rs                # ESP protocol implementation
```

**Tests** (15+ tests):
- ESP header parsing
- AEAD encapsulation (AES-GCM)
- AEAD decapsulation
- Non-AEAD encapsulation (AES-CBC + HMAC)
- Padding calculation (block size alignment)
- Sequence number increment
- Invalid packet rejection

**Success Criteria**:
- ✅ ESP packets correctly formatted
- ✅ Encryption/decryption with Child SA keys
- ✅ AEAD and non-AEAD modes supported
- ✅ Proper padding added/removed

**Encapsulation Example**:
```rust
pub fn encapsulate(
    child_sa: &mut ChildSa,
    plaintext: &[u8],
    next_header: u8,
) -> Result<Vec<u8>> {
    // 1. Increment sequence number
    child_sa.seq_out += 1;

    // 2. Generate IV
    let iv = generate_random_iv(child_sa.proposal.cipher.iv_len());

    // 3. Add padding
    let block_size = child_sa.proposal.cipher.block_size();
    let pad_len = calculate_padding(plaintext.len(), block_size);
    let mut payload = plaintext.to_vec();
    payload.extend(vec![0u8; pad_len]);
    payload.push(pad_len as u8);
    payload.push(next_header);

    // 4. Encrypt with AEAD or cipher+HMAC
    let encrypted = if child_sa.proposal.cipher.is_aead() {
        // AEAD: ciphertext includes auth tag
        let aad = build_esp_aad(child_sa.spi, child_sa.seq_out);
        child_sa.proposal.cipher.encrypt(
            &child_sa.sk_e,
            &iv,
            &payload,
            &aad,
        )?
    } else {
        // Non-AEAD: encrypt then authenticate
        let ciphertext = child_sa.proposal.cipher.encrypt(
            &child_sa.sk_e,
            &iv,
            &payload,
        )?;
        let icv = compute_icv(
            &child_sa.sk_a.unwrap(),
            child_sa.spi,
            child_sa.seq_out,
            &iv,
            &ciphertext,
        );
        [ciphertext, icv].concat()
    };

    // 5. Build ESP packet
    let mut packet = Vec::new();
    packet.extend_from_slice(&child_sa.spi.to_be_bytes());
    packet.extend_from_slice(&(child_sa.seq_out as u32).to_be_bytes());
    packet.extend_from_slice(&iv);
    packet.extend_from_slice(&encrypted);

    Ok(packet)
}
```

---

### Stage 4: Anti-Replay Protection (1-2 hours)

**Goal**: Implement anti-replay window for inbound packets

**RFC 4303 Section 3.4.3**: Anti-Replay mechanism

**Deliverables**:
- Replay window structure
- `check_and_update()` - Check sequence number, update window
- Window sliding logic

**Files to Create**:
```
crates/proto/src/ipsec/
└── replay.rs             # Anti-replay window
```

**Tests** (10+ tests):
- Accept new packets
- Reject duplicate packets
- Reject old packets (outside window)
- Window sliding
- Edge cases (seq=0, wraparound)

**Success Criteria**:
- ✅ Prevent replay attacks
- ✅ Window size configurable (default: 64)
- ✅ Efficient bitmap implementation

**Algorithm**:
```rust
impl ReplayWindow {
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        // RFC 4303: Sequence number 0 is invalid
        if seq == 0 {
            return false;
        }

        // Calculate difference from highest sequence
        let diff = self.highest_seq.saturating_sub(seq);

        // Packet too old (outside window)
        if diff >= self.window_size as u64 {
            return false;
        }

        if seq > self.highest_seq {
            // Advance window
            let shift = seq - self.highest_seq;
            self.bitmap <<= shift.min(64);
            self.bitmap |= 1;
            self.highest_seq = seq;
            true
        } else {
            // Within window, check if already seen
            let bit_pos = diff;
            let mask = 1u64 << bit_pos;
            if self.bitmap & mask != 0 {
                false // Duplicate
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}
```

---

### Stage 5: Child SA Rekeying (1-2 hours)

**Goal**: Implement Child SA rekeying using CREATE_CHILD_SA

**Deliverables**:
- Rekey trigger logic (lifetime check)
- REKEY_SA notify payload
- Overlapping SA handling
- Old SA deletion

**Files to Modify**:
```
crates/proto/src/ipsec/
├── child_sa.rs           # Add rekey methods
└── sa_lifetime.rs        # Add lifetime checks
```

**Tests** (10+ tests):
- Lifetime expiration detection
- Rekey initiation
- Overlapping SA handling
- Old SA deletion after rekey

**Success Criteria**:
- ✅ Automatic rekeying before hard lifetime
- ✅ Overlap period for seamless transition
- ✅ Proper SA deletion

**Rekeying Flow**:
```
Time:  0s        75s       90s       100s
       |---------|---------|---------|
       [  Child SA 1 Active         ]
                 |   [  Overlap  ]  |
                 |   [Child SA 2]   |
                 ^                  ^
            Soft Limit         Hard Limit
           (Initiate Rekey)   (Delete SA 1)
```

---

## Testing Strategy

### Unit Tests (60+ tests)

**Child SA** (10 tests):
- Creation, key derivation, lifetime

**CREATE_CHILD_SA** (15 tests):
- Request/response creation/processing
- Proposal negotiation
- PFS and non-PFS modes

**ESP** (15 tests):
- Encapsulation/decapsulation
- AEAD and non-AEAD
- Padding

**Anti-Replay** (10 tests):
- Window operations
- Edge cases

**Rekeying** (10 tests):
- Lifetime checks
- Rekey flow
- Overlap handling

### Integration Tests (5+ tests)

1. Complete IKE_SA_INIT → IKE_AUTH → CREATE_CHILD_SA flow
2. ESP packet roundtrip (encrypt → decrypt)
3. Anti-replay window in realistic scenario
4. Child SA rekeying end-to-end
5. Multiple Child SAs with different traffic selectors

---

## Timeline

**Estimated Total**: 8-12 hours

| Stage | Time | Deliverable |
|-------|------|-------------|
| 1. Child SA Structure | 2-3 hours | Data structures, storage |
| 2. CREATE_CHILD_SA | 4-6 hours | Exchange handlers |
| 3. ESP Protocol | 3-4 hours | Encapsulation/decapsulation |
| 4. Anti-Replay | 1-2 hours | Replay window |
| 5. Rekeying | 1-2 hours | Rekey logic |
| Documentation | 1 hour | Completion report |

---

## Dependencies

### Existing Code to Reuse
- ✅ `CipherAlgorithm` (from Phase 2) - For ESP encryption
- ✅ `PrfAlgorithm` (from Phase 2) - For key derivation
- ✅ `TrafficSelectorsPayload` (from Phase 2) - Traffic selectors
- ✅ `SK_d` key (from Phase 2) - Child SA key derivation
- ✅ `IkeMessage` and payload parsing (from Phase 1)

### New Dependencies
None - All crypto primitives already available

---

## Success Metrics

### Functional
- ✅ CREATE_CHILD_SA exchange working
- ✅ ESP packets encrypt/decrypt correctly
- ✅ Anti-replay prevents duplicate packets
- ✅ Child SA rekeying seamless

### Quality
- ✅ Zero unsafe code
- ✅ 90%+ test coverage
- ✅ All tests passing
- ✅ RFC 4303 compliance (ESP)
- ✅ RFC 7296 compliance (CREATE_CHILD_SA)

### Performance
- ✅ ESP encapsulation: <10 μs per packet
- ✅ ESP decapsulation: <10 μs per packet
- ✅ Replay check: <1 μs

---

## References

### RFCs
- **RFC 7296 Section 1.3**: CREATE_CHILD_SA Exchange
- **RFC 7296 Section 2.17**: Generating Keying Material for Child SAs
- **RFC 4303**: IP Encapsulating Security Payload (ESP)
- **RFC 4303 Section 3.4.3**: Sequence Number Verification (Anti-Replay)

### Code Examples
- strongSwan: `src/libcharon/sa/child_sa.c`
- libreswan: `programs/pluto/ikev2_child.c`

---

**Document Version**: 1.0
**Created**: 2025-10-25
**Status**: 📋 Ready for Implementation
