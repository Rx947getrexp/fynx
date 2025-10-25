# IPSec Phase 4 Implementation Plan

**Date**: 2025-10-25
**Phase**: Phase 4 - Advanced Features and IKE SA Management
**Status**: 📋 Planning
**Priority**: High

---

## Executive Summary

Phase 4 will implement advanced IPSec features and complete IKE SA management, building upon the Child SA and ESP protocol foundation from Phase 3. This phase focuses on production deployment requirements including NAT traversal, informational exchanges, and IKE SA lifecycle management.

**Key Deliverables**:
1. NAT-T (NAT Traversal) - RFC 3948
2. INFORMATIONAL exchange - DELETE and NOTIFY payloads
3. IKE SA rekeying mechanism
4. Dead Peer Detection (DPD)
5. Error handling and recovery

---

## Prerequisites (Completed in Phase 3)

✅ Child SA structure and lifecycle (Phase 3)
✅ CREATE_CHILD_SA exchange (Phase 3)
✅ ESP protocol implementation (Phase 3)
✅ Anti-replay protection (Phase 3)
✅ Child SA rekeying (Phase 3)

---

## Goals

### Primary Goals
1. Implement NAT-T for UDP encapsulation
2. Implement INFORMATIONAL exchange handlers
3. Implement IKE SA rekeying
4. Implement Dead Peer Detection (DPD)
5. Add comprehensive error recovery

### Secondary Goals
- Configuration payloads (CP)
- Multiple authentication methods (EAP)
- Traffic selector narrowing
- Cookie challenge for DoS protection

### Non-Goals (Future Phases)
- Certificate authentication (deferred to Phase 5)
- IPv6 support enhancements
- Mobility extensions (MOBIKE)
- IKEv1 compatibility

---

## Architecture Overview

### Phase 4 Components

```
IKE SA (Control Plane)
  ├── IKE_SA_INIT (Phase 1) ✅
  ├── IKE_AUTH (Phase 2) ✅
  ├── CREATE_CHILD_SA (Phase 3) ✅
  ├── INFORMATIONAL (Phase 4) ⏳
  │   ├── DELETE payload
  │   ├── NOTIFY payload
  │   └── Error handling
  ├── IKE SA Rekeying (Phase 4) ⏳
  │   └── CREATE_CHILD_SA for IKE SA
  └── Dead Peer Detection (Phase 4) ⏳
      └── Keepalive mechanism

ESP Data Plane (Phase 3) ✅
  ├── NAT-T (Phase 4) ⏳
  │   ├── UDP encapsulation
  │   ├── Non-ESP marker
  │   └── Port floating
  └── ESP packets ✅
```

---

## Stage Breakdown

### Stage 1: NAT-T Implementation (3-4 hours)

**Goal**: Implement UDP encapsulation for NAT traversal per RFC 3948

**Background**:
NAT (Network Address Translation) breaks IPSec because:
- NAT modifies IP headers, breaking ESP authentication
- NAT devices drop ESP packets (IP protocol 50)
- Firewalls may block ESP

NAT-T solves this by:
- Encapsulating ESP in UDP (port 4500)
- Detecting NAT presence during IKE_SA_INIT
- Floating to port 4500 after NAT detection

**Deliverables**:

1. **NAT Detection (IKE_SA_INIT)**:
```rust
pub struct NatDetection {
    /// SHA-1(SPIi | SPIr | IP_src | Port_src)
    source_hash: [u8; 20],
    /// SHA-1(SPIi | SPIr | IP_dst | Port_dst)
    dest_hash: [u8; 20],
}

impl NatDetection {
    pub fn compute_hash(
        spi_i: u64,
        spi_r: u64,
        ip: IpAddr,
        port: u16,
    ) -> [u8; 20];

    pub fn detect_nat(
        local: &NatDetection,
        remote: &NatDetection,
    ) -> bool;
}
```

2. **UDP Encapsulation**:
```rust
pub struct UdpEncapsulation {
    /// Non-ESP marker (4 bytes of zeros)
    const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
}

impl UdpEncapsulation {
    /// Encapsulate IKE message in UDP
    pub fn encapsulate_ike(msg: &[u8]) -> Vec<u8> {
        // UDP header + Non-ESP marker + IKE message
    }

    /// Encapsulate ESP packet in UDP
    pub fn encapsulate_esp(packet: &[u8]) -> Vec<u8> {
        // UDP header + ESP packet (no marker)
    }

    /// Detect packet type (IKE or ESP)
    pub fn detect_packet_type(data: &[u8]) -> PacketType {
        // Check for Non-ESP marker
    }
}
```

3. **Port Floating**:
```rust
pub struct PortFloating {
    /// Initial port (500)
    initial_port: u16,
    /// NAT-T port (4500)
    nat_t_port: u16,
    /// NAT detected flag
    nat_detected: bool,
}

impl PortFloating {
    pub fn should_float(&self) -> bool;
    pub fn get_active_port(&self) -> u16;
}
```

**Files to Create/Modify**:
```
crates/proto/src/ipsec/
├── nat.rs              # NAT detection and UDP encapsulation (NEW)
├── ikev2/payload.rs    # Add NAT_DETECTION_* payloads
└── ikev2/exchange.rs   # Integrate NAT detection in IKE_SA_INIT
```

**Tests** (15+ tests):
- NAT detection hash computation
- NAT presence detection (4 scenarios)
- UDP encapsulation/decapsulation
- Non-ESP marker handling
- Port floating logic
- Packet type detection

**Success Criteria**:
- ✅ NAT detected correctly during IKE_SA_INIT
- ✅ Port floats from 500 to 4500 when NAT present
- ✅ ESP packets encapsulated in UDP correctly
- ✅ Non-ESP marker added to IKE messages

---

### Stage 2: INFORMATIONAL Exchange (2-3 hours)

**Goal**: Implement INFORMATIONAL exchange for DELETE and NOTIFY payloads

**Background**:
INFORMATIONAL exchange is used for:
- Deleting SAs (IKE SA or Child SA)
- Sending status notifications
- Error reporting
- Configuration updates

**Message Flow**:
```
Initiator                    Responder
---------                    ---------
HDR, SK {[N+], [D+]}  -->
                       <--  HDR, SK {[N+], [D+]}
```

**Deliverables**:

1. **DELETE Payload**:
```rust
pub struct DeletePayload {
    /// Protocol ID (IKE=1, ESP=3)
    pub protocol_id: u8,
    /// SPI size (0 for IKE SA, 4 for ESP)
    pub spi_size: u8,
    /// Number of SPIs
    pub num_spi: u16,
    /// List of SPIs to delete
    pub spis: Vec<u32>,
}

impl DeletePayload {
    /// Create DELETE for IKE SA
    pub fn delete_ike_sa() -> Self;

    /// Create DELETE for Child SA(s)
    pub fn delete_child_sa(spis: Vec<u32>) -> Self;

    /// Parse DELETE payload
    pub fn from_bytes(data: &[u8]) -> Result<Self>;

    /// Serialize DELETE payload
    pub fn to_bytes(&self) -> Vec<u8>;
}
```

2. **NOTIFY Payload**:
```rust
pub enum NotifyType {
    // Error types (1-16383)
    UnsupportedCriticalPayload = 1,
    InvalidIkeSpi = 4,
    InvalidMajorVersion = 5,
    InvalidSyntax = 7,
    InvalidMessageId = 9,
    NoProposalChosen = 14,
    // ...

    // Status types (16384-65535)
    InitialContact = 16384,
    SetWindowSize = 16385,
    AdditionalTssPossible = 16386,
    IpsecReplayCounter = 16387,
    // ...
}

pub struct NotifyPayload {
    /// Protocol ID (0=IKE, 3=ESP)
    pub protocol_id: u8,
    /// SPI size
    pub spi_size: u8,
    /// Notify message type
    pub notify_type: NotifyType,
    /// SPI (if applicable)
    pub spi: Option<Vec<u8>>,
    /// Notification data
    pub data: Vec<u8>,
}

impl NotifyPayload {
    pub fn error(notify_type: NotifyType) -> Self;
    pub fn status(notify_type: NotifyType) -> Self;
    pub fn from_bytes(data: &[u8]) -> Result<Self>;
    pub fn to_bytes(&self) -> Vec<u8>;
}
```

3. **INFORMATIONAL Exchange Handler**:
```rust
pub struct InformationalExchange {
    /// IKE SA reference
    ike_sa: IkeSa,
}

impl InformationalExchange {
    /// Create INFORMATIONAL request to delete SA
    pub fn create_delete_request(
        &self,
        sa_type: SaType,
        spis: Vec<u32>,
    ) -> Result<IkeMessage>;

    /// Create INFORMATIONAL request with NOTIFY
    pub fn create_notify_request(
        &self,
        notify: NotifyPayload,
    ) -> Result<IkeMessage>;

    /// Process INFORMATIONAL request
    pub fn process_request(
        &mut self,
        msg: &IkeMessage,
    ) -> Result<IkeMessage>;

    /// Process INFORMATIONAL response
    pub fn process_response(
        &mut self,
        msg: &IkeMessage,
    ) -> Result<()>;
}
```

**Files to Create/Modify**:
```
crates/proto/src/ipsec/
├── ikev2/informational.rs  # INFORMATIONAL exchange (NEW)
├── ikev2/payload.rs        # Add DELETE and NOTIFY payloads
├── ikev2/constants.rs      # Add NotifyType enum
└── ikev2/exchange.rs       # Integrate INFORMATIONAL handler
```

**Tests** (20+ tests):
- DELETE payload serialization/deserialization
- DELETE for IKE SA
- DELETE for single Child SA
- DELETE for multiple Child SAs
- NOTIFY payload serialization/deserialization
- Error NOTIFY types
- Status NOTIFY types
- INFORMATIONAL request creation
- INFORMATIONAL response processing
- Error handling

**Success Criteria**:
- ✅ Can delete IKE SA via INFORMATIONAL
- ✅ Can delete Child SA(s) via INFORMATIONAL
- ✅ NOTIFY payloads sent/received correctly
- ✅ Errors reported via NOTIFY

---

### Stage 3: IKE SA Rekeying (2-3 hours)

**Goal**: Implement IKE SA rekeying using CREATE_CHILD_SA

**Background**:
IKE SA rekeying is similar to Child SA rekeying but:
- Uses CREATE_CHILD_SA exchange
- Negotiates new IKE SA (not Child SA)
- Moves all Child SAs to new IKE SA
- Deletes old IKE SA after transition

**Rekeying Flow**:
```
Time:  0s        50min     60min
       |-----------|---------|
       [  IKE SA 1 Active   ]
                   | [ Overlap ] |
                   | [IKE SA 2]  |
                   ^             ^
              Soft Limit    Hard Limit
           (Initiate Rekey) (Delete SA 1)
```

**Deliverables**:

1. **IKE SA Lifetime**:
```rust
pub struct IkeSa {
    // Existing fields...

    /// Lifetime configuration
    pub lifetime: SaLifetime,
    /// Creation timestamp
    pub created_at: Instant,
    /// State for rekeying
    pub state: IkeSaState,
    /// Rekey timestamp
    pub rekey_initiated_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeSaState {
    Active,
    Rekeying,
    Rekeyed,
    Deleted,
}
```

2. **IKE SA Rekeying Methods**:
```rust
impl IkeSa {
    /// Check if IKE SA should be rekeyed
    pub fn should_rekey(&self) -> bool {
        self.lifetime.is_soft_expired(self.age(), 0)
    }

    /// Initiate IKE SA rekey
    pub fn initiate_rekey(&mut self) -> Result<()> {
        // State: Active → Rekeying
    }

    /// Mark IKE SA as rekeyed
    pub fn mark_rekeyed(&mut self) -> Result<()> {
        // State: Rekeying → Rekeyed
    }

    /// Move Child SAs to new IKE SA
    pub fn transfer_child_sas(
        &mut self,
        new_ike_sa: &mut IkeSa,
    ) -> Result<()>;
}
```

3. **CREATE_CHILD_SA for IKE SA**:
```rust
impl CreateChildSaExchange {
    /// Create request to rekey IKE SA (not Child SA)
    pub fn create_ike_rekey_request(
        &self,
        ike_sa: &IkeSa,
    ) -> Result<IkeMessage> {
        // SA payload with IKE proposals (not ESP)
        // Nonce, KE, optional NOTIFY
    }

    /// Process IKE SA rekey request
    pub fn process_ike_rekey_request(
        &mut self,
        msg: &IkeMessage,
    ) -> Result<IkeMessage>;
}
```

**Files to Modify**:
```
crates/proto/src/ipsec/
├── ikev2/state.rs          # Add IkeSaState enum
├── ikev2/exchange.rs       # Add IKE SA rekey methods
└── child_sa.rs             # Add transfer logic
```

**Tests** (15+ tests):
- IKE SA lifetime expiration
- Rekey initiation
- State transitions
- Child SA transfer
- Old IKE SA deletion
- CREATE_CHILD_SA for IKE SA (different from Child SA)

**Success Criteria**:
- ✅ IKE SA rekeyed before hard lifetime
- ✅ All Child SAs transferred to new IKE SA
- ✅ Old IKE SA deleted gracefully
- ✅ No interruption to data traffic

---

### Stage 4: Dead Peer Detection (1-2 hours)

**Goal**: Implement DPD for detecting disconnected peers

**Background**:
DPD detects when peer is unreachable by:
- Sending INFORMATIONAL with empty NOTIFY
- Expecting response within timeout
- Marking peer as dead if no response

**Deliverables**:

1. **DPD Configuration**:
```rust
pub struct DpdConfig {
    /// Enable DPD
    pub enabled: bool,
    /// Interval between DPD checks (default: 30s)
    pub interval: Duration,
    /// Timeout for response (default: 10s)
    pub timeout: Duration,
    /// Max retries before marking dead (default: 3)
    pub max_retries: u32,
}
```

2. **DPD State Tracking**:
```rust
pub struct DpdState {
    /// Last DPD request sent
    pub last_sent: Option<Instant>,
    /// Waiting for response
    pub waiting: bool,
    /// Retry count
    pub retries: u32,
    /// Message ID of last DPD request
    pub message_id: u32,
}

impl DpdState {
    /// Should send DPD check now?
    pub fn should_send(&self, config: &DpdConfig) -> bool;

    /// Record DPD request sent
    pub fn mark_sent(&mut self, msg_id: u32);

    /// Record DPD response received
    pub fn mark_received(&mut self);

    /// Check if peer is dead
    pub fn is_dead(&self, config: &DpdConfig) -> bool;
}
```

3. **DPD Integration**:
```rust
impl IkeSa {
    /// DPD configuration
    pub dpd_config: DpdConfig,
    /// DPD state
    pub dpd_state: DpdState,

    /// Create DPD INFORMATIONAL request
    pub fn create_dpd_request(&mut self) -> Result<IkeMessage> {
        // Empty INFORMATIONAL with NOTIFY
    }

    /// Process DPD request
    pub fn process_dpd_request(
        &self,
        msg: &IkeMessage,
    ) -> Result<IkeMessage> {
        // Echo response
    }

    /// Check DPD status
    pub fn check_dpd(&mut self) -> DpdStatus {
        if self.dpd_state.should_send(&self.dpd_config) {
            DpdStatus::SendRequest
        } else if self.dpd_state.is_dead(&self.dpd_config) {
            DpdStatus::Dead
        } else {
            DpdStatus::Alive
        }
    }
}
```

**Files to Create/Modify**:
```
crates/proto/src/ipsec/
├── dpd.rs              # DPD implementation (NEW)
└── ikev2/state.rs      # Integrate DPD state
```

**Tests** (10+ tests):
- DPD configuration
- DPD timing
- DPD request creation
- DPD response processing
- Retry logic
- Dead peer detection

**Success Criteria**:
- ✅ DPD requests sent periodically
- ✅ Responses detected correctly
- ✅ Dead peer marked after timeout
- ✅ Configurable intervals and retries

---

### Stage 5: Error Handling and Recovery (1-2 hours)

**Goal**: Robust error handling and automatic recovery

**Deliverables**:

1. **Error Recovery Strategies**:
```rust
pub enum RecoveryAction {
    /// Retry the operation
    Retry { max_attempts: u32, delay: Duration },
    /// Send NOTIFY error to peer
    NotifyPeer(NotifyType),
    /// Delete the SA
    DeleteSa,
    /// Reset connection
    Reset,
    /// No action (ignore)
    Ignore,
}

pub struct ErrorHandler {
    /// Map error types to recovery actions
    strategies: HashMap<ErrorKind, RecoveryAction>,
}

impl ErrorHandler {
    pub fn handle_error(
        &self,
        error: &Error,
    ) -> RecoveryAction;
}
```

2. **Automatic Retry Logic**:
```rust
pub struct RetryPolicy {
    /// Max retry attempts
    pub max_attempts: u32,
    /// Base delay between retries
    pub base_delay: Duration,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f32,
    /// Max delay cap
    pub max_delay: Duration,
}

impl RetryPolicy {
    pub fn should_retry(&self, attempt: u32) -> bool;
    pub fn get_delay(&self, attempt: u32) -> Duration;
}
```

3. **State Validation**:
```rust
impl IkeSa {
    /// Validate SA state before operations
    pub fn validate_state(&self) -> Result<()> {
        // Check state machine consistency
        // Check lifetime expiration
        // Check message ID sequence
    }

    /// Recover from invalid state
    pub fn recover_state(&mut self) -> Result<()> {
        // Attempt to repair inconsistencies
        // Or delete SA if unrecoverable
    }
}
```

**Files to Create/Modify**:
```
crates/proto/src/ipsec/
├── error.rs            # Add recovery strategies
└── ikev2/state.rs      # Add validation methods
```

**Tests** (10+ tests):
- Error recovery strategies
- Retry policy calculations
- State validation
- Automatic recovery
- Error NOTIFY generation

---

## Testing Strategy

### Unit Tests (70+ tests)

**NAT-T** (15 tests):
- NAT detection hash computation
- NAT presence detection
- UDP encapsulation
- Port floating logic

**INFORMATIONAL** (20 tests):
- DELETE payload parsing
- NOTIFY payload parsing
- Exchange flow
- Error handling

**IKE SA Rekeying** (15 tests):
- Lifetime checks
- Rekey flow
- Child SA transfer
- State transitions

**DPD** (10 tests):
- Timing logic
- Request/response
- Dead peer detection
- Retry mechanism

**Error Handling** (10 tests):
- Recovery strategies
- Retry policies
- State validation

### Integration Tests (10+ tests)

1. Complete NAT-T flow with ESP
2. Delete Child SA via INFORMATIONAL
3. Delete IKE SA via INFORMATIONAL
4. IKE SA rekey with Child SA transfer
5. DPD timeout and reconnection
6. Error recovery scenarios
7. Multiple SAs with NAT-T
8. Port floating during active session
9. NOTIFY error propagation
10. Simultaneous rekey handling

---

## Timeline

**Estimated Total**: 10-14 hours

| Stage | Time | Deliverable |
|-------|------|-------------|
| 1. NAT-T | 3-4 hours | NAT detection, UDP encapsulation |
| 2. INFORMATIONAL | 2-3 hours | DELETE/NOTIFY payloads |
| 3. IKE SA Rekeying | 2-3 hours | IKE SA lifecycle |
| 4. DPD | 1-2 hours | Keepalive mechanism |
| 5. Error Handling | 1-2 hours | Recovery strategies |
| Documentation | 1 hour | Completion report |

---

## Success Metrics

### Functional
- ✅ NAT-T working with ESP
- ✅ SAs deleted via INFORMATIONAL
- ✅ IKE SA rekeyed successfully
- ✅ Dead peers detected
- ✅ Errors handled gracefully

### Quality
- ✅ Zero unsafe code
- ✅ 90%+ test coverage
- ✅ All tests passing
- ✅ RFC 3948 compliance (NAT-T)
- ✅ RFC 7296 compliance (INFORMATIONAL, IKE SA rekey)

### Performance
- ✅ NAT-T overhead: <5%
- ✅ DPD latency: <1ms
- ✅ Error recovery: <100ms

---

## Dependencies

### Existing Code to Reuse
- ✅ IkeMessage and payload parsing (Phase 1)
- ✅ Cryptographic operations (Phase 2)
- ✅ Child SA management (Phase 3)
- ✅ ESP protocol (Phase 3)

### New Dependencies
- SHA-1 for NAT detection hashes (already in crypto crates)
- UDP socket handling (std library)

---

## References

### RFCs
- **RFC 7296 Section 1.4**: INFORMATIONAL Exchange
- **RFC 7296 Section 1.3.2**: Rekeying the IKE SA
- **RFC 7296 Section 2.4**: State Transitions
- **RFC 3948**: UDP Encapsulation of IPsec ESP Packets
- **RFC 3706**: A Traffic-Based Method of Detecting Dead IKE Peers (DPD)

### Implementation Notes
- strongSwan NAT-T implementation
- libreswan INFORMATIONAL handling
- Openswan DPD mechanism

---

## Risks and Mitigations

### Risk 1: NAT-T Complexity
**Risk**: UDP encapsulation adds complexity
**Mitigation**: Extensive testing with different NAT scenarios

### Risk 2: State Synchronization
**Risk**: IKE SA rekey with multiple Child SAs
**Mitigation**: Atomic transfer operations, rollback on failure

### Risk 3: DPD False Positives
**Risk**: Network latency may trigger false dead peer detection
**Mitigation**: Configurable timeouts and retries

### Risk 4: Backward Compatibility
**Risk**: NAT-T changes packet format
**Mitigation**: Auto-detect NAT presence, fallback to normal ESP

---

## Future Enhancements (Phase 5+)

1. **Certificate Authentication**
   - X.509 certificate validation
   - Certificate chains
   - CRL/OCSP checking

2. **EAP Authentication**
   - Extensible Authentication Protocol
   - Multiple authentication methods
   - User authentication

3. **Configuration Payloads**
   - IP address assignment
   - DNS configuration
   - Internal subnet info

4. **IPv6 Support**
   - IPv6 traffic selectors
   - IPv6 NAT detection
   - Dual-stack support

5. **MOBIKE**
   - Mobility and multihoming
   - Address updates
   - Path MTU discovery

---

## Conclusion

Phase 4 will complete the core IPSec implementation with production-ready features for NAT traversal, SA management, and error handling. After Phase 4, the IPSec implementation will be suitable for real-world deployments.

**Phase 4 Priority**: High
**Complexity**: Medium-High
**Dependencies**: Phase 3 complete ✅

---

**Plan Created**: 2025-10-25
**Estimated Duration**: 10-14 hours
**Target Completion**: 2025-10-26
