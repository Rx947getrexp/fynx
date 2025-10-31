# Phase 5 Stage 2: High-Level API Implementation Plan

**Date**: 2025-10-31
**Stage**: Phase 5 Stage 2 - High-Level API Design
**Estimated Duration**: 4-6 hours
**Status**: 📋 Planning

---

## Goal

Provide ergonomic, async-friendly APIs for users to establish IPSec tunnels without dealing with low-level protocol details.

---

## Implementation Breakdown

### Sub-Stage 1: Configuration Structures (30-45 min)

**Goal**: Define configuration types and builder pattern

**Files to Create**:
- `crates/proto/src/ipsec/config.rs` (~150 lines)

**What to Implement**:
```rust
pub struct ClientConfig {
    pub local_id: String,
    pub remote_id: String,
    pub psk: Vec<u8>,
    pub ike_proposals: Vec<Proposal>,
    pub esp_proposals: Vec<Proposal>,
    pub dpd_config: Option<DpdConfig>,
    pub lifetime: SaLifetime,
}

pub struct ServerConfig {
    pub local_id: String,
    pub psk: Vec<u8>,
    pub ike_proposals: Vec<Proposal>,
    pub esp_proposals: Vec<Proposal>,
    pub dpd_config: Option<DpdConfig>,
    pub lifetime: SaLifetime,
}

pub struct ClientBuilder { ... }
pub struct ServerBuilder { ... }
```

**Tests** (3 tests):
- test_client_config_builder
- test_server_config_builder
- test_config_validation

**Success Criteria**:
- ✅ Builder pattern for both client and server configs
- ✅ Default values for optional fields
- ✅ Validation in build() method

---

### Sub-Stage 2: Client API Core (1-1.5 hours)

**Goal**: Implement IpsecClient structure and basic methods

**Files to Create**:
- `crates/proto/src/ipsec/client.rs` (~300 lines)

**What to Implement**:
```rust
pub struct IpsecClient {
    config: ClientConfig,
    ike_sa: Option<IkeSaContext>,
    child_sas: HashMap<u32, ChildSa>,
    socket: UdpSocket,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
}

impl IpsecClient {
    pub fn builder() -> ClientBuilder;

    pub async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        // 1. Bind UDP socket
        // 2. Run IKE_SA_INIT exchange
        // 3. Run IKE_AUTH exchange
        // 4. Create Child SA
    }

    pub async fn send_packet(&mut self, data: &[u8]) -> Result<()>;
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>>;
}
```

**Tests** (5 tests):
- test_client_builder
- test_client_connect_success
- test_client_connect_failure
- test_client_send_recv
- test_client_without_connect

**Success Criteria**:
- ✅ Async connect() performs full IKEv2 handshake
- ✅ send_packet() encrypts with ESP
- ✅ recv_packet() decrypts with ESP
- ✅ Proper error handling

---

### Sub-Stage 3: Server API Core (1-1.5 hours)

**Goal**: Implement IpsecServer and IpsecSession

**Files to Create**:
- `crates/proto/src/ipsec/server.rs` (~300 lines)

**What to Implement**:
```rust
pub struct IpsecServer {
    config: ServerConfig,
    sessions: HashMap<SocketAddr, IpsecSession>,
    socket: UdpSocket,
    local_addr: SocketAddr,
}

pub struct IpsecSession {
    peer_addr: SocketAddr,
    ike_sa: IkeSaContext,
    child_sas: HashMap<u32, ChildSa>,
}

impl IpsecServer {
    pub async fn bind(config: ServerConfig, addr: SocketAddr) -> Result<Self>;
    pub async fn accept(&mut self) -> Result<(SocketAddr, IpsecSession)>;
}

impl IpsecSession {
    pub async fn send_packet(&mut self, data: &[u8]) -> Result<()>;
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>>;
    pub async fn close(&mut self) -> Result<()>;
}
```

**Tests** (5 tests):
- test_server_bind
- test_server_accept
- test_session_send_recv
- test_session_close
- test_multiple_sessions

**Success Criteria**:
- ✅ Server accepts multiple concurrent sessions
- ✅ Each session has independent IKE SA and Child SAs
- ✅ Graceful session termination

---

### Sub-Stage 4: Shutdown and Cleanup (30-45 min)

**Goal**: Implement shutdown methods with proper cleanup

**What to Implement**:
```rust
impl IpsecClient {
    pub async fn shutdown(&mut self) -> Result<()> {
        // 1. Send DELETE for Child SAs
        // 2. Send DELETE for IKE SA
        // 3. Close socket
    }
}

impl IpsecServer {
    pub async fn shutdown(&mut self) -> Result<()> {
        // 1. Close all sessions
        // 2. Close socket
    }
}
```

**Tests** (2 tests):
- test_client_shutdown
- test_server_shutdown

**Success Criteria**:
- ✅ Graceful INFORMATIONAL exchange with DELETE
- ✅ No resource leaks
- ✅ Socket properly closed

---

### Sub-Stage 5: Background Tasks (1-1.5 hours)

**Goal**: Implement DPD and automatic rekeying

**What to Implement**:
```rust
impl IpsecClient {
    async fn start_background_tasks(&mut self) {
        // Spawn DPD task
        // Spawn rekey task
    }

    async fn dpd_loop(&mut self) { ... }
    async fn rekey_loop(&mut self) { ... }
}
```

**Tests** (2 tests):
- test_client_dpd
- test_client_automatic_rekey

**Success Criteria**:
- ✅ DPD checks run periodically
- ✅ Automatic rekey before soft lifetime
- ✅ Background tasks stop on shutdown

---

### Sub-Stage 6: Integration Tests (30-45 min)

**Goal**: End-to-end client/server tests

**Files to Create**:
- Add tests to `crates/proto/tests/ipsec_client_server.rs`

**Tests** (3+ tests):
- test_client_server_handshake
- test_client_server_data_transfer
- test_client_server_shutdown

**Success Criteria**:
- ✅ Client connects to server
- ✅ Bidirectional data transfer works
- ✅ Graceful shutdown on both sides

---

## Total Breakdown

| Sub-Stage | Duration | Lines | Tests |
|-----------|----------|-------|-------|
| 1. Config Structures | 30-45 min | ~150 | 3 |
| 2. Client API | 1-1.5 hours | ~300 | 5 |
| 3. Server API | 1-1.5 hours | ~300 | 5 |
| 4. Shutdown | 30-45 min | ~100 | 2 |
| 5. Background Tasks | 1-1.5 hours | ~200 | 2 |
| 6. Integration Tests | 30-45 min | ~150 | 3 |
| **Total** | **4.5-6.5 hours** | **~1,200** | **20** |

---

## Dependencies

### Internal Dependencies
- ✅ `IkeSaContext` (from exchange.rs)
- ✅ `ChildSa` (from child_sa.rs)
- ✅ `EspPacket` (from esp.rs)
- ✅ `IkeSaInitExchange` (from exchange.rs)
- ✅ `IkeAuthExchange` (from exchange.rs)
- ✅ `CreateChildSaExchange` (from exchange.rs)
- ✅ `InformationalExchange` (from informational.rs)
- ✅ `DpdConfig` (from dpd.rs)
- ✅ `SaLifetime` (from child_sa.rs)

### External Dependencies
- ✅ `tokio` - Already in Cargo.toml
- ✅ `async-trait` - Already in Cargo.toml

---

## Implementation Order

1. **Start**: Sub-Stage 1 (Config Structures)
2. **Then**: Sub-Stage 2 (Client API)
3. **Then**: Sub-Stage 3 (Server API)
4. **Then**: Sub-Stage 4 (Shutdown)
5. **Then**: Sub-Stage 5 (Background Tasks)
6. **Finally**: Sub-Stage 6 (Integration Tests)

---

## Current Status

- [x] Planning complete
- [x] Sub-Stage 1: Config Structures (5 tests passing)
- [x] Sub-Stage 2: Client API (5 tests passing)
- [x] Sub-Stage 3: Server API (5 tests passing)
- [x] Sub-Stage 4: Shutdown (2 tests passing)
- [ ] Sub-Stage 5: Background Tasks
- [ ] Sub-Stage 6: Integration Tests

**Next Action**: Begin Sub-Stage 5 - Implement DPD and automatic rekeying
