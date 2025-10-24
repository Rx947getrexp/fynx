# IPSec Architecture Design

**Version**: 1.0
**Date**: 2025-10-24
**Status**: Design Phase

---

## Overview

This document describes the architecture of the Fynx IPSec implementation, including IKEv2 and ESP protocols.

### Design Principles

1. **Security First** - No unsafe code, constant-time operations, secure defaults
2. **Performance** - Zero-copy where possible, efficient state management
3. **Modularity** - Clean separation between IKE and ESP, reusable components
4. **Testability** - All components independently testable
5. **Interoperability** - Strict RFC compliance, tested against major implementations

---

## System Architecture

### High-Level Components

```
┌─────────────────────────────────────────────────────────┐
│                  Application Layer                      │
│          (VPN Client/Server using IPSec API)           │
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
┌───────▼────────┐              ┌───────────▼─────────┐
│  IKEv2 Engine  │              │    ESP Engine       │
│  (Control)     │◄─────────────┤   (Data Plane)      │
│                │   SA Keys    │                     │
└───────┬────────┘              └───────────┬─────────┘
        │                                   │
┌───────▼────────┐              ┌───────────▼─────────┐
│  SA Database   │              │  Packet Processor   │
└───────┬────────┘              └───────────┬─────────┘
        │                                   │
        └───────────────┬───────────────────┘
                        │
              ┌─────────▼──────────┐
              │  Crypto Primitives │
              │ (Reused from SSH)  │
              └────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Dependencies |
|-----------|---------------|--------------|
| **IKEv2 Engine** | SA negotiation, authentication, rekeying | SA Database, Crypto |
| **ESP Engine** | Packet encryption/decryption, anti-replay | SA Database, Crypto |
| **SA Database** | Security Association storage and lifecycle | - |
| **Crypto Primitives** | AEAD, PRF, DH, signatures | ring, dalek |
| **Packet Processor** | Protocol encoding/decoding | bytes |

---

## Module Structure

### Directory Layout

```
crates/proto/src/ipsec/
├── mod.rs                    # Public API exports
├── error.rs                  # Unified error types
├── config.rs                 # Configuration structures
│
├── ikev2/                    # IKEv2 Protocol
│   ├── mod.rs
│   ├── message.rs            # IKE message structure
│   ├── payload/              # IKE payloads
│   │   ├── mod.rs
│   │   ├── sa.rs             # Security Association payload
│   │   ├── ke.rs             # Key Exchange payload
│   │   ├── nonce.rs          # Nonce payload
│   │   ├── auth.rs           # Authentication payload
│   │   ├── notify.rs         # Notify payload
│   │   ├── delete.rs         # Delete payload
│   │   └── ...
│   ├── state.rs              # State machine
│   ├── exchange/             # IKE exchanges
│   │   ├── mod.rs
│   │   ├── sa_init.rs        # IKE_SA_INIT
│   │   ├── auth.rs           # IKE_AUTH
│   │   ├── child_sa.rs       # CREATE_CHILD_SA
│   │   └── informational.rs  # INFORMATIONAL
│   ├── auth/                 # Authentication methods
│   │   ├── mod.rs
│   │   ├── psk.rs            # Pre-Shared Key
│   │   └── cert.rs           # Certificate auth
│   ├── proposal.rs           # Proposal selection
│   └── constants.rs          # RFC constants
│
├── esp/                      # ESP Protocol
│   ├── mod.rs
│   ├── packet.rs             # ESP packet structure
│   ├── encap.rs              # Encapsulation
│   ├── decap.rs              # Decapsulation
│   ├── seq.rs                # Sequence numbers
│   ├── replay.rs             # Anti-replay protection
│   ├── transport.rs          # Transport mode
│   └── tunnel.rs             # Tunnel mode
│
├── sa/                       # Security Associations
│   ├── mod.rs
│   ├── database.rs           # SA storage
│   ├── ike_sa.rs             # IKE SA structure
│   ├── child_sa.rs           # Child SA structure
│   ├── lifetime.rs           # Lifetime management
│   ├── selector.rs           # Traffic selectors
│   └── rekey.rs              # Rekeying logic
│
├── crypto/                   # Cryptographic operations
│   ├── mod.rs
│   ├── prf.rs                # Pseudo-Random Function
│   ├── kdf.rs                # Key Derivation
│   ├── dh.rs                 # Diffie-Hellman (reuse SSH)
│   ├── aead.rs               # AEAD operations
│   └── signature.rs          # Digital signatures
│
├── nat.rs                    # NAT Traversal
├── cookie.rs                 # Cookie mechanism
└── utils.rs                  # Utility functions

examples/
├── ipsec_client.rs           # VPN client example
├── ipsec_server.rs           # VPN server example
└── site_to_site.rs           # Site-to-site VPN

tests/
├── ikev2_tests.rs            # IKEv2 unit tests
├── esp_tests.rs              # ESP unit tests
├── integration_tests.rs      # End-to-end tests
└── interop_tests.rs          # Interoperability tests
```

---

## Core Data Structures

### IKEv2 Message

```rust
/// IKEv2 message structure (RFC 7296 Section 3.1)
pub struct IkeMessage {
    /// Message header
    pub header: IkeHeader,
    /// List of payloads
    pub payloads: Vec<IkePayload>,
}

pub struct IkeHeader {
    /// Initiator's SPI (8 bytes)
    pub initiator_spi: [u8; 8],
    /// Responder's SPI (8 bytes, zero for IKE_SA_INIT request)
    pub responder_spi: [u8; 8],
    /// Next payload type
    pub next_payload: PayloadType,
    /// Major and minor version (always 0x20)
    pub version: u8,
    /// Exchange type
    pub exchange_type: ExchangeType,
    /// Flags (R, V, I)
    pub flags: IkeFlags,
    /// Message ID
    pub message_id: u32,
    /// Total message length
    pub length: u32,
}

pub enum ExchangeType {
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
}

pub enum IkePayload {
    SA(SaPayload),
    KE(KeyExchangePayload),
    Nonce(NoncePayload),
    Notification(NotifyPayload),
    Delete(DeletePayload),
    VendorId(VendorIdPayload),
    TSi(TrafficSelectorPayload),
    TSr(TrafficSelectorPayload),
    Authentication(AuthPayload),
    // ... more payload types
}
```

### ESP Packet

```rust
/// ESP packet structure (RFC 4303)
pub struct EspPacket {
    /// Security Parameters Index
    pub spi: u32,
    /// Sequence number
    pub seq: u32,
    /// Initialization Vector (AEAD only)
    pub iv: Vec<u8>,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// Padding
    pub padding: Vec<u8>,
    /// Padding length
    pub pad_length: u8,
    /// Next header (protocol number)
    pub next_header: u8,
    /// Integrity Check Value (AEAD tag or MAC)
    pub icv: Vec<u8>,
}

impl EspPacket {
    /// Parse ESP packet from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self>;

    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8>;

    /// Decrypt and verify
    pub fn decrypt(&self, sa: &ChildSa) -> Result<Vec<u8>>;

    /// Encrypt and authenticate
    pub fn encrypt(plaintext: &[u8], sa: &ChildSa) -> Result<Self>;
}
```

### Security Associations

```rust
/// IKE Security Association
pub struct IkeSa {
    /// Local SPI
    pub local_spi: [u8; 8],
    /// Remote SPI
    pub remote_spi: [u8; 8],
    /// Current state
    pub state: IkeSaState,
    /// Negotiated proposal
    pub proposal: Proposal,
    /// Keying material
    pub keys: IkeKeys,
    /// Creation time
    pub created_at: Instant,
    /// Lifetime
    pub lifetime: Lifetime,
    /// Child SAs associated with this IKE SA
    pub child_sas: Vec<u32>, // SPI list
}

pub struct IkeKeys {
    pub sk_d: Vec<u8>,   // Key derivation
    pub sk_ai: Vec<u8>,  // Initiator auth (integrity)
    pub sk_ar: Vec<u8>,  // Responder auth (integrity)
    pub sk_ei: Vec<u8>,  // Initiator encryption
    pub sk_er: Vec<u8>,  // Responder encryption
    pub sk_pi: Vec<u8>,  // Initiator auth payload
    pub sk_pr: Vec<u8>,  // Responder auth payload
}

/// Child Security Association (ESP/AH)
pub struct ChildSa {
    /// Inbound SPI
    pub spi_in: u32,
    /// Outbound SPI
    pub spi_out: u32,
    /// Protocol (ESP or AH)
    pub protocol: Protocol,
    /// Mode (Transport or Tunnel)
    pub mode: Mode,
    /// Encryption key (inbound)
    pub enc_key_in: Vec<u8>,
    /// Encryption key (outbound)
    pub enc_key_out: Vec<u8>,
    /// Integrity key (inbound, if not AEAD)
    pub int_key_in: Option<Vec<u8>>,
    /// Integrity key (outbound, if not AEAD)
    pub int_key_out: Option<Vec<u8>>,
    /// Sequence number (outbound)
    pub seq_out: AtomicU64,
    /// Anti-replay window (inbound)
    pub replay_window: ReplayWindow,
    /// Traffic selectors (initiator)
    pub ts_i: Vec<TrafficSelector>,
    /// Traffic selectors (responder)
    pub ts_r: Vec<TrafficSelector>,
    /// Lifetime
    pub lifetime: Lifetime,
}

/// SA Database
pub struct SaDatabase {
    /// IKE SAs (indexed by initiator SPI)
    ike_sas: HashMap<[u8; 8], IkeSa>,
    /// Child SAs (indexed by SPI)
    child_sas: HashMap<u32, ChildSa>,
    /// Cleanup task handle
    cleanup_task: Option<JoinHandle<()>>,
}
```

---

## State Machines

### IKEv2 State Machine

```
IDLE
  │
  ├─ (send IKE_SA_INIT request)
  ↓
INIT_SENT
  │
  ├─ (recv IKE_SA_INIT response)
  ↓
INIT_DONE
  │
  ├─ (send IKE_AUTH request)
  ↓
AUTH_SENT
  │
  ├─ (recv IKE_AUTH response with success)
  ↓
ESTABLISHED ◄─────┐
  │               │
  ├─ (soft lifetime) → REKEYING
  ├─ (hard lifetime) → DELETING → DELETED
  ├─ (recv CREATE_CHILD_SA) → handle and stay
  ├─ (recv INFORMATIONAL) → handle and stay
  └─ (recv DELETE) → DELETING → DELETED
```

**State Transitions**:

```rust
pub enum IkeSaState {
    Idle,
    InitSent,
    InitDone,
    AuthSent,
    Established,
    Rekeying,
    Deleting,
    Deleted,
}

impl IkeSa {
    pub fn handle_event(&mut self, event: IkeEvent) -> Result<Vec<IkeMessage>> {
        match (self.state, event) {
            (IkeSaState::Idle, IkeEvent::InitiateHandshake) => {
                let msg = self.build_sa_init_request()?;
                self.state = IkeSaState::InitSent;
                Ok(vec![msg])
            }

            (IkeSaState::InitSent, IkeEvent::ReceivedMessage(msg)) => {
                if msg.header.exchange_type == ExchangeType::IkeSaInit {
                    self.process_sa_init_response(msg)?;
                    let auth_msg = self.build_auth_request()?;
                    self.state = IkeSaState::AuthSent;
                    Ok(vec![auth_msg])
                } else {
                    Err(Error::UnexpectedMessage)
                }
            }

            // ... more transitions
        }
    }
}
```

### ESP Sequence Number State

```rust
/// Outbound sequence number (atomic, always incrementing)
pub struct OutboundSeq {
    counter: AtomicU64,
}

impl OutboundSeq {
    pub fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }
}

/// Inbound anti-replay window
pub struct ReplayWindow {
    window_size: u32,
    highest_seq: u64,
    bitmap: u64,
}

impl ReplayWindow {
    /// Check if packet should be accepted and update window
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        // Implementation in IMPLEMENTATION_PLAN.md
    }
}
```

---

## Cryptographic Architecture

### Key Hierarchy

```
                        ┌──────────────┐
                        │ Shared Secret│
                        │   (DH: g^ir) │
                        └───────┬──────┘
                                │
                    ┌───────────▼───────────┐
                    │      SKEYSEED         │
                    │  prf(Ni|Nr, g^ir)    │
                    └───────────┬───────────┘
                                │
                ┌───────────────┴───────────────┐
                │         prf+ (SKEYSEED,       │
                │         Ni|Nr|SPIi|SPIr)      │
                └───────────────┬───────────────┘
                                │
        ┌───────┬───────┬───────┼───────┬───────┬───────┐
        │       │       │       │       │       │       │
       SK_d   SK_ai  SK_ar   SK_ei  SK_er  SK_pi  SK_pr
        │       │       │       │       │       │       │
        │       │       │       │       │       │       │
   (rekey)  (init   (resp   (init   (resp   (init   (resp
            MAC)    MAC)    enc)    enc)    AUTH)   AUTH)
```

### Key Derivation Implementation

```rust
pub struct KeyDerivation {
    prf: PrfAlgorithm,
}

impl KeyDerivation {
    /// Compute SKEYSEED
    pub fn compute_skeyseed(
        &self,
        nonce_i: &[u8],
        nonce_r: &[u8],
        shared_secret: &[u8],
    ) -> Vec<u8> {
        let key = [nonce_i, nonce_r].concat();
        self.prf.compute(&key, shared_secret)
    }

    /// PRF+ key expansion (RFC 7296 Section 2.13)
    pub fn prf_plus(
        &self,
        key: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Vec<u8> {
        let mut output = Vec::with_capacity(output_len);
        let mut t = Vec::new();
        let mut counter = 1u8;

        while output.len() < output_len {
            let mut input = t.clone();
            input.extend_from_slice(seed);
            input.push(counter);

            t = self.prf.compute(key, &input);
            output.extend_from_slice(&t);
            counter += 1;
        }

        output.truncate(output_len);
        output
    }

    /// Derive all IKE SA keys
    pub fn derive_ike_keys(
        &self,
        skeyseed: &[u8],
        nonce_i: &[u8],
        nonce_r: &[u8],
        spi_i: &[u8; 8],
        spi_r: &[u8; 8],
        key_lengths: &KeyLengths,
    ) -> IkeKeys {
        let seed = [nonce_i, nonce_r, spi_i, spi_r].concat();
        let total_len = key_lengths.total();
        let keymat = self.prf_plus(skeyseed, &seed, total_len);

        IkeKeys::from_bytes(&keymat, key_lengths)
    }
}
```

### Reusing SSH Crypto

```rust
// Reuse SSH AEAD ciphers for ESP
use crate::ssh::crypto::{ChaCha20Poly1305, AesGcm};

pub enum EspCipher {
    ChaCha20Poly1305(ChaCha20Poly1305),
    Aes128Gcm(AesGcm),
    Aes256Gcm(AesGcm),
}

impl EspCipher {
    pub fn encrypt(&self, plaintext: &[u8], ad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::ChaCha20Poly1305(cipher) => cipher.encrypt(plaintext, ad, nonce),
            Self::Aes128Gcm(cipher) => cipher.encrypt(plaintext, ad, nonce),
            Self::Aes256Gcm(cipher) => cipher.encrypt(plaintext, ad, nonce),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8], ad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::ChaCha20Poly1305(cipher) => cipher.decrypt(ciphertext, ad, nonce),
            Self::Aes128Gcm(cipher) => cipher.decrypt(ciphertext, ad, nonce),
            Self::Aes256Gcm(cipher) => cipher.decrypt(ciphertext, ad, nonce),
        }
    }
}
```

---

## Network Architecture

### IKEv2 Transport (UDP)

```rust
pub struct IkeTransport {
    socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    nat_detected: bool,
}

impl IkeTransport {
    /// Bind to local address
    pub async fn bind(local: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        Ok(Self {
            socket,
            local_addr: local,
            remote_addr: "0.0.0.0:0".parse().unwrap(),
            nat_detected: false,
        })
    }

    /// Send IKE message
    pub async fn send(&self, msg: &IkeMessage) -> Result<()> {
        let bytes = msg.to_bytes()?;

        // If NAT detected, use port 4500 and add non-ESP marker
        if self.nat_detected {
            let mut packet = vec![0u8; 4]; // Non-ESP marker
            packet.extend_from_slice(&bytes);
            self.socket.send_to(&packet, self.remote_addr).await?;
        } else {
            self.socket.send_to(&bytes, self.remote_addr).await?;
        }

        Ok(())
    }

    /// Receive IKE message
    pub async fn recv(&self) -> Result<(IkeMessage, SocketAddr)> {
        let mut buf = vec![0u8; 65535]; // Max UDP size
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);

        // Check for non-ESP marker
        let offset = if self.nat_detected && buf.len() > 4 && &buf[0..4] == &[0, 0, 0, 0] {
            4
        } else {
            0
        };

        let msg = IkeMessage::from_bytes(&buf[offset..])?;
        Ok((msg, addr))
    }
}
```

### ESP Processing (Raw IP)

```rust
pub struct EspProcessor {
    /// SA database reference
    sa_db: Arc<SaDatabase>,
    /// Raw socket for ESP packets
    socket: RawSocket,
}

impl EspProcessor {
    /// Encapsulate outbound packet
    pub fn encapsulate(
        &self,
        plaintext: &[u8],
        spi: u32,
    ) -> Result<Vec<u8>> {
        let sa = self.sa_db.get_child_sa(spi)?;

        // Get next sequence number
        let seq = sa.seq_out.fetch_add(1, Ordering::SeqCst);

        // Generate IV (random for GCM/ChaCha20)
        let mut iv = vec![0u8; sa.cipher.iv_len()];
        ring::rand::SystemRandom::new().fill(&mut iv)?;

        // Encrypt payload
        let ciphertext = sa.cipher.encrypt(plaintext, &[], &iv)?;

        // Build ESP packet
        let packet = EspPacket {
            spi,
            seq: seq as u32,
            iv,
            payload: ciphertext,
            // ... padding, next_header, icv
        };

        packet.to_bytes()
    }

    /// Decapsulate inbound packet
    pub fn decapsulate(&self, esp_packet: &[u8]) -> Result<Vec<u8>> {
        let packet = EspPacket::from_bytes(esp_packet)?;
        let sa = self.sa_db.get_child_sa(packet.spi)?;

        // Check anti-replay
        if !sa.replay_window.lock().check_and_update(packet.seq as u64) {
            return Err(Error::ReplayDetected);
        }

        // Decrypt and verify
        packet.decrypt(&sa)
    }
}
```

---

## Concurrency Model

### Async Architecture

```rust
/// IKEv2 Session (single SA pair)
pub struct IkeSession {
    sa: Arc<Mutex<IkeSa>>,
    transport: IkeTransport,
    sa_db: Arc<SaDatabase>,
}

impl IkeSession {
    /// Run IKE session (event loop)
    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                // Receive messages
                Ok((msg, addr)) = self.transport.recv() => {
                    self.handle_message(msg, addr).await?;
                }

                // Lifetime expiry
                _ = self.wait_lifetime() => {
                    self.initiate_rekey().await?;
                }

                // Keepalive timer
                _ = self.wait_keepalive() => {
                    self.send_keepalive().await?;
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: IkeMessage, addr: SocketAddr) -> Result<()> {
        let mut sa = self.sa.lock().await;
        let responses = sa.handle_event(IkeEvent::ReceivedMessage(msg))?;
        drop(sa);

        for response in responses {
            self.transport.send(&response).await?;
        }

        Ok(())
    }
}
```

### Thread Safety

- **SA Database**: `Arc<Mutex<SaDatabase>>` for shared access
- **Sequence Numbers**: `AtomicU64` for lock-free increments
- **Replay Window**: `Mutex<ReplayWindow>` for state updates

---

## Performance Optimizations

### Zero-Copy where Possible

```rust
use bytes::{Bytes, BytesMut};

impl EspPacket {
    /// Parse without copying (view into buffer)
    pub fn parse_view(data: &Bytes) -> Result<EspPacketView> {
        // Parse headers, but don't copy payload
        let spi = u32::from_be_bytes(data[0..4].try_into()?);
        let seq = u32::from_be_bytes(data[4..8].try_into()?);

        // Return view (no copy)
        Ok(EspPacketView {
            spi,
            seq,
            payload: data.slice(8..data.len() - 16), // Reference, not copy
        })
    }
}
```

### Batch Processing

```rust
/// Process multiple ESP packets in batch
pub async fn process_batch(&self, packets: Vec<Bytes>) -> Result<Vec<Bytes>> {
    // Decrypt in parallel
    let tasks: Vec<_> = packets
        .into_iter()
        .map(|pkt| {
            let sa_db = self.sa_db.clone();
            tokio::spawn(async move {
                Self::decapsulate_one(&sa_db, &pkt)
            })
        })
        .collect();

    // Wait for all
    let results = futures::future::join_all(tasks).await;

    results.into_iter().collect::<Result<Vec<_>>>()
}
```

---

## Error Handling

### Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum IpsecError {
    #[error("IKEv2 protocol error: {0}")]
    Protocol(String),

    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    #[error("No proposal chosen")]
    NoProposalChosen,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Replay attack detected (seq: {0})")]
    ReplayDetected(u64),

    #[error("SA not found (SPI: {0:08x})")]
    SaNotFound(u32),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IpsecError>;
```

---

## Testing Strategy

### Unit Testing Layers

```rust
// Layer 1: Protocol parsing
#[test]
fn test_ike_message_parse() {
    let bytes = include_bytes!("../testdata/ike_sa_init.bin");
    let msg = IkeMessage::from_bytes(bytes).unwrap();
    assert_eq!(msg.header.exchange_type, ExchangeType::IkeSaInit);
}

// Layer 2: State machine
#[test]
fn test_state_transition() {
    let mut sa = IkeSa::new();
    assert_eq!(sa.state, IkeSaState::Idle);

    sa.handle_event(IkeEvent::InitiateHandshake).unwrap();
    assert_eq!(sa.state, IkeSaState::InitSent);
}

// Layer 3: Crypto operations
#[test]
fn test_key_derivation() {
    let kdf = KeyDerivation::new(PrfAlgorithm::HmacSha256);
    let keys = kdf.derive_ike_keys(/* ... */);
    assert_eq!(keys.sk_d.len(), 32);
}

// Layer 4: End-to-end
#[tokio::test]
async fn test_full_handshake() {
    let client = IkeClient::new(/* ... */);
    let server = IkeServer::new(/* ... */);

    client.connect("127.0.0.1:500").await.unwrap();
    // Verify SA established
}
```

---

## Security Considerations

### Constant-Time Operations

```rust
// Use constant-time comparison for AUTH payloads
use subtle::ConstantTimeEq;

pub fn verify_auth(received: &[u8], expected: &[u8]) -> bool {
    received.ct_eq(expected).into()
}
```

### Memory Zeroization

```rust
use zeroize::Zeroize;

pub struct IkeKeys {
    pub sk_d: Vec<u8>,
    // ... other keys
}

impl Drop for IkeKeys {
    fn drop(&mut self) {
        self.sk_d.zeroize();
        // ... zeroize all keys
    }
}
```

### Input Validation

```rust
impl IkeMessage {
    pub fn validate(&self) -> Result<()> {
        // Check message length
        if self.header.length > MAX_IKE_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }

        // Validate version
        if self.header.version != 0x20 {
            return Err(Error::UnsupportedVersion);
        }

        // Validate payloads
        for payload in &self.payloads {
            payload.validate()?;
        }

        Ok(())
    }
}
```

---

## Metrics & Monitoring

### Performance Metrics

```rust
pub struct IpsecMetrics {
    // IKE metrics
    pub ike_handshakes_total: AtomicU64,
    pub ike_handshakes_failed: AtomicU64,
    pub ike_rekeys_total: AtomicU64,

    // ESP metrics
    pub esp_packets_encrypted: AtomicU64,
    pub esp_packets_decrypted: AtomicU64,
    pub esp_replay_detected: AtomicU64,
    pub esp_auth_failed: AtomicU64,

    // Timing
    pub handshake_duration_ms: Histogram,
    pub esp_encrypt_duration_us: Histogram,
}
```

---

**Document Version**: 1.0
**Created**: 2025-10-24
**Status**: ✅ Design Complete
