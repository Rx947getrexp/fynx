# Stage 3: Traffic Selectors Implementation

**Date**: 2025-10-24
**Status**: ✅ Completed
**Commit**: c32e4dc
**Test Count**: 301 tests (172 SSH + 129 IPSec)

---

## Overview

Implemented complete Traffic Selectors (TSi/TSr) payload support for IKE_AUTH exchange, enabling IPSec to specify which traffic should be protected by the Security Association.

---

## Implementation Details

### 1. TsType Enum

```rust
pub enum TsType {
    Ipv4AddrRange = 7,   // RFC 7296 TS Type value
    Ipv6AddrRange = 8,
}
```

**Features**:
- Type-safe enum for TS types
- Conversion from/to u8 with validation
- Supports both IPv4 and IPv6 address ranges

### 2. TrafficSelector Structure (234 lines)

```rust
pub struct TrafficSelector {
    pub ts_type: TsType,
    pub ip_protocol_id: u8,        // 0 = any, 6 = TCP, 17 = UDP, etc.
    pub start_port: u16,            // 0-65535
    pub end_port: u16,
    pub start_address: Vec<u8>,     // 4 bytes for IPv4, 16 for IPv6
    pub end_address: Vec<u8>,
}
```

**Key Methods**:
- `new()` - Create with validation
- `ipv4_any()` - Match all IPv4 traffic (0.0.0.0/0, ports 0-65535)
- `ipv4_addr()` - Match specific IPv4 address
- `ipv6_any()` - Match all IPv6 traffic (::/0, ports 0-65535)
- `from_bytes()` - Parse from wire format
- `to_bytes()` - Serialize to wire format
- `length()` - Calculate selector length

**Validation**:
- IPv4 addresses must be exactly 4 bytes
- IPv6 addresses must be exactly 16 bytes
- Address range consistency checked

### 3. TrafficSelectorsPayload (78 lines)

```rust
pub struct TrafficSelectorsPayload {
    pub selectors: Vec<TrafficSelector>,
}
```

**Wire Format** (RFC 7296 Section 3.13):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Payload  |C|  RESERVED   |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Number of TSs |                 RESERVED                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                       Traffic Selectors                       ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Key Methods**:
- `new()` - Create from selector list
- `from_payload_data()` - Parse multiple selectors
- `to_payload_data()` - Serialize with count and reserved bytes
- `total_length()` - Calculate total payload length
- `count()` - Get number of selectors
- `single()` - Create payload with single selector

### 4. IkePayload Integration

Added TSi and TSr variants to IkePayload enum:
```rust
pub enum IkePayload {
    // ... existing variants
    V(VendorIdPayload),
    TSi(TrafficSelectorsPayload),  // Traffic Selector - Initiator
    TSr(TrafficSelectorsPayload),  // Traffic Selector - Responder
    Unknown { ... },
}
```

### 5. Message Serialization

Updated `message.rs` to handle TS payloads:
- Added TSi/TSr to `to_bytes()` length calculation
- Added TSi/TSr to `serialize_payload()` match statement

---

## Test Coverage (15 tests)

### TsType Tests (1 test)
- ✅ Type conversions (u8 ↔ TsType)

### TrafficSelector Tests (9 tests)
- ✅ IPv4 any address (0.0.0.0 - 255.255.255.255)
- ✅ IPv4 specific address
- ✅ IPv6 any address (:: - ffff:ffff:...)
- ✅ IPv4 with TCP port range
- ✅ Address length validation (IPv4: 4 bytes, IPv6: 16 bytes)
- ✅ Roundtrip serialization (IPv4)
- ✅ Roundtrip serialization (IPv6)

### TrafficSelectorsPayload Tests (5 tests)
- ✅ Single selector
- ✅ Multiple selectors (3 mixed IPv4/IPv6)
- ✅ Roundtrip with multiple selectors
- ✅ Total length calculation
- ✅ Empty payload

### Example Test
```rust
#[test]
fn test_traffic_selector_ipv4_any() {
    let ts = TrafficSelector::ipv4_any();

    assert_eq!(ts.ts_type, TsType::Ipv4AddrRange);
    assert_eq!(ts.ip_protocol_id, 0); // Any protocol
    assert_eq!(ts.start_port, 0);
    assert_eq!(ts.end_port, 65535);
    assert_eq!(ts.start_address, vec![0, 0, 0, 0]);
    assert_eq!(ts.end_address, vec![255, 255, 255, 255]);
}
```

---

## Code Statistics

### Added Lines
- Implementation: ~312 lines (234 TrafficSelector + 78 TrafficSelectorsPayload)
- Tests: ~88 lines (15 comprehensive tests)
- Total: ~400 lines

### File Sizes
- `payload.rs`: ~2200 lines total
- `message.rs`: ~420 lines total

---

## Technical Achievements

### 1. RFC Compliance
- ✅ RFC 7296 Section 3.13 (Traffic Selector Payload)
- ✅ Proper TS Type encoding (7 = IPv4, 8 = IPv6)
- ✅ Correct wire format with reserved bytes
- ✅ Multiple selectors support

### 2. Type Safety
- Type-safe TsType enum
- Validated address lengths
- No magic numbers
- Comprehensive error handling

### 3. Usability
- Helper methods for common cases:
  - `ipv4_any()` - Accept all IPv4 traffic
  - `ipv4_addr()` - Specific IPv4 address
  - `ipv6_any()` - Accept all IPv6 traffic
- Flexible port range specification
- Protocol filtering support

### 4. Testing
- 100% pass rate (301 tests)
- Comprehensive coverage:
  - Type conversions
  - Helper methods
  - Validation
  - Roundtrip serialization
  - Multiple selectors
  - Edge cases (empty payload)

---

## Use Cases

### 1. Accept All Traffic (Common Case)
```rust
// Initiator: Any IPv4 traffic from our side
let tsi = TrafficSelectorsPayload::single(TrafficSelector::ipv4_any());

// Responder: Any IPv4 traffic from their side
let tsr = TrafficSelectorsPayload::single(TrafficSelector::ipv4_any());
```

### 2. Specific Address Range
```rust
let ts = TrafficSelector::new(
    TsType::Ipv4AddrRange,
    0,                              // Any protocol
    0,                              // Any source port
    65535,                          // Any dest port
    vec![192, 168, 1, 0],          // Start: 192.168.1.0
    vec![192, 168, 1, 255],        // End: 192.168.1.255
).unwrap();
```

### 3. TCP Port Range
```rust
let ts = TrafficSelector::new(
    TsType::Ipv4AddrRange,
    6,                              // TCP protocol
    1024,                           // Start port: 1024
    8080,                           // End port: 8080
    vec![0, 0, 0, 0],              // Any source IP
    vec![255, 255, 255, 255],      // Any dest IP
).unwrap();
```

---

## Integration Points

### IKE_AUTH Exchange
Traffic Selectors are used in IKE_AUTH exchange:
```
Initiator                         Responder
-----------                       -----------
                                  IKE_SA_INIT complete
HDR, SK {IDi, AUTH,
    SAi2, TSi, TSr}  -->
                     <--  HDR, SK {IDr, AUTH,
                              SAr2, TSi, TSr}
```

**TSi (Initiator TS)**: Traffic from initiator's side
**TSr (Responder TS)**: Traffic from responder's side

Both peers send their proposed selectors and negotiate the intersection.

---

## Next Steps (Phase 2 Remaining)

### Immediate Priority (IKE_AUTH Exchange)
1. **SK (Encrypted) Payload** (2-3 days)
   - Encrypted payload for IKE_AUTH
   - Payload encryption/decryption
   - IV generation and management
   - Padding handling

2. **IKE_AUTH Exchange Handler** (2-3 days)
   - Complete authentication exchange
   - Integrate PSK authentication (already implemented)
   - Traffic selector negotiation
   - First Child SA creation
   - State transitions (InitDone → AuthSent → Established)

3. **Configuration Payload (CP)** (1 day) - Optional
   - Address assignment
   - DNS server configuration

### Medium Priority
4. **CREATE_CHILD_SA Exchange** (2-3 days)
   - Additional Child SA creation
   - Rekeying support
   - SA lifetime management

5. **INFORMATIONAL Exchange** (1 day)
   - Error reporting
   - Status notifications
   - SA deletion

---

## Lessons Learned

### What Went Well
1. **Helper Methods**: `ipv4_any()`, `ipv4_addr()` make common cases simple
2. **Validation**: Strict address length checking prevents bugs
3. **Test Coverage**: 15 tests catch edge cases early
4. **RFC Compliance**: Following RFC 7296 Section 3.13 exactly

### Challenges Overcome
1. **Length Calculation**: Had to carefully calculate selector length (8 + addr + addr)
2. **Reserved Bytes**: Proper handling of 3 reserved bytes in payload
3. **Multiple Selectors**: Parsing variable-length selector list correctly

---

## Metrics

### Development Time
- **Implementation**: ~30 minutes
- **Testing**: ~15 minutes
- **Documentation**: ~10 minutes
- **Total**: ~1 hour

### Code Quality
- ✅ Zero unsafe code
- ✅ Zero warnings
- ✅ 100% test pass rate
- ✅ Comprehensive error handling

---

## References

- [RFC 7296 Section 3.13](https://datatracker.ietf.org/doc/html/rfc7296#section-3.13) - Traffic Selector Payload
- [RFC 7296 Section 2.9](https://datatracker.ietf.org/doc/html/rfc7296#section-2.9) - Traffic Selector Negotiation

---

**Status**: ✅ Complete
**Next**: SK (Encrypted) Payload + IKE_AUTH Exchange Handler
