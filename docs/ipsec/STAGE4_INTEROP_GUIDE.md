# Phase 5 Stage 4: Interoperability Testing Guide

**Date**: 2025-10-31
**Stage**: Phase 5 Stage 4 - Interoperability Testing
**Status**: 📋 Framework Ready (Requires Manual Execution)

---

## Overview

This stage validates interoperability between Fynx IPSec and strongSwan, the industry-standard IPSec implementation. These tests ensure protocol compatibility and real-world usability.

**Note**: These tests require strongSwan installation and must be run manually on a Linux/macOS system with appropriate permissions.

---

## Prerequisites

### System Requirements

- **Operating System**: Linux or macOS (strongSwan has limited Windows support)
- **Permissions**: Root/sudo access for binding to port 500
- **Network**: Localhost or network connectivity

### Software Installation

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install strongswan strongswan-pki libcharon-extra-plugins
```

#### macOS

```bash
brew install strongswan
```

#### Arch Linux

```bash
sudo pacman -S strongswan
```

---

## strongSwan Configuration

### 1. Server Configuration

Create `/etc/strongswan/ipsec.conf`:

```conf
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2"
    uniqueids=no

conn fynx-client-to-strongswan-server
    left=%any
    leftid=server@example.com
    leftauth=psk
    right=%any
    rightid=client@example.com
    rightauth=psk
    ike=aes128gcm16-prfsha256-modp2048!
    esp=aes128gcm16-esn!
    keyexchange=ikev2
    auto=add
    dpdaction=clear
    dpddelay=30s
    dpdtimeout=120s

conn fynx-server-to-strongswan-client
    left=%any
    leftid=client@example.com
    leftauth=psk
    right=127.0.0.1
    rightid=server@example.com
    rightauth=psk
    ike=aes128gcm16-prfsha256-modp2048!
    esp=aes128gcm16-esn!
    keyexchange=ikev2
    auto=start
    dpdaction=clear
    dpddelay=30s
```

### 2. Secrets Configuration

Create `/etc/strongswan/ipsec.secrets`:

```
# PSK for Fynx interop testing
: PSK "fynx-interop-test-key-32-bytes"
```

**Important**: This key must match the key used in Fynx tests.

### 3. strongSwan Commands

```bash
# Start strongSwan
sudo ipsec start

# Check status
sudo ipsec status

# Bring up connection
sudo ipsec up fynx-client-to-strongswan-server

# Bring down connection
sudo ipsec down fynx-client-to-strongswan-server

# Stop strongSwan
sudo ipsec stop

# Restart strongSwan
sudo ipsec restart

# View logs
sudo journalctl -u strongswan -f
```

---

## Test Scenarios

### Scenario 1: Fynx Client → strongSwan Server

**Goal**: Verify Fynx can initiate connection to strongSwan.

**Steps**:
1. Start strongSwan server: `sudo ipsec start`
2. Wait for strongSwan to be ready
3. Run Fynx client test: `cargo test --test interop_strongswan test_fynx_client_to_strongswan`
4. Verify IKE handshake completes
5. Verify ESP packets are exchanged
6. Verify data transfer works

**Expected Result**:
- IKE_SA_INIT exchange succeeds
- IKE_AUTH exchange succeeds
- Child SA established
- Data transfer successful

### Scenario 2: strongSwan Client → Fynx Server

**Goal**: Verify strongSwan can connect to Fynx server.

**Steps**:
1. Start Fynx server: `cargo run --example ipsec_server --features ipsec`
2. Wait for Fynx server to bind to port 500
3. Start strongSwan client: `sudo ipsec up fynx-server-to-strongswan-client`
4. Verify connection in strongSwan logs
5. Send test data through tunnel
6. Verify data received by Fynx

**Expected Result**:
- strongSwan initiates connection
- Fynx responds correctly
- Tunnel established
- Bidirectional data transfer works

### Scenario 3: Cipher Suite Negotiation

**Test cipher suites**:
- AES-128-GCM
- AES-256-GCM
- ChaCha20-Poly1305

**Configuration**: Update `ike=` and `esp=` lines in ipsec.conf for each test.

### Scenario 4: NAT Traversal (NAT-T)

**Goal**: Verify NAT-T works correctly.

**Steps**:
1. Configure NAT router or use network namespace
2. Place Fynx client behind NAT
3. Verify NAT detection (UDP 4500)
4. Verify ESP-in-UDP encapsulation

### Scenario 5: Dead Peer Detection (DPD)

**Goal**: Verify DPD detects failed peers.

**Steps**:
1. Establish tunnel
2. Kill peer process without sending DELETE
3. Verify DPD timeout triggers
4. Verify tunnel is torn down

### Scenario 6: SA Rekeying

**Goal**: Verify rekeying works without data loss.

**Steps**:
1. Configure short SA lifetime (60 seconds)
2. Establish tunnel
3. Send continuous data stream
4. Wait for rekey trigger
5. Verify rekey succeeds
6. Verify no data loss during rekey

---

## Test Framework

### Test File Structure

```
crates/proto/tests/interop/
├── mod.rs                    # Test module
├── strongswan.rs             # strongSwan interop tests
├── common.rs                 # Common test utilities
└── README.md                 # Test documentation
```

### Running Tests

```bash
# Run all interop tests (requires strongSwan)
cargo test --test interop_strongswan --features ipsec -- --test-threads=1

# Run specific test
cargo test --test interop_strongswan test_fynx_client_to_strongswan -- --nocapture

# Enable verbose logging
RUST_LOG=fynx_proto::ipsec=trace cargo test --test interop_strongswan -- --nocapture
```

**Important**: Use `--test-threads=1` to avoid port conflicts.

---

## Packet Capture

### Capturing IKE/ESP Packets

```bash
# Capture IKE and NAT-T traffic
sudo tcpdump -i any -w ipsec-interop.pcap 'udp port 500 or udp port 4500'

# Capture for specific duration (60 seconds)
timeout 60s sudo tcpdump -i any -w ipsec-interop.pcap 'udp port 500 or udp port 4500'
```

### Analyzing with Wireshark

1. Open `ipsec-interop.pcap` in Wireshark
2. Verify IKE_SA_INIT messages
3. Verify IKE_AUTH messages
4. Check proposal negotiation
5. Verify ESP packets (may be encrypted)

### Decrypting ESP in Wireshark

Wireshark can decrypt ESP if you provide keys:

1. Edit → Preferences → Protocols → ESP
2. Add ESP SA with:
   - Protocol: ESP
   - SPI: (from packet capture)
   - Encryption: AES-GCM-128/256
   - Encryption Key: (derived key - requires extraction from code)

---

## Troubleshooting

### Issue 1: strongSwan Fails to Start

**Symptoms**: `sudo ipsec start` fails

**Solutions**:
```bash
# Check strongSwan status
sudo ipsec status

# Check logs
sudo journalctl -u strongswan -n 50

# Verify configuration syntax
sudo ipsec checkconfig

# Restart strongSwan
sudo ipsec restart
```

### Issue 2: Connection Timeout

**Symptoms**: Fynx client times out connecting to strongSwan

**Solutions**:
- Verify strongSwan is listening: `sudo ss -ulnp | grep 500`
- Check firewall: `sudo iptables -L -n | grep 500`
- Verify PSK matches on both sides
- Check strongSwan logs: `sudo journalctl -u strongswan -f`

### Issue 3: NO_PROPOSAL_CHOSEN

**Symptoms**: Handshake fails with NO_PROPOSAL_CHOSEN error

**Solutions**:
- Compare proposals in both configurations
- Ensure at least one matching cipher suite
- Check DH group compatibility
- Verify transform types match

### Issue 4: AUTHENTICATION_FAILED

**Symptoms**: IKE_AUTH fails with authentication error

**Solutions**:
- Verify PSK is identical on both sides (case-sensitive)
- Check identity strings match configuration
- Ensure PSK is correctly configured in ipsec.secrets

### Issue 5: ESP Packets Not Decrypting

**Symptoms**: ESP packets received but decryption fails

**Solutions**:
- Verify keys were derived correctly
- Check SPI matches on both sides
- Verify cipher suite matches
- Check for sequence number issues

---

## Success Criteria

Phase 5 Stage 4 is complete when:

- ✅ Fynx client can connect to strongSwan server
- ✅ strongSwan client can connect to Fynx server
- ✅ All supported cipher suites work
- ✅ NAT-T detection and encapsulation works
- ✅ DPD correctly detects peer failures
- ✅ SA rekeying works without data loss
- ✅ ESP packets decrypt correctly on both sides
- ✅ No interoperability issues found

---

## Test Results Template

### Test Run Information

- **Date**: YYYY-MM-DD
- **Environment**: Ubuntu 22.04 / macOS 13.0
- **strongSwan Version**: 5.9.x
- **Fynx Version**: 0.1.0-alpha.1

### Test Results

| Test Scenario | Status | Notes |
|---------------|--------|-------|
| Fynx Client → strongSwan Server | ⏳ Not Run | |
| strongSwan Client → Fynx Server | ⏳ Not Run | |
| AES-128-GCM | ⏳ Not Run | |
| AES-256-GCM | ⏳ Not Run | |
| ChaCha20-Poly1305 | ⏳ Not Run | |
| NAT-T | ⏳ Not Run | |
| DPD | ⏳ Not Run | |
| IKE SA Rekey | ⏳ Not Run | |
| Child SA Rekey | ⏳ Not Run | |

### Issues Found

(List any interoperability issues discovered)

---

## Continuous Integration

### GitHub Actions Workflow (Future)

```yaml
name: IPSec Interoperability Tests

on:
  push:
    branches: [ main, feature/ipsec ]
  pull_request:
    branches: [ main ]

jobs:
  interop-test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Install strongSwan
      run: |
        sudo apt update
        sudo apt install -y strongswan strongswan-pki

    - name: Configure strongSwan
      run: |
        sudo cp tests/interop/ipsec.conf /etc/strongswan/
        sudo cp tests/interop/ipsec.secrets /etc/strongswan/

    - name: Start strongSwan
      run: sudo ipsec start

    - name: Run Interop Tests
      run: cargo test --test interop_strongswan --features ipsec -- --test-threads=1

    - name: Collect Logs
      if: failure()
      run: |
        sudo ipsec status
        sudo journalctl -u strongswan -n 100
```

---

## References

- [strongSwan Documentation](https://docs.strongswan.org/)
- [strongSwan Configuration Examples](https://wiki.strongswan.org/projects/strongswan/wiki/UsableExamples)
- [IKEv2 RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296)
- [ESP RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303)

---

**Status**: Framework complete, awaiting manual test execution on Linux/macOS with strongSwan installed.
