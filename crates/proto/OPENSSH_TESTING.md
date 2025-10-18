# OpenSSH Interoperability Testing Guide

This guide explains how to test the fynx SSH implementation against real OpenSSH servers and clients.

## Prerequisites

### Linux/macOS

```bash
# Install OpenSSH server (if not already installed)
# Ubuntu/Debian
sudo apt-get install openssh-server

# macOS
# OpenSSH is pre-installed

# Fedora/RHEL
sudo dnf install openssh-server
```

### Windows

```powershell
# Install OpenSSH Server (Windows 10/11)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

## Test 1: fynx Client → OpenSSH Server

### Setup

1. **Start OpenSSH Server**

```bash
# Linux
sudo systemctl start sshd
sudo systemctl status sshd

# Windows
# Already started from prerequisites
```

2. **Create Test User** (Optional, for authentication tests)

```bash
# Linux
sudo useradd -m -s /bin/bash sshtest
echo "sshtest:testpass123" | sudo chpasswd

# Enable password authentication in /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config
# Ensure: PasswordAuthentication yes
sudo systemctl restart sshd
```

### Run Tests

```bash
cd fynx/crates/proto

# Test 1: Basic connection (version exchange + KEX)
cargo test --test openssh_interop test_connect_to_openssh_localhost -- --ignored --nocapture

# Test 2: Password authentication
export SSH_TEST_USER="sshtest"
export SSH_TEST_PASS="testpass123"
cargo test --test openssh_interop test_password_auth_with_openssh -- --ignored --nocapture

# Test 3: Command execution
cargo test --test openssh_interop test_execute_command_openssh -- --ignored --nocapture

# Test 4: Protocol negotiation details
cargo test --test openssh_interop test_protocol_negotiation -- --ignored --nocapture

# Run all OpenSSH interop tests
cargo test --test openssh_interop -- --ignored --nocapture
```

### Expected Results

✅ **Success Criteria:**
- Connection establishes successfully
- Version exchange completes
- Curve25519 key exchange succeeds
- Host key verification works (Ed25519 or RSA)
- Password authentication succeeds (if credentials provided)
- Command execution returns output

⚠️ **Potential Issues:**
- OpenSSH rejects chacha20-poly1305: Server doesn't support this cipher
  - **Solution**: Need to implement AES-128-CTR or AES-256-CTR (Stage 6)
- KEX algorithm mismatch: Server doesn't support curve25519-sha256
  - **Solution**: Need to implement diffie-hellman-group14-sha256
- Host key algorithm mismatch: Server doesn't support ssh-ed25519
  - **Solution**: Already supported (rsa-sha2-256, rsa-sha2-512, ecdsa-*)

## Test 2: OpenSSH Client → fynx Server

### Setup

1. **Run fynx SSH Server Example**

```bash
cd fynx/crates/proto
cargo run --example simple_server
# Server will listen on 127.0.0.1:2222
```

2. **Connect with OpenSSH Client**

```bash
# Test connection
ssh -p 2222 testuser@127.0.0.1

# Verbose mode to see negotiation
ssh -vvv -p 2222 testuser@127.0.0.1

# With specific algorithms (if needed)
ssh -p 2222 -c chacha20-poly1305@openssh.com testuser@127.0.0.1
```

### Expected Results

✅ **Success:**
- OpenSSH client connects
- Version exchange completes
- KEX completes (curve25519-sha256)
- Authentication prompt appears
- Login succeeds with correct password (testuser/testpass)

## Test 3: Protocol Analysis

### Capture SSH Traffic

```bash
# On Linux/macOS - capture SSH traffic
sudo tcpdump -i lo port 22 -w ssh_traffic.pcap

# Analyze with Wireshark
wireshark ssh_traffic.pcap
```

### Check Negotiated Algorithms

```bash
# OpenSSH client verbose output shows negotiation
ssh -vvv -p 2222 testuser@127.0.0.1 2>&1 | grep -E "kex|cipher|mac|hostkey"
```

Expected output:
```
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ssh-ed25519
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
```

## Troubleshooting

### Issue: "Connection refused"

**Cause**: SSH server not running

**Solution**:
```bash
sudo systemctl start sshd
sudo systemctl status sshd
```

### Issue: "Permission denied (publickey)"

**Cause**: Password authentication disabled

**Solution**:
```bash
# Edit /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

# Change:
PasswordAuthentication yes

# Restart
sudo systemctl restart sshd
```

### Issue: "Algorithm negotiation failed"

**Cause**: fynx only supports modern algorithms

**Current Support:**
- KEX: curve25519-sha256, diffie-hellman-group14-sha256
- Cipher: chacha20-poly1305@openssh.com, aes128-gcm, aes256-gcm
- Host Key: ssh-ed25519, rsa-sha2-256, rsa-sha2-512, ecdsa-sha2-nistp256/384/521

**OpenSSH Defaults (recent versions):**
- Should work out of the box with modern OpenSSH

**Older OpenSSH versions:**
- May need AES-CTR (Stage 6) for compatibility

### Issue: "Host key verification failed"

**For testing only**:
```bash
# Disable strict host key checking (INSECURE - testing only!)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 testuser@127.0.0.1
```

## Compatibility Matrix

| OpenSSH Version | Expected Result | Notes |
|-----------------|-----------------|-------|
| 8.0+ | ✅ Full support | Modern algorithms |
| 7.4 - 7.9 | ✅ Should work | ChaCha20 supported since 6.5 |
| 7.0 - 7.3 | ⚠️ Partial | May need AES-CTR fallback |
| < 7.0 | ❌ Limited | Requires Stage 6 (AES-CTR) |

## Next Steps

After completing OpenSSH interop tests:

1. **Document Results**: Record which OpenSSH versions work
2. **Identify Gaps**: Note any algorithm negotiation failures
3. **Prioritize Stage 6**: If needed for compatibility
4. **Update Tests**: Add specific version tests

## Automated CI Testing

For CI environments without OpenSSH:

```yaml
# .github/workflows/openssh-interop.yml
name: OpenSSH Interoperability

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install OpenSSH
        run: sudo apt-get install -y openssh-server
      - name: Setup SSH
        run: |
          sudo systemctl start ssh
          sudo useradd -m sshtest
          echo "sshtest:testpass123" | sudo chpasswd
      - name: Run Tests
        env:
          SSH_TEST_USER: sshtest
          SSH_TEST_PASS: testpass123
        run: |
          cargo test --test openssh_interop -- --ignored
```

---

**Last Updated**: 2025-10-18
**fynx-proto Version**: 0.1.0
