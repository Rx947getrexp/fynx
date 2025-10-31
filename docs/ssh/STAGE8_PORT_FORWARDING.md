# Stage 8: SSH Port Forwarding Implementation

**Status**: 🚧 In Progress
**Branch**: `feature/ssh-port-forwarding`
**Started**: 2025-10-31
**Target Completion**: 2025-11-07 (7 days)

---

## 📋 Overview

Implement complete SSH port forwarding functionality supporting three modes:
- **Local Forward** (`-L`): Forward local ports to remote destinations
- **Remote Forward** (`-R`): Forward remote ports to local destinations
- **Dynamic Forward** (`-D`): SOCKS5 proxy for dynamic port forwarding

## 🎯 Goals

### Primary Goals
1. ✅ Local port forwarding (Direct TCP/IP)
2. ✅ Remote port forwarding (tcpip-forward)
3. ✅ Dynamic port forwarding (SOCKS5 proxy)
4. ✅ Comprehensive testing
5. ✅ Usage examples and documentation

### Success Criteria
- [ ] All three forwarding modes working
- [ ] 20+ unit tests (100% pass rate)
- [ ] 3+ integration tests
- [ ] Example programs for each mode
- [ ] Updated API documentation
- [ ] Zero compilation warnings

---

## 🏗️ Architecture

### Existing Foundation

Already implemented in codebase:
- ✅ `ChannelType::DirectTcpip` - Protocol support for local forward
- ✅ `ChannelType::ForwardedTcpip` - Protocol support for remote forward
- ✅ `MessageType::GlobalRequest` - For tcpip-forward requests
- ✅ Channel serialization/deserialization

### New Components to Add

```
crates/proto/src/ssh/
├── forwarding/
│   ├── mod.rs              # Public API exports
│   ├── local.rs            # Local forward implementation
│   ├── remote.rs           # Remote forward implementation
│   ├── dynamic.rs          # SOCKS5 proxy implementation
│   └── types.rs            # Common types and utilities
└── client.rs               # Add forwarding methods
```

---

## 📐 Design

### 1. Local Forward (Direct TCP/IP)

**RFC**: RFC 4254 Section 7.2

**Use Case**: Forward `localhost:8080` to `database.internal:3306`

```rust
// User API
client.local_forward("localhost:8080", "database.internal:3306").await?;

// What happens:
// 1. Listen on localhost:8080
// 2. When connection arrives, open SSH channel (direct-tcpip)
// 3. Relay data bidirectionally
```

**Flow**:
```
User App          SSH Client         SSH Server         Target
   |                  |                  |                 |
   |--connect 8080--->|                  |                 |
   |                  |--CHANNEL_OPEN--->|                 |
   |                  | (direct-tcpip)   |--connect 3306-->|
   |                  |<-CONFIRM---------|                 |
   |<--established----|                  |                 |
   |<===== data relay =====================================>|
```

**Implementation**:
```rust
pub struct LocalForward {
    listener: TcpListener,
    target_host: String,
    target_port: u16,
    client: Arc<Mutex<SshClient>>,
}

impl LocalForward {
    pub async fn run(&mut self) -> FynxResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let client = self.client.clone();
            let target = (self.target_host.clone(), self.target_port);

            tokio::spawn(async move {
                Self::handle_connection(stream, client, target).await
            });
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        client: Arc<Mutex<SshClient>>,
        (host, port): (String, u16),
    ) -> FynxResult<()> {
        // 1. Open direct-tcpip channel
        let channel = client.lock().await
            .open_direct_tcpip(&host, port).await?;

        // 2. Bidirectional relay
        tokio::io::copy_bidirectional(&mut stream, &mut channel).await?;

        Ok(())
    }
}
```

### 2. Remote Forward (tcpip-forward)

**RFC**: RFC 4254 Section 7.1

**Use Case**: Forward `remote:8080` to `localhost:3000`

```rust
// User API
client.remote_forward("0.0.0.0:8080", "localhost:3000").await?;

// What happens:
// 1. Send global request "tcpip-forward" to server
// 2. Server listens on 0.0.0.0:8080
// 3. When connection arrives, server opens channel (forwarded-tcpip)
// 4. Client connects to localhost:3000 and relays data
```

**Flow**:
```
Local App         SSH Client         SSH Server         Remote User
   |                  |                  |                   |
   |                  |--GLOBAL_REQ----->|                   |
   |                  | (tcpip-forward)  |                   |
   |                  |<--SUCCESS--------|                   |
   |                  |                  |<--connect 8080----|
   |                  |<-CHANNEL_OPEN----|                   |
   |                  | (forwarded-tcpip)|                   |
   |<--connect 3000---|                  |                   |
   |<===================== data relay ======================>|
```

**Implementation**:
```rust
pub struct RemoteForward {
    bind_address: String,
    bind_port: u16,
    local_host: String,
    local_port: u16,
}

impl RemoteForward {
    pub async fn setup(&self, client: &mut SshClient) -> FynxResult<()> {
        // Send global request "tcpip-forward"
        client.send_global_request(
            "tcpip-forward",
            true, // want reply
            &[
                ("address to bind", &self.bind_address),
                ("port to bind", &self.bind_port),
            ]
        ).await?;

        // Wait for success reply
        client.wait_request_success().await?;

        Ok(())
    }

    pub async fn handle_forwarded_channel(
        &self,
        channel: SshChannel,
    ) -> FynxResult<()> {
        // Connect to local target
        let mut local_stream = TcpStream::connect(
            (self.local_host.as_str(), self.local_port)
        ).await?;

        // Bidirectional relay
        tokio::io::copy_bidirectional(&mut local_stream, &mut channel).await?;

        Ok(())
    }
}
```

### 3. Dynamic Forward (SOCKS5)

**RFC**: RFC 1928 (SOCKS5)

**Use Case**: SOCKS5 proxy on `localhost:1080`

```rust
// User API
client.dynamic_forward("localhost:1080").await?;

// What happens:
// 1. Listen on localhost:1080 as SOCKS5 proxy
// 2. Parse SOCKS5 handshake to get target
// 3. Open direct-tcpip channel to target
// 4. Relay data bidirectionally
```

**SOCKS5 Handshake**:
```
Client → Proxy: [version, methods...]
Proxy → Client: [version, chosen method]
Client → Proxy: [version, command, target host, target port]
Proxy → Client: [version, status, bound address, bound port]
<bidirectional data>
```

**Implementation**:
```rust
pub struct DynamicForward {
    listener: TcpListener,
    client: Arc<Mutex<SshClient>>,
}

impl DynamicForward {
    async fn handle_socks5(
        mut stream: TcpStream,
        client: Arc<Mutex<SshClient>>,
    ) -> FynxResult<()> {
        // 1. SOCKS5 handshake
        let (host, port) = socks5_handshake(&mut stream).await?;

        // 2. Open SSH channel to target
        let mut channel = client.lock().await
            .open_direct_tcpip(&host, port).await?;

        // 3. Send success to SOCKS client
        socks5_send_success(&mut stream).await?;

        // 4. Bidirectional relay
        tokio::io::copy_bidirectional(&mut stream, &mut channel).await?;

        Ok(())
    }
}

// SOCKS5 protocol helpers
async fn socks5_handshake(stream: &mut TcpStream) -> FynxResult<(String, u16)> {
    // Read greeting: [version, nmethods, methods...]
    let mut buf = [0u8; 257];
    stream.read_exact(&mut buf[..2]).await?;

    if buf[0] != 5 { // SOCKS version 5
        return Err(FynxError::Protocol("Invalid SOCKS version".into()));
    }

    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    // Send method selection: [version, method]
    // 0x00 = no authentication required
    stream.write_all(&[5, 0]).await?;

    // Read request: [version, command, reserved, address type, address, port]
    stream.read_exact(&mut buf[..4]).await?;

    if buf[1] != 1 { // CONNECT command
        return Err(FynxError::Protocol("Only CONNECT supported".into()));
    }

    let address_type = buf[3];
    let (host, port) = match address_type {
        1 => { // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            (ip, port)
        }
        3 => { // Domain name
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
            let host = String::from_utf8_lossy(&buf[..len]).to_string();
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            (host, port)
        }
        4 => { // IPv6
            stream.read_exact(&mut buf[..18]).await?;
            // Parse IPv6 address...
            todo!("IPv6 support")
        }
        _ => return Err(FynxError::Protocol("Invalid address type".into())),
    };

    Ok((host, port))
}

async fn socks5_send_success(stream: &mut TcpStream) -> FynxResult<()> {
    // [version, status, reserved, address type, address, port]
    // Status 0 = succeeded
    stream.write_all(&[
        5, 0, 0, 1,           // version, success, reserved, IPv4
        0, 0, 0, 0,           // Bound address (0.0.0.0)
        0, 0,                 // Bound port (0)
    ]).await?;
    Ok(())
}
```

---

## 📝 Implementation Plan

### Phase 1: Local Forward (Days 1-2)

- [x] Create `forwarding/` module structure
- [ ] Implement `LocalForward` struct
- [ ] Add `SshClient::local_forward()` method
- [ ] Add `SshClient::open_direct_tcpip()` helper
- [ ] Implement bidirectional data relay
- [ ] Write unit tests
- [ ] Write integration test
- [ ] Create example: `examples/ssh_local_forward.rs`

### Phase 2: Remote Forward (Days 3-4)

- [ ] Implement `RemoteForward` struct
- [ ] Add `SshClient::remote_forward()` method
- [ ] Add `SshClient::send_global_request()` helper
- [ ] Handle incoming `forwarded-tcpip` channels
- [ ] Implement connection to local target
- [ ] Write unit tests
- [ ] Write integration test
- [ ] Create example: `examples/ssh_remote_forward.rs`

### Phase 3: Dynamic Forward (Days 5-6)

- [ ] Implement SOCKS5 protocol helpers
- [ ] Implement `DynamicForward` struct
- [ ] Add `SshClient::dynamic_forward()` method
- [ ] Handle SOCKS5 handshake
- [ ] Support IPv4 and domain names
- [ ] Write unit tests
- [ ] Write integration test
- [ ] Create example: `examples/ssh_dynamic_forward.rs`

### Phase 4: Testing & Documentation (Day 7)

- [ ] Review all code
- [ ] Run `cargo clippy`
- [ ] Run `cargo test`
- [ ] Update SSH README
- [ ] Update API documentation
- [ ] Create usage guide
- [ ] Performance testing

---

## 🧪 Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_forward_channel_open() {
        // Test opening direct-tcpip channel
    }

    #[tokio::test]
    async fn test_remote_forward_global_request() {
        // Test sending tcpip-forward request
    }

    #[tokio::test]
    async fn test_socks5_handshake_ipv4() {
        // Test SOCKS5 with IPv4 address
    }

    #[tokio::test]
    async fn test_socks5_handshake_domain() {
        // Test SOCKS5 with domain name
    }
}
```

### Integration Tests

```rust
// tests/ssh_forwarding.rs

#[tokio::test]
async fn test_local_forward_http() {
    // 1. Start HTTP server on port 8000
    // 2. Start SSH server
    // 3. Connect SSH client with local forward localhost:9000 -> localhost:8000
    // 4. Make HTTP request to localhost:9000
    // 5. Verify response received
}

#[tokio::test]
async fn test_remote_forward() {
    // 1. Start local HTTP server on port 3000
    // 2. Start SSH server
    // 3. Connect SSH client with remote forward server:8080 -> localhost:3000
    // 4. Make HTTP request to server:8080
    // 5. Verify response received from local server
}

#[tokio::test]
async fn test_dynamic_forward_socks5() {
    // 1. Start SSH server
    // 2. Connect SSH client with dynamic forward localhost:1080
    // 3. Configure HTTP client to use SOCKS5 proxy
    // 4. Make HTTP request through proxy
    // 5. Verify request succeeded
}
```

---

## 📚 API Design

### Client Methods

```rust
impl SshClient {
    /// Start local port forwarding.
    ///
    /// Forwards connections from local address to remote target through SSH.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::client::SshClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = SshClient::connect("server:22").await?;
    /// client.authenticate_password("user", "pass").await?;
    ///
    /// // Forward localhost:8080 to database.internal:3306
    /// let forward = client.local_forward(
    ///     "localhost:8080",
    ///     "database.internal:3306"
    /// ).await?;
    ///
    /// // Run until stopped (Ctrl+C)
    /// forward.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn local_forward(
        &mut self,
        bind_address: &str,
        target_address: &str,
    ) -> FynxResult<LocalForward>;

    /// Start remote port forwarding.
    ///
    /// Asks server to forward connections to you.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::client::SshClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = SshClient::connect("server:22").await?;
    /// client.authenticate_password("user", "pass").await?;
    ///
    /// // Forward remote:8080 to localhost:3000
    /// let forward = client.remote_forward(
    ///     "0.0.0.0:8080",
    ///     "localhost:3000"
    /// ).await?;
    ///
    /// // Handle incoming connections
    /// forward.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn remote_forward(
        &mut self,
        bind_address: &str,
        local_address: &str,
    ) -> FynxResult<RemoteForward>;

    /// Start dynamic port forwarding (SOCKS5 proxy).
    ///
    /// Creates a SOCKS5 proxy server on local address.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use fynx_proto::ssh::client::SshClient;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = SshClient::connect("server:22").await?;
    /// client.authenticate_password("user", "pass").await?;
    ///
    /// // Create SOCKS5 proxy on localhost:1080
    /// let proxy = client.dynamic_forward("localhost:1080").await?;
    ///
    /// // Run proxy
    /// proxy.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dynamic_forward(
        &mut self,
        bind_address: &str,
    ) -> FynxResult<DynamicForward>;
}
```

---

## 🔍 References

### RFCs
- **RFC 4254** - SSH Connection Protocol (Sections 7.1, 7.2)
- **RFC 1928** - SOCKS Protocol Version 5

### OpenSSH Implementation
- `channels.c` - Channel management
- `clientloop.c` - Port forwarding handling
- `serverloop.c` - Server-side forwarding

### Similar Implementations
- **Thrussh**: https://github.com/warp-tech/russh
- **libssh**: https://www.libssh.org/

---

## ✅ Completion Checklist

### Code
- [ ] All three forwarding modes implemented
- [ ] Zero compilation warnings
- [ ] Zero clippy warnings
- [ ] Code formatted with `cargo fmt`

### Tests
- [ ] 20+ unit tests (100% pass)
- [ ] 3+ integration tests (100% pass)
- [ ] Manual testing with real SSH servers

### Documentation
- [ ] Rustdoc for all public APIs
- [ ] Usage examples in docs
- [ ] 3 example programs
- [ ] Updated SSH README.md
- [ ] Updated CHANGELOG.md

### Quality
- [ ] Code review
- [ ] Security review
- [ ] Performance review
- [ ] Cross-platform testing (Windows, Linux, macOS)

---

**Maintainer**: Fynx Core Team
**Reviewers**: TBD
**Last Updated**: 2025-10-31
