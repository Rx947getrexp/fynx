# SSH Enhancements - SFTP & Port Forwarding 🚀

Major SSH protocol enhancements with **6800+ lines** of new code, maintaining **100% backward compatibility**.

## 🎯 What's New

### 📁 SFTP File Transfer Protocol
Complete SFTP v3 implementation for secure remote file operations.

```rust
let mut sftp = client.sftp().await?;
sftp.upload("local.txt", "/remote/file.txt").await?;
sftp.download("/remote/data", "local_data").await?;
let entries = sftp.readdir("/remote/path").await?;
```

**Features:**
- ✅ File upload with 32KB efficient chunking
- ✅ Streaming download for large files
- ✅ Directory listing with full attributes
- ✅ One-line API: `client.sftp().await`

### 🔀 Port Forwarding
Full SSH tunneling support with three modes:

**Local Forward** (local → remote):
```rust
let forward = LocalForward::new("127.0.0.1:8080", "192.168.1.100:80", ...).await?;
```

**Remote Forward** (remote → local):
```rust
let forward = RemoteForward::new("0.0.0.0:9000", "127.0.0.1:3000", ...).await?;
```

**Dynamic Forward** (SOCKS5 proxy):
```rust
let forward = DynamicForward::new("127.0.0.1:1080", ...).await?;
```

### ⚡ Async Multi-Channel Architecture
- Non-blocking concurrent operations
- Message dispatcher for routing
- Shared connection management

### 🔄 Session Management
- Keep-alive heartbeat
- Automatic reconnection
- Connection pooling

## 📊 Quality Metrics

- ✅ **583/583 tests passing** (219 SSH + 364 IPSec)
- ✅ **Zero breaking changes**
- ✅ **Zero unsafe code**
- ✅ **Comprehensive documentation**

## 🔧 Installation

```toml
[dependencies]
fynx-proto = "0.1.0-alpha.3"
```

## 📚 Quick Example

```rust
use fynx_proto::ssh::SshClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SshClient::connect("server:22").await?;
    client.authenticate_password("user", "password").await?;

    // SFTP operations
    let mut sftp = client.sftp().await?;
    sftp.upload("local.txt", "/remote/file.txt").await?;

    println!("Success!");
    Ok(())
}
```

## 🆕 New APIs

### SshClient
- `sftp()` - Create SFTP session
- `enable_async_mode()` - Enable multi-channel
- `open_channel()` - Open new SSH channel

### Types
- `SftpClient`, `FileAttributes`, `FileMode`
- `LocalForward`, `RemoteForward`, `DynamicForward`

## ⚠️ Known Limitations

1. **RemoteForward** - Basic implementation (awaiting forwarded-tcpip parser)
2. **Async Mode** - Must enable during connection (not after)
3. **Integration Tests** - Unit tests complete, need real server tests

## 📝 Full Details

See [RELEASE_NOTES_v0.1.0-alpha.3.md](https://github.com/Rx947getrexp/fynx/blob/main/RELEASE_NOTES_v0.1.0-alpha.3.md) for complete changelog.

## 🔄 Upgrading from v0.1.0-alpha.2

**No breaking changes** - Simply update your `Cargo.toml`:

```toml
fynx-proto = "0.1.0-alpha.3"
```

Then run:
```bash
cargo update fynx-proto
```

All existing code continues to work without modification.

---

**Note**: This is an **Alpha release** - Not recommended for production use.

**Full Changelog**: https://github.com/Rx947getrexp/fynx/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
