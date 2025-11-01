# Release v0.1.0-alpha.3 - SSH Enhancements 🚀

**发布日期**: 2025-11-01
**类型**: Alpha Release (技术预览版)
**重要性**: 主要功能更新

---

## 📋 概述

此版本为 Fynx 项目带来了全面的 SSH 协议增强，包括 SFTP 文件传输协议和端口转发功能。这是一个重大的功能更新版本，添加了约 **6800 行**新代码，同时保持 **100% 向后兼容**。

---

## ✨ 新增功能

### 1. 📁 SFTP 文件传输协议

完整的 SFTP v3 协议实现，支持安全的远程文件操作。

**功能特性**:
- ✅ **文件上传** - 高效的 32KB 分块上传
- ✅ **文件下载** - 流式下载，支持大文件
- ✅ **目录列表** - 完整的文件属性信息
- ✅ **简洁 API** - 一行代码创建 SFTP 会话

**使用示例**:
```rust
use fynx_proto::ssh::SshClient;

// 连接并认证
let mut client = SshClient::connect("server:22").await?;
client.authenticate_password("user", "password").await?;

// 创建 SFTP 会话
let mut sftp = client.sftp().await?;

// 文件操作
sftp.upload("local.txt", "/remote/file.txt").await?;
sftp.download("/remote/data", "local_data").await?;

// 目录列表
let entries = sftp.readdir("/remote/path").await?;
for (filename, attrs) in entries {
    println!("{}: {} bytes", filename, attrs.size.unwrap_or(0));
}
```

**协议合规性**:
- 遵循 SFTP v3 draft 规范
- 25 种消息类型
- 9 种错误码
- 完整的文件属性系统

---

### 2. 🔀 端口转发

全面的 SSH 端口转发支持，包括三种转发模式。

#### Local Forwarding (本地 → 远程)
将本地端口转发到远程服务器。

**使用场景**: 访问远程内网服务

**示例**:
```rust
// 监听本地 8080，转发到远程 192.168.1.100:80
let forward = LocalForward::new(
    "127.0.0.1:8080",
    "192.168.1.100:80",
    connection,
    dispatcher
).await?;

forward.start().await?;
// 现在访问 localhost:8080 相当于访问远程的 192.168.1.100:80
```

#### Remote Forwarding (远程 → 本地)
将远程端口转发到本地服务器。

**使用场景**: 公开本地服务到远程

**示例**:
```rust
// 远程监听 9000，转发到本地 127.0.0.1:3000
let forward = RemoteForward::new(
    "0.0.0.0:9000",
    "127.0.0.1:3000",
    connection,
    dispatcher
).await?;

forward.start().await?;
```

#### Dynamic Forwarding (SOCKS5 代理)
创建 SOCKS5 代理服务器，动态转发请求。

**使用场景**: 浏览器代理、全局流量转发

**示例**:
```rust
// 在本地 1080 端口启动 SOCKS5 代理
let forward = DynamicForward::new(
    "127.0.0.1:1080",
    connection,
    dispatcher
).await?;

forward.start().await?;
// 配置浏览器使用 SOCKS5 代理 localhost:1080
```

---

### 3. ⚡ 异步多通道架构

全新的异步架构，支持并发多通道操作。

**特性**:
- 🔄 **消息调度器** - 自动路由 SSH 消息到对应通道
- 🔗 **共享连接** - 多个通道共享一个 TCP 连接
- ⏱️ **非阻塞 I/O** - 基于 Tokio 的异步操作
- 🛡️ **线程安全** - 使用 Arc<Mutex<>> 保证安全性

**架构组件**:
- `SshConnection` - 共享连接抽象
- `MessageDispatcher` - 消息路由调度
- `SshChannel` - 异步消息通道

---

### 4. 🔄 会话管理增强

改进的会话管理功能，提高连接稳定性。

**功能**:
- ❤️ **Keep-alive 心跳** - 定期发送心跳保持连接
- 🔁 **自动重连** - 连接断开时自动重新连接
- 🏊 **连接池** - 复用连接，提高性能

**配置示例**:
```rust
let mut config = SshClientConfig::default();
config.keepalive_interval = Some(Duration::from_secs(30));
config.reconnect = ReconnectConfig {
    enabled: true,
    max_retries: 3,
    initial_backoff: Duration::from_secs(1),
    max_backoff: Duration::from_secs(60),
};

let client = SshClient::connect_with_config("server:22", config).await?;
```

---

## 📊 质量指标

### 测试覆盖
- ✅ **583 个测试**全部通过
  - 219 个 SSH 测试
  - 364 个 IPSec 测试
- ✅ **0 个测试失败**
- ✅ **1 个测试忽略**（预期）

### 代码质量
- ✅ **7 个 Clippy 警告**（全部可接受）
- ✅ **零 unsafe 代码**
- ✅ **完整文档覆盖**
- ✅ **格式化一致**

### 兼容性
- ✅ **零破坏性变更**
- ✅ **向后兼容 100%**
- ✅ **所有新功能可选**

---

## 🔧 API 变更

### 新增公共 API

#### SshClient 新方法
```rust
impl SshClient {
    /// 创建 SFTP 会话（自动启用异步模式）
    pub async fn sftp(&mut self) -> FynxResult<SftpClient>;

    /// 启用异步多通道模式
    pub async fn enable_async_mode(&mut self) -> FynxResult<()>;

    /// 检查是否已启用异步模式
    pub fn is_async_mode(&self) -> bool;

    /// 打开新的 SSH 通道
    pub async fn open_channel(&mut self, channel_type: ChannelType)
        -> FynxResult<SshChannel>;

    /// 获取共享连接（异步模式）
    pub fn connection(&self) -> Option<Arc<Mutex<SshConnection>>>;

    /// 获取消息调度器（异步模式）
    pub fn dispatcher(&self) -> Option<Arc<Mutex<MessageDispatcher>>>;
}
```

#### SFTP 类型导出
```rust
pub use sftp::{
    FileAttributes,  // 文件属性
    FileMode,        // 文件权限
    FileType,        // 文件类型
    SftpClient,      // SFTP 客户端
    SftpError,       // SFTP 错误
    SftpErrorCode,   // SFTP 错误码
};
```

#### 端口转发类型导出
```rust
pub use forwarding::{
    parse_forward_addr,  // 解析转发地址
    DynamicForward,      // 动态转发（SOCKS5）
    ForwardAddr,         // 转发地址类型
    LocalForward,        // 本地转发
    RemoteForward,       // 远程转发
};
```

### 依赖变更
```toml
# 新增 tokio "fs" 特性用于 SFTP 文件操作
tokio = { version = "1.35", features = ["net", "io-util", "sync", "time", "rt", "fs"] }
```

---

## ⚠️ 已知限制

### 1. RemoteForward 未来工作
- ✅ 已实现转发请求发送
- ⚠️ 待实现 forwarded-tcpip 消息处理
- 📅 计划在下个版本完成

### 2. 异步模式限制
- ⚠️ `enable_async_mode()` 当前不支持现有连接
- ℹ️ 需要在连接时启用异步模式
- 📅 未来版本将支持动态切换

### 3. 集成测试
- ✅ 单元测试完整
- ⚠️ 需要真实 SSH 服务器的集成测试
- 📅 计划添加 Docker 容器测试环境

---

## 📦 安装和使用

### 添加依赖

**Cargo.toml**:
```toml
[dependencies]
fynx-proto = "0.1.0-alpha.3"
tokio = { version = "1", features = ["full"] }
```

### 启用特性

```toml
# 仅 SSH 功能
fynx-proto = { version = "0.1.0-alpha.3", features = ["ssh"] }

# SSH + IPSec
fynx-proto = { version = "0.1.0-alpha.3", features = ["ssh", "ipsec"] }
```

### 完整示例

```rust
use fynx_proto::ssh::{SshClient, SshClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 连接到 SSH 服务器
    let mut client = SshClient::connect("example.com:22").await?;

    // 2. 认证
    client.authenticate_password("user", "password").await?;

    // 3. 使用 SFTP
    let mut sftp = client.sftp().await?;
    sftp.upload("local.txt", "/remote/file.txt").await?;

    println!("File uploaded successfully!");

    Ok(())
}
```

---

## 🔄 从 v0.1.0-alpha.2 升级

### 升级步骤

1. **更新 Cargo.toml**:
   ```toml
   fynx-proto = "0.1.0-alpha.3"
   ```

2. **运行 `cargo update`**:
   ```bash
   cargo update fynx-proto
   ```

3. **（可选）使用新功能**:
   ```rust
   // SFTP
   let sftp = client.sftp().await?;

   // 端口转发
   let forward = LocalForward::new(...).await?;
   ```

### ⚠️ 破坏性变更

**无破坏性变更** - 所有现有代码无需修改即可继续工作。

---

## 📚 文档

### 新增文档
- `MERGE_CHECKLIST.md` - 合并前审查清单
- `docs/ssh/STAGE8_PORT_FORWARDING.md` - 端口转发设计文档
- `docs/ssh/STAGE9_SESSION_MANAGEMENT.md` - 会话管理文档
- `docs/ssh/ARCHITECTURE_DECISION_PORT_FORWARDING.md` - 架构决策

### 在线文档
- 📖 [API 文档](https://docs.rs/fynx-proto/0.1.0-alpha.3)
- 🏠 [项目主页](https://github.com/Rx947getrexp/fynx)

---

## 🙏 致谢

感谢所有测试和反馈的用户！

---

## 📝 更新日志

### v0.1.0-alpha.3 (2025-11-01)

#### 新增
- SFTP v3 协议完整实现
- 端口转发（Local, Remote, Dynamic）
- 异步多通道架构
- 会话管理增强

#### 改进
- 代码质量提升（Clippy 警告减少）
- 文档完善
- 测试覆盖增加

#### 修复
- 无（此版本专注于新功能）

---

## 🔗 相关链接

- 🐛 [报告问题](https://github.com/Rx947getrexp/fynx/issues)
- 💬 [讨论区](https://github.com/Rx947getrexp/fynx/discussions)
- 📖 [完整变更日志](https://github.com/Rx947getrexp/fynx/blob/main/CHANGELOG.md)

---

## ⚡ 快速开始

```bash
# 克隆仓库
git clone https://github.com/Rx947getrexp/fynx.git
cd fynx

# 运行示例
cargo run --example ssh_sftp_demo

# 运行测试
cargo test --features ssh
```

---

## 📄 许可证

MIT OR Apache-2.0

---

**注意**: 这是一个 **Alpha 版本**，不建议在生产环境中使用。API 可能会在未来版本中发生变化。

---

**下载**: [GitHub Release](https://github.com/Rx947getrexp/fynx/releases/tag/v0.1.0-alpha.3)

**发布者**: Fynx Core Team
**发布时间**: 2025-11-01
