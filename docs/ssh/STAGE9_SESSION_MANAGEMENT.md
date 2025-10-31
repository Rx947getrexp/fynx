# STAGE 9: SSH 会话管理（Session Management）

**日期**: 2025-10-31
**状态**: ✅ 部分完成 (9.1 + 9.2 完成，9.3 待架构重构)
**优先级**: 🔴 高
**实际工作量**: 1 天 (9.1 + 9.2)

---

## 📋 概述

实现 SSH 会话管理功能，包括：
1. **Keep-alive 心跳**: 防止连接超时断开 ✅ **完成**
2. **自动重连机制**: 连接断开后自动重新连接 ✅ **完成**
3. **连接池**: 复用 SSH 连接，提高性能 ⏸️ **延期** (需要多通道支持)

**已完成**: 核心会话管理功能 (Keep-alive + Reconnection)
**待完成**: 连接池 (需配合 Phase 3 架构重构)

---

## 🎯 功能需求

### 1. Keep-alive 心跳

**描述**: 定期发送 SSH_MSG_IGNORE 消息保持连接活跃。

**用户故事**:
- 作为用户，我希望 SSH 连接在空闲时不被服务器或防火墙断开
- 作为用户，我希望能够配置心跳间隔
- 作为用户，我希望心跳在后台自动运行

**技术需求**:
- 支持配置心跳间隔（默认 60 秒）
- 使用 SSH_MSG_IGNORE 消息（RFC 4253）
- 后台任务定期发送心跳
- 检测发送失败并标记连接为断开

**API 设计**:
```rust
impl SshClientConfig {
    pub keepalive_interval: Option<Duration>,
}

impl SshClient {
    /// 启用 keep-alive 心跳
    pub fn start_keepalive(&mut self, interval: Duration) -> FynxResult<()>;

    /// 停止 keep-alive 心跳
    pub fn stop_keepalive(&mut self) -> FynxResult<()>;

    /// 检查连接是否仍然活跃
    pub fn is_alive(&self) -> bool;
}
```

**RFC 参考**:
- RFC 4253 Section 11.1: SSH_MSG_IGNORE message

---

### 2. 自动重连机制

**描述**: 检测连接断开并自动重新连接。

**用户故事**:
- 作为用户，我希望网络短暂中断后能自动恢复连接
- 作为用户，我希望能够配置重试次数和间隔
- 作为用户，我希望重连失败时能收到通知

**技术需求**:
- 检测连接断开（发送/接收失败）
- 自动重试连接（可配置次数和间隔）
- 重新进行认证
- 指数退避策略（1s, 2s, 4s, 8s, ...）
- 最大重试次数（默认 3 次）

**API 设计**:
```rust
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// 是否启用自动重连
    pub enabled: bool,
    /// 最大重试次数
    pub max_retries: u32,
    /// 初始重试间隔
    pub initial_backoff: Duration,
    /// 最大重试间隔
    pub max_backoff: Duration,
}

impl SshClientConfig {
    pub reconnect: ReconnectConfig,
}

impl SshClient {
    /// 启用自动重连
    pub fn enable_auto_reconnect(&mut self, config: ReconnectConfig);

    /// 禁用自动重连
    pub fn disable_auto_reconnect(&mut self);

    /// 手动触发重连
    pub async fn reconnect(&mut self) -> FynxResult<()>;
}
```

**重连流程**:
```
1. 检测连接断开
   ↓
2. 等待退避时间（1s）
   ↓
3. 尝试 TCP 连接
   ↓
4. 版本交换 + 密钥交换
   ↓
5. 重新认证
   ↓
6. 成功 → 恢复正常
   失败 → 增加退避时间，重试
```

---

### 3. 连接池

**描述**: 复用 SSH 连接，避免重复建立连接的开销。

**用户故事**:
- 作为用户，我希望复用 SSH 连接提高性能
- 作为用户，我希望连接池自动管理连接生命周期
- 作为用户，我希望能够配置连接池大小

**技术需求**:
- 基于 `(host, port, username)` 的连接缓存
- 最大连接数限制（默认 10）
- 连接空闲超时（默认 5 分钟）
- 自动清理过期连接
- 线程安全（Arc + Mutex）

**API 设计**:
```rust
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// 最大连接数
    pub max_connections: usize,
    /// 连接空闲超时
    pub idle_timeout: Duration,
    /// 是否启用 keep-alive
    pub enable_keepalive: bool,
}

pub struct SshConnectionPool {
    config: ConnectionPoolConfig,
    connections: Arc<Mutex<HashMap<String, PooledConnection>>>,
}

struct PooledConnection {
    client: SshClient,
    last_used: Instant,
    in_use: bool,
}

impl SshConnectionPool {
    /// 创建新的连接池
    pub fn new(config: ConnectionPoolConfig) -> Self;

    /// 获取连接（如果不存在则创建）
    pub async fn get(&self, addr: &str, username: &str) -> FynxResult<PooledSshClient>;

    /// 获取带密码认证的连接
    pub async fn get_with_password(
        &self,
        addr: &str,
        username: &str,
        password: &str,
    ) -> FynxResult<PooledSshClient>;

    /// 获取带私钥认证的连接
    pub async fn get_with_key(
        &self,
        addr: &str,
        username: &str,
        private_key: &PrivateKey,
    ) -> FynxResult<PooledSshClient>;

    /// 清理空闲连接
    pub async fn cleanup_idle(&self) -> FynxResult<usize>;

    /// 关闭所有连接
    pub async fn close_all(&self) -> FynxResult<()>;
}

/// RAII guard for pooled connection
pub struct PooledSshClient {
    client: SshClient,
    pool: Arc<SshConnectionPool>,
    key: String,
}

impl Drop for PooledSshClient {
    fn drop(&mut self) {
        // Return connection to pool
    }
}
```

**连接池工作流程**:
```
用户请求连接
   ↓
检查连接池是否有可用连接
   ↓
有 → 检查连接是否仍活跃
   ↓     ↓
   是    否 → 移除过期连接，创建新连接
   ↓
返回 PooledSshClient
   ↓
用户使用完毕（Drop）
   ↓
连接归还到池中
```

---

## 🏗️ 架构设计

### 模块结构

```
crates/proto/src/ssh/
├── session/
│   ├── mod.rs              # 模块入口
│   ├── keepalive.rs        # Keep-alive 实现
│   ├── reconnect.rs        # 自动重连实现
│   └── pool.rs             # 连接池实现
└── client.rs               # 扩展 SshClient
```

### Keep-alive 架构

```rust
// keepalive.rs
pub struct KeepaliveTask {
    interval: Duration,
    stop_signal: Arc<AtomicBool>,
}

impl KeepaliveTask {
    pub fn start(client: Arc<Mutex<SshClient>>, interval: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }

                // 发送 SSH_MSG_IGNORE
                let mut client = client.lock().await;
                if let Err(e) = client.send_keepalive().await {
                    tracing::warn!("Keep-alive failed: {}", e);
                    break;
                }
            }
        })
    }
}
```

### 重连架构

```rust
// reconnect.rs
pub struct ReconnectHandler {
    config: ReconnectConfig,
    addr: String,
    username: String,
    auth_method: AuthMethod,
}

impl ReconnectHandler {
    pub async fn reconnect_with_backoff(&self, client: &mut SshClient) -> FynxResult<()> {
        let mut backoff = self.config.initial_backoff;

        for attempt in 0..self.config.max_retries {
            tracing::info!("Reconnect attempt {}/{}", attempt + 1, self.config.max_retries);

            // 等待退避时间
            tokio::time::sleep(backoff).await;

            // 尝试重连
            match self.try_reconnect(client).await {
                Ok(()) => {
                    tracing::info!("Reconnected successfully");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Reconnect attempt {} failed: {}", attempt + 1, e);
                    backoff = std::cmp::min(backoff * 2, self.config.max_backoff);
                }
            }
        }

        Err(FynxError::Connection("Reconnection failed after all retries".to_string()))
    }
}
```

### 连接池架构

```rust
// pool.rs
pub struct SshConnectionPool {
    config: ConnectionPoolConfig,
    connections: Arc<Mutex<HashMap<String, PooledConnection>>>,
    cleanup_task: Option<JoinHandle<()>>,
}

impl SshConnectionPool {
    fn start_cleanup_task(&mut self) {
        let connections = Arc::clone(&self.connections);
        let idle_timeout = self.config.idle_timeout;

        self.cleanup_task = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                let mut conns = connections.lock().await;
                let now = Instant::now();

                conns.retain(|key, conn| {
                    if !conn.in_use && now.duration_since(conn.last_used) > idle_timeout {
                        tracing::info!("Removing idle connection: {}", key);
                        false
                    } else {
                        true
                    }
                });
            }
        }));
    }
}
```

---

## 📝 实施计划

### Stage 9.1: Keep-alive 心跳（1-2 天）

**目标**: 实现基础的 keep-alive 功能。

**任务**:
1. ✅ 创建 `session/` 模块
2. ✅ 实现 `keepalive.rs`
   - KeepaliveTask 结构
   - 后台任务启动/停止
   - SSH_MSG_IGNORE 消息发送
3. ✅ 扩展 SshClientConfig
   - 添加 `keepalive_interval` 字段
4. ✅ 扩展 SshClient
   - `send_keepalive()` 方法
   - `start_keepalive()` 方法
   - `stop_keepalive()` 方法
5. ✅ 编写单元测试
   - 心跳消息格式测试
   - 后台任务启动/停止测试

**测试**:
```rust
#[tokio::test]
async fn test_keepalive_message_format() {
    // 验证 SSH_MSG_IGNORE 消息格式正确
}

#[tokio::test]
async fn test_keepalive_task_starts_and_stops() {
    // 验证后台任务能正确启动和停止
}
```

---

### Stage 9.2: 自动重连机制（1-2 天）

**目标**: 实现连接断开后自动重连。

**任务**:
1. ✅ 实现 `reconnect.rs`
   - ReconnectConfig 结构
   - ReconnectHandler 结构
   - 指数退避逻辑
2. ✅ 扩展 SshClient
   - `reconnect()` 方法
   - `enable_auto_reconnect()` 方法
   - 连接状态跟踪
3. ✅ 连接检测逻辑
   - 检测 send/receive 失败
   - 触发重连流程
4. ✅ 编写单元测试
   - 退避计算测试
   - 重连流程测试

**测试**:
```rust
#[tokio::test]
async fn test_exponential_backoff() {
    // 验证退避时间按指数增长
}

#[tokio::test]
async fn test_reconnect_on_connection_failure() {
    // 模拟连接断开，验证自动重连
}
```

---

### Stage 9.3: 连接池（1-2 天）

**目标**: 实现 SSH 连接池。

**任务**:
1. ✅ 实现 `pool.rs`
   - SshConnectionPool 结构
   - PooledConnection 结构
   - PooledSshClient RAII guard
2. ✅ 连接管理
   - 基于 key 的缓存
   - 连接获取逻辑
   - 连接归还逻辑
3. ✅ 自动清理
   - 空闲超时检测
   - 后台清理任务
4. ✅ 编写单元测试
   - 连接复用测试
   - 空闲清理测试
   - 并发访问测试

**测试**:
```rust
#[tokio::test]
async fn test_connection_pool_reuse() {
    // 验证连接被正确复用
}

#[tokio::test]
async fn test_connection_pool_cleanup() {
    // 验证空闲连接被自动清理
}

#[tokio::test]
async fn test_connection_pool_concurrent_access() {
    // 验证并发安全性
}
```

---

## 🧪 测试策略

### 单元测试

**Keep-alive**:
- ✅ SSH_MSG_IGNORE 消息格式
- ✅ 后台任务生命周期
- ✅ 心跳间隔准确性

**Reconnect**:
- ✅ 指数退避计算
- ✅ 最大重试次数
- ✅ 重连成功/失败处理

**Connection Pool**:
- ✅ 连接创建和复用
- ✅ 空闲超时清理
- ✅ 并发安全性
- ✅ 最大连接数限制

### 集成测试

```rust
#[tokio::test]
async fn test_session_management_end_to_end() {
    // 1. 创建连接池
    let pool = SshConnectionPool::new(ConnectionPoolConfig::default());

    // 2. 获取连接（启用 keep-alive）
    let client = pool.get_with_password("127.0.0.1:22", "user", "pass").await?;

    // 3. 验证 keep-alive 正在运行
    assert!(client.is_keepalive_running());

    // 4. 执行命令
    let output = client.execute("echo hello").await?;
    assert_eq!(output, b"hello\n");

    // 5. Drop client，连接归还到池
    drop(client);

    // 6. 再次获取，验证复用
    let client2 = pool.get_with_password("127.0.0.1:22", "user", "pass").await?;
    // 应该复用同一个连接（无需重新认证）
}
```

---

## 📊 性能考虑

### Keep-alive

**开销**:
- 网络: 每个心跳 ~40 字节（SSH_MSG_IGNORE + 填充）
- CPU: 极低（每60秒一次）
- 内存: 每个连接额外 ~100 字节（任务状态）

**优化**:
- 心跳间隔可配置（默认 60秒）
- 可以完全禁用

### Reconnect

**开销**:
- 重连成本: 1 次 TCP 握手 + 密钥交换 + 认证（~200ms）
- 指数退避减少频繁重试的开销

**优化**:
- 退避策略可配置
- 最大重试次数可配置

### Connection Pool

**收益**:
- 避免重复建立连接（节省 ~200ms）
- 复用已认证的连接

**开销**:
- 内存: 每个连接 ~10KB（包括缓冲区）
- 清理任务: 每60秒运行一次（开销极低）

**优化**:
- 连接池大小可配置
- 空闲超时可配置
- 可以手动触发清理

---

## 🔍 安全考虑

### Keep-alive

**风险**: SSH_MSG_IGNORE 可能被用于旁路攻击
**缓解**:
- 心跳数据随机化（随机长度和内容）
- 心跳间隔添加随机抖动（±10%）

### Reconnect

**风险**: 重连过程中会话状态丢失
**缓解**:
- 明确记录重连事件
- 用户可以配置重连策略

### Connection Pool

**风险**: 连接被其他用户复用
**缓解**:
- 连接池基于 `(host, port, username)` 隔离
- 不跨用户共享连接

---

## 📋 使用示例

### Keep-alive

```rust
use fynx_proto::ssh::client::{SshClient, SshClientConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 配置 keep-alive
    let config = SshClientConfig {
        keepalive_interval: Some(Duration::from_secs(60)),
        ..Default::default()
    };

    // 连接并自动启用 keep-alive
    let mut client = SshClient::connect_with_config("server:22", config).await?;
    client.authenticate_password("user", "password").await?;

    // Keep-alive 在后台自动运行
    // 连接不会因为空闲而被断开
    tokio::time::sleep(Duration::from_secs(300)).await;

    Ok(())
}
```

### Reconnect

```rust
use fynx_proto::ssh::client::{SshClient, ReconnectConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SshClient::connect("server:22").await?;
    client.authenticate_password("user", "password").await?;

    // 启用自动重连
    client.enable_auto_reconnect(ReconnectConfig {
        enabled: true,
        max_retries: 3,
        initial_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
    });

    // 网络短暂中断后会自动重连
    // 用户无需手动处理连接断开

    Ok(())
}
```

### Connection Pool

```rust
use fynx_proto::ssh::session::pool::{SshConnectionPool, ConnectionPoolConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建连接池
    let pool = SshConnectionPool::new(ConnectionPoolConfig {
        max_connections: 10,
        idle_timeout: Duration::from_secs(300),
        enable_keepalive: true,
    });

    // 获取连接（自动创建或复用）
    let client = pool.get_with_password("server:22", "user", "password").await?;

    // 使用连接
    let output = client.execute("ls -la").await?;
    println!("{}", String::from_utf8_lossy(&output));

    // Drop 后连接归还到池中
    drop(client);

    // 再次获取会复用同一个连接（无需重新认证）
    let client2 = pool.get_with_password("server:22", "user", "password").await?;

    Ok(())
}
```

---

## ✅ 完成标准

### Stage 9.1: Keep-alive

- [ ] KeepaliveTask 实现完成
- [ ] SshClient 集成 keep-alive
- [ ] 单元测试通过（≥ 3 个）
- [ ] Keep-alive 在后台正确运行

### Stage 9.2: Reconnect

- [ ] ReconnectHandler 实现完成
- [ ] 指数退避逻辑正确
- [ ] SshClient 集成重连功能
- [ ] 单元测试通过（≥ 5 个）
- [ ] 重连流程端到端测试通过

### Stage 9.3: Connection Pool

- [ ] SshConnectionPool 实现完成
- [ ] PooledSshClient RAII guard 正确
- [ ] 连接复用逻辑正确
- [ ] 空闲清理正常工作
- [ ] 单元测试通过（≥ 8 个）
- [ ] 并发测试通过

### 整体完成

- [ ] 所有单元测试通过（预计 16+ 个）
- [ ] 集成测试通过
- [ ] 文档完整（包括示例）
- [ ] 代码审查通过
- [ ] 性能测试通过（keep-alive 开销 < 1% CPU）

---

## 📚 参考资料

### RFC 文档

- [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253) - SSH Transport Layer Protocol
  - Section 11.1: SSH_MSG_IGNORE

### OpenSSH 实现参考

- `ServerAliveInterval`: Keep-alive 间隔
- `ServerAliveCountMax`: Keep-alive 失败阈值
- `ControlMaster`: 连接复用

### 相关库

- [russh](https://github.com/warp-tech/russh) - Rust SSH implementation
- [thrussh](https://nest.pijul.com/pijul/thrussh) - Pure Rust SSH

---

**维护者**: Fynx Core Team
**最后更新**: 2025-10-31
**状态**: 🟡 开发中
