# 架构决策：SSH 端口转发实现

**日期**: 2025-10-31
**状态**: 🔴 需要决策
**相关**: STAGE8_PORT_FORWARDING.md

---

## 📋 问题描述

在实现 SSH 端口转发时，发现当前 `SshClient` 的架构无法支持多通道并发操作。

### 当前架构限制

```rust
// SshClient 当前实现
pub struct SshClient {
    stream: TcpStream,
    transport: TransportState,
    next_channel_id: u32,
    // ...
}

impl SshClient {
    // 同步的消息发送/接收
    async fn send_packet(&mut self, payload: &[u8]) -> FynxResult<()> { ... }
    async fn receive_packet(&mut self) -> FynxResult<Packet> { ... }

    // execute() 方法示例 - 同步处理一个通道
    pub async fn execute(&mut self, command: &str) -> FynxResult<Vec<u8>> {
        // 1. 打开通道
        // 2. 等待确认
        // 3. 发送请求
        // 4. 接收数据
        // 5. 关闭通道
        // 所有步骤都是顺序执行的
    }
}
```

**问题**:
- ❌ 一次只能处理一个操作
- ❌ `send_packet`/`receive_packet` 是阻塞的
- ❌ 无法同时管理多个通道
- ❌ 无法将消息路由到不同的通道

### 端口转发的需求

```rust
// 端口转发需要同时处理多个通道
let forward = client.local_forward("localhost:8080", "target:3306").await?;
// 同时需要：
// - 监听 localhost:8080
// - 为每个连接打开新的 SSH 通道
// - 同时转发多个连接的数据
// - 独立处理每个通道的生命周期
```

**需求**:
- ✅ 并发接受多个连接
- ✅ 每个连接使用独立的 SSH 通道
- ✅ 异步消息分发到不同通道
- ✅ 独立的通道读写接口

---

## 🎯 可选方案

### 方案 A: 重构 SshClient 支持多通道（推荐）

**描述**: 重构 `SshClient` 架构，实现真正的多通道支持

**设计**:
```rust
pub struct SshClient {
    // 底层连接
    connection: Arc<Mutex<SshConnection>>,
    // 通道管理
    channels: Arc<Mutex<HashMap<u32, SshChannel>>>,
    // 消息分发器
    dispatcher: mpsc::Sender<SshMessage>,
}

pub struct SshConnection {
    stream: TcpStream,
    transport: TransportState,
    next_channel_id: u32,
}

pub struct SshChannel {
    local_id: u32,
    remote_id: u32,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    state: ChannelState,
}

impl SshClient {
    // 后台任务：消息分发
    async fn message_dispatcher_task(...) {
        loop {
            let packet = receive_packet().await?;
            // 根据消息类型和通道ID分发到对应的通道
            match extract_channel_id(&packet) {
                Some(channel_id) => channels[channel_id].send(packet),
                None => // 处理全局消息
            }
        }
    }

    // 异步打开通道
    pub async fn open_channel(&self, channel_type: ChannelType) -> FynxResult<SshChannel> {
        // 1. 分配通道ID
        // 2. 创建通道对象
        // 3. 发送 CHANNEL_OPEN
        // 4. 等待 CHANNEL_OPEN_CONFIRMATION（通过通道的 rx）
        // 5. 返回通道对象
    }
}

// 通道提供独立的读写接口
impl SshChannel {
    pub async fn read(&mut self) -> FynxResult<Vec<u8>> {
        self.rx.recv().await
    }

    pub async fn write(&mut self, data: &[u8]) -> FynxResult<()> {
        // 发送 CHANNEL_DATA 消息
    }
}
```

**优点**:
- ✅ 真正的多通道支持
- ✅ 架构清晰、符合 SSH 协议设计
- ✅ 可重用于其他需要多通道的功能（SFTP等）
- ✅ 长期价值高

**缺点**:
- ❌ 工作量大（估计 3-5 天）
- ❌ 可能引入 bug
- ❌ 需要重写 `execute()` 等现有方法
- ❌ 需要大量测试

**工作量估计**: 3-5 天
- Day 1: 设计并实现 SshConnection 和通道抽象
- Day 2: 实现消息分发器
- Day 3: 重构现有方法（execute 等）
- Day 4: 测试和调试
- Day 5: 实现端口转发

---

### 方案 B: 创建独立的 SshForwardingClient

**描述**: 创建一个专门用于端口转发的独立客户端实现

**设计**:
```rust
// 独立的转发客户端，不依赖现有 SshClient
pub struct SshForwardingClient {
    stream: TcpStream,
    transport: TransportState,
    channels: HashMap<u32, ChannelState>,
    next_channel_id: u32,
}

impl SshForwardingClient {
    // 专门为转发优化的实现
    pub async fn connect_and_auth(...) -> FynxResult<Self> {
        // 连接、认证
    }

    pub async fn run_local_forward(&mut self, ...) -> FynxResult<()> {
        // 运行转发循环
        tokio::select! {
            // 接受新连接
            // 处理通道消息
            // 转发数据
        }
    }
}
```

**优点**:
- ✅ 不影响现有 SshClient
- ✅ 可以专门为转发优化
- ✅ 工作量相对较小
- ✅ 风险低

**缺点**:
- ❌ 代码重复（连接、认证等逻辑）
- ❌ 维护两套实现
- ❌ 不是长期解决方案
- ❌ 其他需要多通道的功能仍需重构

**工作量估计**: 2-3 天

---

### 方案 C: 单连接转发原型（临时方案）

**描述**: 实现一个只支持单个转发连接的原型，用于测试

**设计**:
```rust
impl SshClient {
    // 只支持一个活动转发连接
    pub async fn forward_single_connection(
        &mut self,
        local_stream: TcpStream,
        target_host: &str,
        target_port: u16,
    ) -> FynxResult<()> {
        // 打开 direct-tcpip 通道
        // 转发数据（阻塞直到连接关闭）
        // 关闭通道
    }
}
```

**优点**:
- ✅ 工作量最小
- ✅ 可以验证协议实现
- ✅ 可以用于测试

**缺点**:
- ❌ 功能不完整
- ❌ 不是生产可用
- ❌ 仍需后续重构
- ❌ 用户体验差

**工作量估计**: 1 天

---

### 方案 D: 暂停端口转发，优先实现其他功能

**描述**: 标注端口转发为"需要架构重构"，优先实现不需要多通道的功能

**下一步可以实现**:
- ✅ SFTP (需要多通道，但可以用单通道简化实现)
- ✅ SCP (基于 execute，不需要额外通道)
- ✅ Session管理 (连接池、重连等)
- ✅ ssh-agent 支持
- ✅ 性能优化

**优点**:
- ✅ 避免强行实现不完整的功能
- ✅ 可以先完成其他高价值功能
- ✅ 等架构成熟后再实现端口转发
- ✅ 符合"增量进步"原则

**缺点**:
- ❌ 端口转发延期
- ❌ 用户期望可能降低

**工作量**: 0 天（标注TODO）

---

## 💡 建议

### 短期建议（当前）

**推荐方案 A + 部分方案 D**:

1. **本次提交**:
   - ✅ 已完成框架和文档
   - ✅ 已标注架构限制
   - ✅ 创建本决策文档

2. **下一阶段（SSH Phase 2）**:
   - 优先实现不需要多通道的功能:
     - **会话管理** (3-5 天) - 连接池、重连、Keep-alive
     - **ssh-agent 支持** (3-4 天) - 基于现有认证
     - **SCP** (2-3 天) - 基于 execute，简单实用
   - 完成这些后再考虑架构重构

3. **SSH Phase 3（未来）**:
   - 重构 SshClient 支持多通道（方案 A）
   - 实现完整的端口转发
   - 实现 SFTP

### 长期规划

**Phase 2** (2-3 周):
- Week 1-2: 会话管理 + ssh-agent + SCP
- Week 3: 测试、优化、文档

**Phase 3** (4-6 周):
- Week 1-2: 重构 SshClient 多通道支持
- Week 3-4: 实现端口转发（Local/Remote/Dynamic）
- Week 5-6: 实现 SFTP

---

## ✅ 决策记录

**决策**: 采用方案 A + D 的组合

**理由**:
1. 端口转发是重要功能，但不应强行实现不完整版本
2. 多通道支持是核心架构改进，将使多个功能受益
3. 先实现其他高价值功能，积累经验后再重构
4. 符合"增量进步"和"技术债务管理"原则

**后续行动**:
1. ✅ 提交当前框架代码和文档
2. ✅ 标注端口转发为"需要多通道支持"
3. ⬜ 切换到其他 SSH 功能实现
4. ⬜ 完成 Phase 2 功能后，规划架构重构
5. ⬜ Phase 3 实现多通道和端口转发

---

**维护者**: Fynx Core Team
**最后更新**: 2025-10-31
