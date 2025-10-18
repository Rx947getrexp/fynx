# Fynx 项目架构设计

## 项目概述

**Fynx** 是一个模块化的 Rust 网络安全生态系统，旨在填补 Rust 在安全协议、保护、检测和渗透测试领域的空白。

### 核心目标

1. **模块化设计** - 每个模块独立发布到 crates.io，用户可按需引入
2. **安全第一** - 符合 Google OpenSSF Level 5 标准
3. **生态补全** - 专注 Rust 当前缺失的安全功能
4. **开源协作** - MIT/Apache-2.0 双许可，社区驱动

## 顶层架构

```
fynx/
├── Cargo.toml         # Workspace 配置
├── docs/              # 项目文档
├── .github/           # CI/CD 配置
├── examples/          # 综合示例
├── tests/             # 集成测试
└── crates/            # 所有模块
    ├── platform/      # fynx-platform - 核心基础设施
    ├── proto/         # fynx-proto    - 协议实现 (SSH/DTLS/IPSec/HSM)
    ├── protect/       # fynx-protect  - 保护工具 (混淆/加壳/反调试)
    ├── detect/        # fynx-detect   - 检测防御 (YARA/流量分析)
    ├── exploit/        # fynx-exploit   - 渗透测试 (扫描/审计) [受限发布]
    └── rustsec/       # fynx          - 元包 (统一入口)
```

## 模块职责

### 1. platform - 核心基础设施

**Crate 名**: `fynx-platform`

**职责**:
- 统一错误类型 (`FynxResult<T>`, `FynxError`)
- 核心 trait 定义 (`SecurityModule`, `ProtocolStack`, `Scanner`, `Analyzer`)
- 配置管理 (`Config`, `ModuleConfig`)
- 日志抽象 (基于 `tracing`)
- 插件系统接口 (可选 WASM 支持)

**为什么需要**:
- 避免各模块重复定义基础类型
- 提供统一的接口规范
- 减少依赖冲突

**依赖**:
```toml
[dependencies]
thiserror = "1.0"
tracing = "0.1"
serde = { version = "1.0", features = ["derive"] }
```

**导出内容**:
```rust
pub use error::{FynxError, FynxResult};
pub use traits::{SecurityModule, ProtocolStack, Scanner, Analyzer};
pub use config::Config;
```

---

### 2. proto - 协议与加密

**Crate 名**: `fynx-proto`

**职责**:
- SSH 协议栈 (client/server, KEX, auth, channels)
- DTLS 实现 (UDP 安全通信)
- IPSec/IKEv2 (VPN 协议)
- PKCS#11/HSM 绑定 (硬件安全模块)

**子模块结构**:
```
crates/proto/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs          # 统一导出
│   ├── ssh/            # SSH 实现
│   ├── dtls/           # DTLS 实现
│   ├── ipsec/          # IPSec 实现
│   └── hsm/            # HSM 绑定
├── examples/
└── tests/
```

**特性标志**:
```toml
[features]
default = []
ssh = []
dtls = []
ipsec = []
hsm = []
full = ["ssh", "dtls", "ipsec", "hsm"]
```

**优先级**: SSH > HSM > DTLS > IPSec

---

### 3. protect - 保护与混淆

**Crate 名**: `fynx-protect`

**职责**:
- 字符串混淆 (编译时加密)
- 控制流混淆 (宏/LLVM pass)
- 程序加壳 (packer + stub)
- 反调试机制 (跨平台)

**子模块结构**:
```
crates/protect/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── obfuscate/      # 混淆工具
│   │   ├── string.rs   # 字符串加密宏
│   │   └── control.rs  # 控制流混淆
│   ├── packer/         # 加壳工具
│   │   ├── stub.rs     # 解压 stub
│   │   └── crypto.rs   # 加密封装
│   └── anti_debug/     # 反调试
│       ├── linux.rs
│       ├── windows.rs
│       └── macos.rs
├── examples/
└── tests/
```

**特性标志**:
```toml
[features]
default = ["obfuscate"]
obfuscate = []
packer = []
anti-debug = []
```

**优先级**: obfuscate > anti-debug > packer

---

### 4. detect - 检测与防御

**Crate 名**: `fynx-detect`

**职责**:
- YARA 风格规则引擎
- 流量分析 (PCAP/NetFlow)
- 签名检测
- 协议识别

**子模块结构**:
```
crates/detect/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── yara/           # YARA 引擎
│   │   ├── parser.rs   # 规则解析
│   │   ├── engine.rs   # 匹配引擎
│   │   └── rules/      # 内置规则
│   ├── flow/           # 流量分析
│   │   ├── pcap.rs     # PCAP 解析
│   │   └── protocol.rs # 协议识别
│   └── signature/      # 签名检测
├── examples/
└── tests/
```

**特性标志**:
```toml
[features]
default = ["yara"]
yara = []
flow = ["pcap"]
signature = []
```

**优先级**: yara > signature > flow

---

### 5. exploit - 渗透测试 [受限]

**Crate 名**: `fynx-exploit`

**职责**:
- 网络扫描器 (端口/服务识别)
- 漏洞扫描 (CVE 匹配)
- 审计工具 (配置检查)

**特别说明**:
- **仅用于合法安全审计**
- 不包含 payload 生成器
- 不包含远程代码执行工具
- 添加使用限制声明

**子模块结构**:
```
crates/exploit/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── scanner/        # 扫描器
│   │   ├── port.rs     # 端口扫描
│   │   └── service.rs  # 服务识别
│   └── audit/          # 审计工具
│       └── config.rs   # 配置检查
├── examples/
└── tests/
```

**发布策略**:
- 初期可能不发布到 crates.io
- 或发布时明确标注 "仅供安全研究"

---

### 6. rustsec - 元包

**Crate 名**: `fynx`

**职责**:
- 统一入口，方便用户一次性引入
- 可选特性，灵活组合

**Cargo.toml**:
```toml
[dependencies]
fynx-platform = { version = "0.1", path = "../crates/platform" }
fynx-proto = { version = "0.1", path = "../crates/proto", optional = true }
fynx-protect = { version = "0.1", path = "../crates/protect", optional = true }
fynx-detect = { version = "0.1", path = "../crates/detect", optional = true }
fynx-exploit = { version = "0.1", path = "../crates/exploit", optional = true }

[features]
default = ["platform"]
proto = ["fynx-proto"]
protect = ["fynx-protect"]
detect = ["fynx-detect"]
exploit = ["fynx-exploit"]
full = ["proto", "protect", "detect"]  # 不包含 exploit
```

## 依赖关系图

```
           ┌─────────────┐
           │    fynx     │ (元包)
           └──────┬──────┘
                  │
      ┌───────────┼───────────┬───────────┬──────────┐
      │           │           │           │          │
┌─────▼────┐ ┌───▼────┐ ┌────▼────┐ ┌────▼────┐ ┌──▼──────┐
│ protocol │ │ protect│ │ detect  │ │ eexploit │ │ platform│
└─────┬────┘ └────┬───┘ └────┬────┘ └────┬────┘ └─────────┘
      │           │           │           │
      └───────────┴───────────┴───────────┘
                  │
           ┌──────▼──────┐
           │   platform  │ (所有模块依赖)
           └─────────────┘
```

## 发布策略

### 阶段 1: 核心基础 (0.1.x)
1. `fynx-platform` 0.1.0
2. `fynx-proto` 0.1.0 (仅 SSH)
3. `fynx-protect` 0.1.0 (仅 obfuscate)
4. `fynx` 0.1.0 (元包)

### 阶段 2: 功能扩展 (0.2.x)
5. `fynx-detect` 0.1.0 (YARA)
6. `fynx-proto` 0.2.0 (+ HSM)
7. `fynx-protect` 0.2.0 (+ anti-debug)

### 阶段 3: 高级功能 (0.3.x)
8. `fynx-proto` 0.3.0 (+ DTLS)
9. `fynx-detect` 0.2.0 (+ flow)
10. `fynx-exploit` 0.1.0 (审计工具)

### 阶段 4: 生态成熟 (1.0.x)
11. 所有模块达到 1.0 稳定版
12. 完整审计和安全评估
13. 生产环境就绪

## 版本管理

- 使用语义化版本 (SemVer 2.0)
- 所有模块独立版本号
- `fynx` 元包版本跟随最新稳定模块

## 测试策略

### 单元测试
- 每个模块 `tests/` 目录
- 覆盖率要求 ≥ 80%

### 集成测试
- Workspace 级别 `tests/` 目录
- 测试模块间交互

### Fuzz 测试
- 使用 `cargo-fuzz`
- 关键协议解析器必须 fuzz

### 互操作性测试
- SSH: 与 OpenSSH 交互
- DTLS: 与 OpenSSL 交互
- YARA: 与官方 YARA 规则兼容

## 文档要求

每个模块必须包含:
1. `README.md` - 功能说明和快速开始
2. `CHANGELOG.md` - 版本变更记录
3. `examples/` - 至少 3 个示例
4. API 文档 - 所有公开 API 必须有 rustdoc

## 合规要求

- 符合 OpenSSF Best Practices Level 5
- MIT/Apache-2.0 双许可
- 依赖审计 (cargo-audit)
- 静态分析 (clippy pedantic)
- 安全策略 (SECURITY.md)

## 社区治理

- 贡献指南 (CONTRIBUTING.md)
- 行为准则 (CODE_OF_CONDUCT.md)
- Issue 模板
- PR 模板
- CODEOWNERS

---

**文档版本**: 0.1.0
**最后更新**: 2025-01-17
**维护者**: Fynx Core Team
