# Fynx 模块设计规范

本文档定义 Fynx 项目中所有模块的统一设计标准和接口规范。

## 模块通用规范

### 1. 目录结构

每个模块必须遵循以下标准结构：

```
crates/<module-name>/
├── Cargo.toml          # 模块配置
├── README.md           # 模块文档
├── CHANGELOG.md        # 版本变更记录
├── LICENSE             # 许可证文件
├── src/
│   ├── lib.rs          # 模块入口
│   ├── error.rs        # 错误定义 (如需要)
│   └── ...             # 其他源文件
├── examples/           # 示例代码 (至少 3 个)
│   ├── basic.rs
│   ├── advanced.rs
│   └── integration.rs
├── tests/              # 集成测试
│   └── integration.rs
└── benches/            # 性能测试 (可选)
    └── benchmark.rs
```

### 2. Cargo.toml 标准

```toml
[package]
name = "fynx-<module>"
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
authors = ["Fynx Contributors"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/<org>/fynx"
documentation = "https://docs.rs/fynx-<module>"
homepage = "https://fynx.dev"
readme = "README.md"
description = "简短描述 (不超过 160 字符)"
keywords = ["security", "...", "..."]  # 最多 5 个
categories = ["network-programming", "cryptography"]  # 最多 5 个

[dependencies]
fynx-platform = { version = "0.1", path = "../platform" }

[dev-dependencies]
criterion = "0.5"
tokio-test = "0.4"

[features]
default = []
# 定义特性标志

[[example]]
name = "basic"
required-features = []

[badges]
maintenance = { status = "actively-developed" }
```

### 3. README.md 标准

每个模块的 README 必须包含：

```markdown
# fynx-<module>

[![Crates.io](https://img.shields.io/crates/v/fynx-<module>)](https://crates.io/crates/fynx-<module>)
[![Documentation](https://docs.rs/fynx-<module>/badge.svg)](https://docs.rs/fynx-<module>)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)

## 概述

简短描述模块功能 (2-3 句话)

## 功能特性

- 功能 1
- 功能 2
- 功能 3

## 快速开始

### 安装

\`\`\`toml
[dependencies]
fynx-<module> = "0.1"
\`\`\`

### 基本使用

\`\`\`rust
// 代码示例
\`\`\`

## 示例

查看 `examples/` 目录获取更多示例。

## 安全说明

(如适用) 说明安全使用注意事项

## 许可证

MIT OR Apache-2.0
```

### 4. 代码风格

**文件头部**:
```rust
//! 模块级文档
//!
//! 详细说明模块功能、使用场景等

#![forbid(unsafe_code)]  // 除非必要
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// 依赖导入按字母排序
use fynx_platform::{FynxError, FynxResult};
use std::collections::HashMap;
```

**公开 API**:
```rust
/// 函数功能简述
///
/// # 参数
///
/// * `param1` - 参数说明
/// * `param2` - 参数说明
///
/// # 返回值
///
/// 返回值说明
///
/// # 错误
///
/// 可能的错误情况
///
/// # 示例
///
/// ```
/// use fynx_module::function;
///
/// let result = function("example")?;
/// assert_eq!(result, expected);
/// ```
pub fn function(param1: &str, param2: u32) -> FynxResult<String> {
    // 实现
}
```

---

## 核心模块规范

### platform 模块

**职责**: 提供所有模块的基础设施

**必须导出**:

```rust
// src/lib.rs
pub mod error;
pub mod traits;
pub mod config;

pub use error::{FynxError, FynxResult};
pub use traits::{SecurityModule, ProtocolStack, Scanner, Analyzer};
pub use config::Config;

/// 平台版本号
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

**核心类型**:

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FynxError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type FynxResult<T> = Result<T, FynxError>;
```

**核心 Trait**:

```rust
// src/traits.rs
use crate::{FynxError, FynxResult};

/// 安全模块通用接口
pub trait SecurityModule: Send + Sync {
    /// 模块唯一标识符
    fn id(&self) -> &'static str;

    /// 模块版本
    fn version(&self) -> &'static str;

    /// 模块描述
    fn description(&self) -> &'static str;

    /// 初始化模块
    fn init(&mut self) -> FynxResult<()> {
        Ok(())
    }

    /// 关闭模块
    fn shutdown(&mut self) -> FynxResult<()> {
        Ok(())
    }
}

/// 协议栈接口
#[async_trait::async_trait]
pub trait ProtocolStack: SecurityModule {
    /// 协议名称
    fn proto_name(&self) -> &'static str;

    /// 启动服务端
    async fn listen(&mut self, bind: &str) -> FynxResult<()>;

    /// 连接服务端
    async fn connect(&mut self, target: &str) -> FynxResult<()>;

    /// 关闭连接
    async fn close(&mut self) -> FynxResult<()>;
}

/// 扫描器接口
#[async_trait::async_trait]
pub trait Scanner: SecurityModule {
    /// 扫描目标
    async fn scan(&self, target: &str) -> FynxResult<ScanResult>;
}

/// 分析器接口
pub trait Analyzer: SecurityModule {
    /// 分析数据
    fn analyze(&self, data: &[u8]) -> FynxResult<AnalysisResult>;
}

// 辅助类型
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub matches: Vec<Match>,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub offset: usize,
    pub length: usize,
    pub rule: String,
}
```

---

## 功能模块规范

### proto 模块

**特性标志**:
```toml
[features]
default = []
ssh = ["tokio", "ring"]
dtls = ["rustls"]
ipsec = ["tokio"]
hsm = ["pkcs11"]
full = ["ssh", "dtls", "ipsec", "hsm"]
```

**子模块接口**:

```rust
// src/ssh/mod.rs
use fynx_platform::{FynxResult, ProtocolStack};

/// SSH 客户端
pub struct SshClient {
    // 字段
}

impl SshClient {
    /// 创建新的 SSH 客户端
    pub fn new() -> FynxResult<Self> {
        todo!()
    }

    /// 连接到服务器
    pub async fn connect(&mut self, host: &str, port: u16) -> FynxResult<()> {
        todo!()
    }

    /// 认证 (密码)
    pub async fn authenticate_password(&mut self, user: &str, pass: &str) -> FynxResult<()> {
        todo!()
    }

    /// 执行命令
    pub async fn execute(&mut self, command: &str) -> FynxResult<String> {
        todo!()
    }
}

#[async_trait::async_trait]
impl ProtocolStack for SshClient {
    fn proto_name(&self) -> &'static str {
        "SSH"
    }

    async fn listen(&mut self, _bind: &str) -> FynxResult<()> {
        Err(FynxError::NotImplemented("SSH server not implemented".into()))
    }

    async fn connect(&mut self, target: &str) -> FynxResult<()> {
        // 解析 target (user@host:port)
        todo!()
    }

    async fn close(&mut self) -> FynxResult<()> {
        todo!()
    }
}
```

---

### protect 模块

**特性标志**:
```toml
[features]
default = ["obfuscate"]
obfuscate = []
packer = ["zstd"]
anti-debug = []
full = ["obfuscate", "packer", "anti-debug"]
```

**宏接口**:

```rust
// src/obfuscate/string.rs

/// 编译时字符串加密
///
/// # 示例
///
/// ```
/// use fynx_protect::obfstr;
///
/// let secret = obfstr!("my_secret_key");
/// println!("{}", secret);  // 运行时解密
/// ```
#[macro_export]
macro_rules! obfstr {
    ($s:expr) => {{
        // 编译时加密逻辑
        const ENCRYPTED: &[u8] = $crate::obfuscate::encrypt_at_compile_time($s);
        $crate::obfuscate::decrypt_at_runtime(ENCRYPTED)
    }};
}
```

---

### detect 模块

**特性标志**:
```toml
[features]
default = ["yara"]
yara = []
flow = ["pcap"]
signature = []
full = ["yara", "flow", "signature"]
```

**YARA 接口**:

```rust
// src/yara/engine.rs
use fynx_platform::{Analyzer, AnalysisResult, FynxResult};

/// YARA 规则引擎
pub struct YaraEngine {
    rules: Vec<Rule>,
}

impl YaraEngine {
    /// 创建新引擎
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// 加载规则文件
    pub fn load_rules(&mut self, path: &str) -> FynxResult<()> {
        todo!()
    }

    /// 添加规则
    pub fn add_rule(&mut self, rule: Rule) -> FynxResult<()> {
        self.rules.push(rule);
        Ok(())
    }

    /// 扫描数据
    pub fn scan(&self, data: &[u8]) -> FynxResult<Vec<Match>> {
        todo!()
    }
}

impl Analyzer for YaraEngine {
    fn analyze(&self, data: &[u8]) -> FynxResult<AnalysisResult> {
        let matches = self.scan(data)?;
        Ok(AnalysisResult { matches })
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub strings: Vec<Pattern>,
    pub condition: Condition,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Text(String),
    Hex(Vec<u8>),
    Regex(String),
}

#[derive(Debug, Clone)]
pub struct Condition {
    // 条件表达式
}

#[derive(Debug, Clone)]
pub struct Match {
    pub offset: usize,
    pub length: usize,
    pub rule: String,
}
```

---

### exploit 模块

**特性标志**:
```toml
[features]
default = ["scanner"]
scanner = ["tokio"]
audit = []
full = ["scanner", "audit"]
```

**扫描器接口**:

```rust
// src/scanner/port.rs
use fynx_platform::{FynxResult, Scanner, ScanResult};

/// 端口扫描器
pub struct PortScanner {
    timeout: std::time::Duration,
}

impl PortScanner {
    /// 创建扫描器
    pub fn new() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(5),
        }
    }

    /// 设置超时
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// 扫描端口范围
    pub async fn scan_range(&self, target: &str, start: u16, end: u16) -> FynxResult<Vec<u16>> {
        todo!()
    }
}

#[async_trait::async_trait]
impl Scanner for PortScanner {
    async fn scan(&self, target: &str) -> FynxResult<ScanResult> {
        // 扫描常见端口
        let open_ports = self.scan_range(target, 1, 1024).await?;
        todo!()
    }
}
```

---

## 测试规范

### 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_basic() {
        let result = function("test", 42);
        assert!(result.is_ok());
    }

    #[test]
    fn test_function_error() {
        let result = function("", 0);
        assert!(result.is_err());
    }
}
```

### 集成测试

```rust
// tests/integration.rs
use fynx_module::*;

#[tokio::test]
async fn test_integration() {
    let mut module = Module::new().unwrap();
    module.init().await.unwrap();

    let result = module.process("test").await;
    assert!(result.is_ok());

    module.shutdown().await.unwrap();
}
```

### 性能测试

```rust
// benches/benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_function(c: &mut Criterion) {
    c.bench_function("function", |b| {
        b.iter(|| function(black_box("test"), black_box(42)))
    });
}

criterion_group!(benches, benchmark_function);
criterion_main!(benches);
```

---

## 文档规范

### API 文档

所有公开 API 必须有 rustdoc 文档：

```rust
/// 简短描述 (一句话)
///
/// 详细说明功能、使用场景、注意事项等
///
/// # 参数
///
/// * `param` - 参数说明
///
/// # 返回值
///
/// 返回值说明
///
/// # 错误
///
/// * `FynxError::Config` - 配置错误
/// * `FynxError::Protocol` - 协议错误
///
/// # 示例
///
/// ```
/// # use fynx_module::*;
/// let result = function("example")?;
/// assert_eq!(result, "expected");
/// # Ok::<(), fynx_platform::FynxError>(())
/// ```
///
/// # 安全性
///
/// (如适用) 说明安全使用注意事项
pub fn function(param: &str) -> FynxResult<String> {
    todo!()
}
```

### 示例代码

每个模块至少提供 3 个示例：

1. **basic.rs** - 基础使用
2. **advanced.rs** - 高级功能
3. **integration.rs** - 与其他模块集成

---

## 发布检查清单

发布前必须确认：

- [ ] 所有测试通过 (`cargo test --all-features`)
- [ ] Clippy 无警告 (`cargo clippy --all-features -- -D warnings`)
- [ ] 格式正确 (`cargo fmt --check`)
- [ ] 文档完整 (`cargo doc --no-deps --all-features`)
- [ ] 示例可运行 (`cargo run --example <name>`)
- [ ] CHANGELOG 已更新
- [ ] 版本号符合 SemVer
- [ ] 依赖审计通过 (`cargo audit`)
- [ ] 许可证正确
- [ ] README 完整

---

**文档版本**: 0.1.0
**最后更新**: 2025-01-17
**维护者**: Fynx Core Team
