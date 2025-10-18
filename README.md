# Fynx

[![Crates.io](https://img.shields.io/crates/v/fynx)](https://crates.io/crates/fynx)
[![Documentation](https://docs.rs/fynx/badge.svg)](https://docs.rs/fynx)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![CI](https://github.com/<org>/fynx/workflows/CI/badge.svg)](https://github.com/<org>/fynx/actions)
[![Security](https://github.com/<org>/fynx/workflows/Security/badge.svg)](https://github.com/<org>/fynx/security)
[![OpenSSF](https://bestpractices.coreinfrastructure.org/projects/<id>/badge)](https://bestpractices.coreinfrastructure.org/projects/<id>)

> 模块化的 Rust 网络安全生态系统

Fynx 是一个专注于填补 Rust 安全生态空白的模块化框架，提供协议实现、保护工具、检测防御和渗透测试功能。

## 🎯 核心特性

- **🔐 协议实现** - SSH, DTLS, IPSec, PKCS#11/HSM
- **🛡️ 保护工具** - 字符串混淆、控制流混淆、加壳、反调试
- **🔍 检测防御** - YARA 引擎、流量分析、签名检测
- **🔬 渗透测试** - 端口扫描、服务识别、安全审计
- **⚡ 高性能** - 零拷贝设计、异步 I/O
- **🔒 安全第一** - 符合 OpenSSF Level 5 标准

## 📦 模块列表

| 模块 | Crate | 说明 | 状态 |
|------|-------|------|------|
| platform | `fynx-platform` | 核心基础设施 | 🚧 开发中 |
| proto | `fynx-proto` | 协议实现 (SSH/DTLS/IPSec/HSM) | 🚧 开发中 |
| protect | `fynx-protect` | 保护工具 (混淆/加壳) | 🚧 开发中 |
| detect | `fynx-detect` | 检测防御 (YARA/流量分析) | 🚧 开发中 |
| exploit | `fynx-exploit` | 渗透测试 (扫描/审计) | 📋 计划中 |

## 🚀 快速开始

### 安装

```toml
[dependencies]
fynx = "0.1"

# 或单独引入模块
fynx-platform = "0.1"
fynx-proto = { version = "0.1", features = ["ssh"] }
fynx-protect = { version = "0.1", features = ["obfuscate"] }
fynx-detect = { version = "0.1", features = ["yara"] }
```

### 示例：SSH 客户端

```rust
use fynx_proto::ssh::SshClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SshClient::new()?;

    client.connect("example.com", 22).await?;
    client.authenticate_password("user", "pass").await?;

    let output = client.execute("ls -la").await?;
    println!("{}", output);

    Ok(())
}
```

### 示例：字符串混淆

```rust
use fynx_protect::obfstr;

fn main() {
    // 编译时加密，运行时解密
    let secret = obfstr!("my_secret_api_key");
    println!("{}", secret);
}
```

### 示例：YARA 扫描

```rust
use fynx_detect::yara::{YaraEngine, Rule};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = YaraEngine::new();

    engine.load_rules("rules.yar")?;

    let data = std::fs::read("suspicious_file.exe")?;
    let matches = engine.scan(&data)?;

    for m in matches {
        println!("Match: {} at offset {}", m.rule, m.offset);
    }

    Ok(())
}
```

## 📚 文档

- [📐 架构设计](docs/ARCHITECTURE.md) - 项目整体架构
- [📝 模块规范](docs/MODULE_DESIGN.md) - 模块设计标准
- [🏷️ 命名规范](docs/NAMING.md) - 命名约定
- [⚙️ 开发标准](docs/STANDARDS.md) - 开发流程和质量要求
- [🔒 安全策略](docs/SECURITY.md) - 安全策略和 OpenSSF 合规

## 🏗️ 开发路线图

### ✅ 已完成

- [x] 项目架构设计
- [x] 文档规范制定
- [x] 模块接口定义

### 🚧 进行中 (Phase 1 - v0.1.0)

- [ ] `fynx-platform` - 核心类型和 trait
- [ ] `fynx-proto` - SSH 协议基础实现
- [ ] `fynx-protect` - 字符串混淆宏

### 📋 计划中

#### Phase 2 (v0.2.0)
- [ ] `fynx-detect` - YARA 引擎
- [ ] `fynx-proto` - HSM/PKCS#11 绑定
- [ ] `fynx-protect` - 反调试机制

#### Phase 3 (v0.3.0)
- [ ] `fynx-proto` - DTLS 实现
- [ ] `fynx-detect` - 流量分析
- [ ] `fynx-exploit` - 端口扫描器

#### Phase 4 (v1.0.0)
- [ ] 完整审计和安全评估
- [ ] 性能优化
- [ ] 生产环境就绪

## 🤝 贡献

我们欢迎所有形式的贡献！

- 📖 阅读 [贡献指南](CONTRIBUTING.md)
- 🐛 [报告 Bug](https://github.com/<org>/fynx/issues/new?template=bug_report.md)
- ✨ [功能请求](https://github.com/<org>/fynx/issues/new?template=feature_request.md)
- 🔒 [报告安全漏洞](SECURITY.md)

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/<org>/fynx.git
cd fynx

# 安装工具
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny

# 构建
cargo build --all-features

# 测试
cargo test --all-features --workspace

# 检查
cargo fmt --check
cargo clippy --all-features -- -D warnings
```

## 🔒 安全

Fynx 致力于达到最高的安全标准：

- ✅ OpenSSF Best Practices Level 5 合规
- ✅ 每日依赖安全扫描
- ✅ Fuzz 测试覆盖关键组件
- ✅ 90 天内修复安全漏洞
- ✅ 独立安全审计（计划中）

如发现安全漏洞，请查看 [安全策略](SECURITY.md)。

## 📄 许可证

本项目使用双许可证：

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

您可以选择其中任意一个许可证使用本项目。

## 🙏 致谢

- [RustCrypto](https://github.com/RustCrypto) - 加密原语参考
- [rustls](https://github.com/rustls/rustls) - TLS 实现参考
- [tokio](https://tokio.rs/) - 异步运行时

## 📞 联系方式

- **官网**: https://fynx.dev
- **文档**: https://docs.rs/fynx
- **讨论**: https://github.com/<org>/fynx/discussions
- **邮件**: team@fynx.dev
- **安全**: security@fynx.dev

---

**Status**: 🚧 Alpha (v0.1.0-dev)

**注意**: 本项目目前处于早期开发阶段，API 可能会有重大变更。不建议用于生产环境。
