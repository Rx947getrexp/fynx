# Fynx 安全策略与 OpenSSF 合规

本文档定义 Fynx 项目的安全策略、漏洞报告流程和 OpenSSF Best Practices Level 5 合规要求。

## 安全策略

### 支持版本

| 版本 | 支持状态 |
|------|---------|
| 0.1.x | ✅ 支持 |
| < 0.1 | ❌ 不支持 |

### 漏洞报告

**请勿公开披露安全漏洞！**

#### 报告流程

1. **私密报告**: 发送邮件到 security@fynx.dev (或使用 GitHub Security Advisory)
2. **邮件标题**: `[SECURITY] Brief description`
3. **必需信息**:
   - 漏洞描述
   - 影响范围
   - 重现步骤
   - 建议修复方案 (如有)

#### 响应时间承诺

| 严重程度 | 首次响应 | 修复发布 |
|---------|---------|---------|
| Critical | 24 小时 | 7 天 |
| High | 48 小时 | 30 天 |
| Medium | 7 天 | 90 天 |
| Low | 14 天 | 下个版本 |

#### 披露政策

- 修复发布后 90 天公开披露
- 提前通知报告者
- 在 CHANGELOG 和 GitHub Advisory 中说明

---

## OpenSSF Best Practices Level 5

Fynx 项目致力于达到 [OpenSSF Best Practices Badge](https://bestpractices.coreinfrastructure.org/) 的最高等级（Silver/Level 5）。

### 通过标准 (Passing - Level 1)

#### 基础要求

- [x] **开源许可证**: MIT OR Apache-2.0
- [x] **版本控制**: Git + GitHub
- [x] **变更日志**: CHANGELOG.md
- [x] **贡献指南**: CONTRIBUTING.md
- [x] **行为准则**: CODE_OF_CONDUCT.md
- [x] **文档**: README.md + API docs (docs.rs)
- [x] **问题追踪**: GitHub Issues
- [x] **构建系统**: Cargo

#### 质量保证

- [x] **自动化测试**: GitHub Actions CI
- [x] **测试覆盖率**: ≥ 80% (tarpaulin)
- [x] **代码审查**: 所有 PR 必须审查
- [x] **代码风格**: rustfmt + clippy
- [x] **警告处理**: 构建时 `-D warnings`

#### 安全要求

- [x] **HTTPS**: 所有网络通信使用 HTTPS
- [x] **密码管理**: 不在代码中硬编码密钥
- [x] **安全漏洞修复**: 90 天内修复
- [x] **依赖审计**: cargo audit (每日运行)
- [x] **加密标准**: 使用业界标准算法 (ring, rustls)

---

### Silver 级别 (Level 2-3)

#### 增强质量

- [x] **多平台测试**: Linux, Windows, macOS
- [x] **Fuzz 测试**: 关键解析器使用 libfuzzer
- [x] **性能测试**: criterion benchmarks
- [x] **内存安全**: 禁止 unsafe (除特殊情况)
- [x] **静态分析**: clippy pedantic

#### 增强安全

- [x] **安全策略文档**: SECURITY.md
- [x] **已知漏洞检查**: cargo-deny
- [x] **依赖最小化**: 仅必需依赖
- [x] **供应链安全**: cargo-vet
- [x] **安全代码审查**: 专人审查安全相关代码

#### 增强文档

- [x] **API 文档**: 所有公开 API 有 rustdoc
- [x] **架构文档**: ARCHITECTURE.md
- [x] **安全文档**: SECURITY.md
- [x] **使用示例**: examples/ 目录

---

### Gold 级别 (Level 4-5)

#### 高级质量

- [ ] **形式化验证**: 关键算法使用形式化方法验证
- [x] **代码覆盖率**: ≥ 90% (核心模块)
- [x] **回归测试**: 自动化回归测试
- [ ] **性能回归检测**: CI 中运行 benchmark
- [x] **多版本测试**: MSRV + stable + nightly

#### 高级安全

- [ ] **外部安全审计**: 聘请第三方安全公司审计
- [x] **漏洞赏金计划**: (待启动)
- [x] **签名发布**: 发布时使用 GPG 签名
- [x] **SBOM 生成**: cargo-sbom
- [ ] **威胁建模**: 完成威胁建模分析

#### 高级文档

- [x] **安全指南**: 安全使用指南
- [ ] **威胁模型文档**: 威胁分析报告
- [x] **合规文档**: 本文档

---

## 详细合规检查清单

### 1. 基础设施

```bash
✅ 许可证
  - LICENSE-MIT
  - LICENSE-APACHE
  - 所有文件头部包含许可证声明

✅ 文档
  - README.md (项目说明)
  - CONTRIBUTING.md (贡献指南)
  - CODE_OF_CONDUCT.md (行为准则)
  - CHANGELOG.md (变更日志)
  - SECURITY.md (安全策略)

✅ 社区
  - Issue 模板
  - PR 模板
  - CODEOWNERS
  - GitHub Discussions
```

### 2. 构建与测试

```bash
✅ 构建配置
  cargo build --all-features
  cargo build --no-default-features

✅ 测试套件
  cargo test --all-features --workspace
  cargo test --doc  # 文档测试

✅ 代码质量
  cargo fmt --check
  cargo clippy -- -D warnings

✅ 覆盖率
  cargo tarpaulin --all-features --workspace
  # 目标: ≥ 80%
```

### 3. 安全检查

```bash
✅ 依赖审计
  cargo audit
  cargo deny check
  cargo outdated

✅ 静态分析
  cargo clippy -- \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::panic

✅ Fuzz 测试
  cargo +nightly fuzz list
  cargo +nightly fuzz run <target> -- -max_total_time=3600

✅ SAST 扫描
  # GitHub CodeQL
  # Semgrep
```

### 4. 发布安全

```bash
✅ 版本签名
  git tag -s v0.1.0

✅ 发布检查
  cargo publish --dry-run
  cargo package --list

✅ SBOM 生成
  cargo sbom > fynx-0.1.0-sbom.json

✅ 校验和
  sha256sum target/package/fynx-0.1.0.crate
```

---

## 安全开发实践

### 1. 输入验证

```rust
/// ❌ 错误示例
fn process(data: &str) {
    let value = data.parse::<u32>().unwrap();  // 可能 panic
}

/// ✅ 正确示例
fn process(data: &str) -> FynxResult<u32> {
    data.parse::<u32>()
        .map_err(|_| FynxError::Protocol("Invalid number".into()))
}
```

### 2. 资源限制

```rust
/// ✅ 限制内存分配
const MAX_PACKET_SIZE: usize = 35_000;  // SSH RFC 4253

fn parse_packet(data: &[u8]) -> FynxResult<Packet> {
    if data.len() > MAX_PACKET_SIZE {
        return Err(FynxError::Protocol("Packet too large".into()));
    }
    // 解析逻辑
}
```

### 3. 时序安全

```rust
/// ✅ 使用常量时间比较
use subtle::ConstantTimeEq;

fn verify_mac(computed: &[u8], expected: &[u8]) -> bool {
    computed.ct_eq(expected).into()
}
```

### 4. 错误处理

```rust
/// ✅ 不泄露敏感信息
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // 不要输出用户名或密码
        write!(f, "Authentication failed")
    }
}
```

---

## 依赖安全策略

### 允许的依赖

```toml
# deny.toml
[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
]

[bans]
multiple-versions = "deny"
wildcards = "deny"
deny = [
    { name = "openssl" },  # 使用 rustls
]
```

### 依赖审查流程

1. **添加依赖前**:
   - 检查许可证兼容性
   - 查看 GitHub stars / 维护状态
   - 检查 CVE 历史
   - 评估是否真正需要

2. **定期审查**:
   - 每月运行 `cargo outdated`
   - 每周运行 `cargo audit`
   - 季度审查所有依赖必要性

3. **漏洞响应**:
   - Critical: 24 小时内更新
   - High: 7 天内更新
   - Medium: 30 天内更新

---

## 威胁模型

### 威胁场景

#### 1. 网络攻击
- **威胁**: 中间人攻击、重放攻击
- **缓解**: TLS/SSH 加密、HMAC 验证、nonce

#### 2. 恶意输入
- **威胁**: 缓冲区溢出、整数溢出、格式化字符串
- **缓解**: Rust 内存安全、输入验证、Fuzz 测试

#### 3. 依赖链攻击
- **威胁**: 恶意依赖、供应链投毒
- **缓解**: cargo-vet、审计、最小依赖

#### 4. 侧信道攻击
- **威胁**: 时序攻击、缓存攻击
- **缓解**: 常量时间算法、zeroize

---

## 合规检查工具

### 自动化检查脚本

```bash
#!/bin/bash
# scripts/security-check.sh

echo "🔍 Security Check"

echo "1. Dependency audit..."
cargo audit || exit 1

echo "2. License check..."
cargo deny check licenses || exit 1

echo "3. Static analysis..."
cargo clippy --all-features -- \
    -D warnings \
    -W clippy::unwrap_used \
    -W clippy::panic || exit 1

echo "4. Tests..."
cargo test --all-features --workspace || exit 1

echo "5. Coverage..."
cargo tarpaulin --all-features --workspace --out Xml
if [ $(grep -oP 'line-rate="\K[0-9.]+' coverage.xml | head -1 | awk '{print ($1 >= 0.8)}') -eq 0 ]; then
    echo "❌ Coverage < 80%"
    exit 1
fi

echo "✅ All security checks passed!"
```

---

## 安全联系方式

- **安全邮箱**: security@fynx.dev
- **PGP 公钥**: [公钥链接]
- **GitHub Security**: https://github.com/<org>/fynx/security/advisories
- **负责人**: Security Team <security@fynx.dev>

---

## 致谢

感谢以下安全研究人员的贡献：

- [待添加]

---

**文档版本**: 0.1.0
**最后更新**: 2025-01-17
**下次审查**: 2025-04-17
**维护者**: Fynx Security Team
