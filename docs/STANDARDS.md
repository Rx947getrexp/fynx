# Fynx 开发标准

本文档定义 Fynx 项目的开发流程、代码质量要求和工具链标准。

## 开发环境

### 必需工具

```bash
# Rust 工具链 (MSRV: 1.75)
rustup install 1.75
rustup default 1.75

# 必需组件
rustup component add rustfmt clippy

# 开发工具
cargo install cargo-audit      # 依赖安全审计
cargo install cargo-deny       # 许可证和依赖检查
cargo install cargo-outdated   # 依赖更新检查
cargo install cargo-fuzz       # Fuzz 测试
cargo install cargo-tarpaulin  # 代码覆盖率 (Linux)
```

### 推荐工具

```bash
cargo install cargo-watch      # 文件监视
cargo install cargo-edit       # 依赖管理
cargo install cargo-tree       # 依赖树可视化
cargo install cargo-bloat      # 二进制大小分析
```

---

## 代码质量标准

### 0. 代码文档要求（符合 crates.io 规范）

**强制要求**:
- ✅ 所有公开 API 必须有 rustdoc 注释
- ✅ 模块级文档 (`//!`) 说明模块用途
- ✅ 函数文档包含：描述、参数、返回值、错误、示例
- ✅ 示例代码必须可编译运行（doctest）
- ✅ 警告 `#![warn(missing_docs)]`

**文档模板**:
```rust
//! 模块级文档 - 说明模块整体功能
//!
//! # 示例
//!
//! ```
//! use fynx_module::Example;
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

/// 函数功能简述（一句话）
///
/// 详细说明函数作用、使用场景、注意事项
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
/// * [`FynxError::Config`] - 配置错误时返回
///
/// # 示例
///
/// ```
/// use fynx_platform::FynxResult;
///
/// fn example() -> FynxResult<()> {
///     // 示例代码
///     Ok(())
/// }
/// ```
///
/// # 安全性
///
/// （如涉及安全）说明安全使用要点
pub fn function(param: &str) -> FynxResult<String> {
    todo!()
}
```

### 1. Clippy 配置

项目根目录的 `.clippy.toml`:

```toml
# 严格检查
msrv = "1.75"
cognitive-complexity-threshold = 15
```

必须通过的 Clippy lint:

```bash
cargo clippy --all-targets --all-features -- \
    -D warnings \
    -D clippy::all \
    -D clippy::pedantic \
    -W clippy::nursery \
    -A clippy::module_name_repetitions \
    -A clippy::missing_errors_doc \
    -A clippy::missing_panics_doc
```

### 2. Rustfmt 配置

项目根目录的 `rustfmt.toml`:

```toml
edition = "2021"
max_width = 100
tab_spaces = 4
newline_style = "Unix"
use_small_heuristics = "Default"
reorder_imports = true
reorder_modules = true
remove_nested_parens = true
edition = "2021"
```

强制格式化:

```bash
cargo fmt --all -- --check
```

### 3. 测试覆盖率

- **最低要求**: 80% 行覆盖率
- **目标**: 90% 行覆盖率
- **核心模块** (platform, proto-ssh): 必须 ≥ 90%

测试命令:

```bash
# Linux
cargo tarpaulin --all-features --workspace --out Html --output-dir coverage

# 所有平台
cargo llvm-cov --all-features --workspace --html
```

### 4. Unsafe 代码规范

- **默认禁止**: 所有模块默认 `#![forbid(unsafe_code)]`
- **例外情况**:
  - FFI 绑定 (hsm 模块)
  - 性能关键路径 (经过审查和文档化)
  - 底层系统调用 (anti-debug)

**Unsafe 代码必须**:
```rust
// SAFETY: 明确说明为什么这段 unsafe 代码是安全的
// 1. 指针有效性保证
// 2. 内存对齐要求
// 3. 生命周期约束
unsafe {
    // unsafe 操作
}
```

---

## Git 工作流

### 分支策略

```
main          # 稳定版本，受保护
├── develop   # 开发主分支
│   ├── feature/ssh-handshake
│   ├── feature/yara-engine
│   └── fix/protocol-parsing
└── release/v0.1.0  # 发布分支
```

### 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**类型 (type)**:
- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更新
- `style`: 代码格式 (不影响功能)
- `refactor`: 重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具链

**示例**:
```
feat(proto): implement SSH handshake

- Add KEX algorithm negotiation
- Implement DH key exchange
- Add packet parsing for SSH_MSG_KEXINIT

Closes #123
```

### Pull Request 规范

**PR 标题**: 同提交规范

**PR 描述模板**:
```markdown
## 变更类型
- [ ] 新功能
- [ ] Bug 修复
- [ ] 重构
- [ ] 文档更新

## 变更说明
简要描述本次变更的目的和内容

## 测试
- [ ] 所有测试通过
- [ ] 添加新测试
- [ ] 手动测试步骤:
  1. ...
  2. ...

## 检查清单
- [ ] 代码已格式化 (`cargo fmt`)
- [ ] 通过 Clippy 检查
- [ ] 文档已更新
- [ ] CHANGELOG 已更新

## 关联 Issue
Closes #123
```

---

## CI/CD 流程

### GitHub Actions 工作流

#### 1. 持续集成 (.github/workflows/ci.yml)

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, 1.75]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
          components: rustfmt, clippy

      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Build
        run: cargo build --all-features --verbose

      - name: Test
        run: cargo test --all-features --verbose

      - name: Doc
        run: cargo doc --no-deps --all-features

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin
      - name: Generate coverage
        run: cargo tarpaulin --all-features --workspace --out Xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

#### 2. 安全审计 (.github/workflows/security.yml)

```yaml
name: Security

on:
  schedule:
    - cron: '0 0 * * *'  # 每天运行
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Cargo Audit
        run: cargo audit
      - name: Cargo Deny
        run: cargo deny check
```

#### 3. Fuzz 测试 (.github/workflows/fuzz.yml)

```yaml
name: Fuzz

on:
  schedule:
    - cron: '0 2 * * *'  # 每天凌晨 2 点
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Fuzz SSH parser
        run: cargo fuzz run ssh_parser -- -max_total_time=300
```

---

## 发布流程

### 版本号规范

遵循 [SemVer 2.0](https://semver.org/):

```
MAJOR.MINOR.PATCH

0.1.0  # 初始开发版本
0.2.0  # 添加新功能 (向后兼容)
0.2.1  # Bug 修复
1.0.0  # 稳定版本
```

### 发布检查清单

```bash
# 1. 更新版本号
vi crates/platform/Cargo.toml
vi crates/proto/Cargo.toml
...

# 2. 更新 CHANGELOG.md
vi CHANGELOG.md

# 3. 运行完整测试套件
cargo test --all-features --workspace
cargo clippy --all-features --workspace -- -D warnings
cargo fmt --all -- --check

# 4. 安全审计
cargo audit
cargo deny check

# 5. 文档检查
cargo doc --no-deps --all-features
# 手动检查 docs.rs 兼容性

# 6. 示例测试
for example in examples/*.rs; do
    cargo run --example $(basename $example .rs)
done

# 7. 创建 Git 标签
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# 8. 发布到 crates.io (按顺序)
cd crates/platform && cargo publish
cd ../proto && cargo publish
cd ../protect && cargo publish
cd ../detect && cargo publish
cd ../exploit && cargo publish  # 可选
cd ../rustsec && cargo publish

# 9. GitHub Release
gh release create v0.1.0 --notes-file CHANGELOG.md
```

---

## 依赖管理

### 依赖选择原则

1. **最小依赖**: 只添加必要的依赖
2. **稳定性优先**: 优先选择 ≥ 1.0 的稳定库
3. **维护活跃**: 选择活跃维护的项目
4. **安全记录**: 检查 CVE 历史

### 依赖更新策略

```toml
# Cargo.toml
[workspace.dependencies]
# 使用 ~ 指定最小版本
tokio = "~1.35"  # 接受 1.35.x 但不接受 1.36.0

# 关键依赖锁定精确版本
ring = "=0.17.7"
```

定期更新检查:

```bash
# 每月检查
cargo outdated --workspace

# 更新非破坏性版本
cargo update

# 审计
cargo audit fix
```

### 禁止的依赖

在 `deny.toml` 中配置:

```toml
[bans]
multiple-versions = "deny"
wildcards = "deny"

[[bans.deny]]
name = "openssl"  # 使用 rustls 替代
```

---

## 性能基准

### Benchmark 编写

```rust
// benches/ssh_handshake.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fynx_proto::ssh::SshClient;

fn benchmark_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("ssh_handshake");

    for size in [1024, 4096, 8192].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                // benchmark 代码
                black_box(size);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_handshake);
criterion_main!(benches);
```

### 性能回归检测

- 在 CI 中运行 benchmark
- 性能降低 > 10% 需要说明
- 使用 `criterion` 的历史对比功能

---

## 文档标准

### Rustdoc 要求

所有公开 API 必须有文档:

```rust
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

/// 模块文档
///
/// # 示例
///
/// ```
/// use fynx_proto::ssh::SshClient;
///
/// let client = SshClient::new()?;
/// # Ok::<(), fynx_platform::FynxError>(())
/// ```
pub mod ssh;
```

### README 必需内容

1. 项目描述
2. 功能特性
3. 安装说明
4. 快速开始
5. 示例代码
6. 许可证

### CHANGELOG 格式

遵循 [Keep a Changelog](https://keepachangelog.com/):

```markdown
# Changelog

## [Unreleased]
### Added
- 新功能

### Changed
- 变更内容

### Fixed
- Bug 修复

## [0.1.0] - 2025-01-17
### Added
- 初始版本
```

---

## 安全开发

### SAST 扫描

```bash
# Clippy 安全 lint
cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used

# 依赖审计
cargo audit

# 许可证检查
cargo deny check licenses
```

### Fuzz 测试

为关键解析器编写 fuzz target:

```rust
// fuzz/fuzz_targets/ssh_packet.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use fynx_proto::ssh::Packet;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::parse(data);
});
```

运行:

```bash
cargo +nightly fuzz run ssh_packet -- -max_total_time=3600
```

### 安全代码审查

-每个 PR 必须至少 1 位安全审查员批准
- 使用 GitHub Security Advisory 报告漏洞
- 90 天内修复 CVE

---

## 工具链配置

### .cargo/config.toml

```toml
[build]
rustflags = ["-D", "warnings"]

[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

[alias]
xtask = "run --package xtask --"
```

### rust-toolchain.toml

```toml
[toolchain]
channel = "1.75"
components = ["rustfmt", "clippy", "rust-src"]
targets = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "x86_64-apple-darwin"]
profile = "default"
```

---

**文档版本**: 0.1.0
**最后更新**: 2025-01-17
**维护者**: Fynx Core Team
