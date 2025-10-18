# Fynx 命名规范

## 模块命名

所有 crate 使用 `fynx-` 前缀 + 简写名称：

| 完整名称 | Crate 名称 | 目录名 | 简写理由 |
|---------|-----------|--------|---------|
| platform | `fynx-platform` | `platform` | 核心基础，保持完整 |
| protocol | `fynx-proto` | `proto` | 通用简写 (protocol → proto) |
| protect | `fynx-protect` | `protect` | 已足够简短 |
| detect | `fynx-detect` | `detect` | 已足够简短 |
| eexploit | `fynx-exploit` | `exploit` | 去掉元音 (eexploit → exploit) |
| rustsec | `fynx` | `rustsec` | 元包，仅使用项目名 |

## 目录结构

```
fynx/
├── crates/
│   ├── platform/       → fynx-platform
│   ├── proto/          → fynx-proto
│   ├── protect/        → fynx-protect
│   ├── detect/         → fynx-detect
│   ├── exploit/         → fynx-exploit
│   └── rustsec/        → fynx
```

## 使用示例

### 在 Cargo.toml 中引用

```toml
[dependencies]
fynx-platform = "0.1"
fynx-proto = "0.1"
fynx-protect = "0.1"
fynx-detect = "0.1"
fynx-exploit = "0.1"
```

### 在代码中使用

```rust
use fynx_platform::{FynxError, FynxResult};
use fynx_proto::ssh::SshClient;
use fynx_protect::obfstr;
use fynx_detect::yara::YaraEngine;
use fynx_exploit::scanner::PortScanner;
```

## 模块内命名约定

### 文件名
- 使用 snake_case
- 文件名应描述其内容
- 示例: `error.rs`, `ssh_client.rs`, `yara_engine.rs`

### 类型名
- 结构体/枚举使用 PascalCase
- Trait 使用 PascalCase
- 示例: `SshClient`, `YaraEngine`, `ProtocolStack`

### 函数名
- 使用 snake_case
- 动词开头
- 示例: `connect()`, `parse_packet()`, `scan_ports()`

### 常量名
- 使用 SCREAMING_SNAKE_CASE
- 示例: `MAX_PACKET_SIZE`, `DEFAULT_TIMEOUT`

### 特性标志名
- 使用 kebab-case
- 简短描述功能
- 示例: `ssh`, `dtls`, `anti-debug`

---

**文档版本**: 0.1.0
**最后更新**: 2025-01-17
