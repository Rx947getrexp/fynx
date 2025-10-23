# Fynx 发布指南

## ⚠️ 重要说明

**目前只有 2 个 crate 准备好发布：**
1. ✅ `fynx-platform` - 核心平台和类型
2. ✅ `fynx-proto` - SSH 协议实现

**请不要发布以下 crate（它们还是空壳）：**
- ❌ `fynx-protect` - 仅有空的 lib.rs
- ❌ `fynx-detect` - 仅有空的 lib.rs
- ❌ `fynx-exploit` - 仅有空的 lib.rs
- ❌ `fynx-rustsec` - 仅有空的 lib.rs

---

## 🚀 快速发布 (推荐)

### 方法 1: 使用自动化脚本

**Windows PowerShell**:
```powershell
cd E:\rust\fynx
.\publish.ps1
```

**Linux/macOS Bash**:
```bash
cd /path/to/fynx
chmod +x publish.sh
./publish.sh
```

脚本会自动完成以下步骤：
1. ✅ 运行所有测试
2. ✅ 发布 fynx-platform
3. ✅ 等待 crates.io 索引 (60秒)
4. ✅ 更新 fynx-proto 依赖
5. ✅ 发布 fynx-proto
6. ✅ 恢复本地路径依赖

---

## 📋 手动发布步骤

### 前置要求

1. **登录 crates.io**:
```bash
cargo login <YOUR_API_TOKEN>
```
获取 API Token: https://crates.io/me

2. **确保所有测试通过**:
```bash
cargo test --all-features --workspace
```

### 步骤 1: 发布 fynx-platform

```bash
cd crates/platform
cargo package --list  # 检查打包内容
cargo publish
cd ../..
```

### 步骤 2: 等待索引

**重要**: 等待 60 秒让 crates.io 索引 fynx-platform

```bash
# 等待 60 秒
sleep 60  # Linux/macOS
Start-Sleep -Seconds 60  # PowerShell
```

### 步骤 3: 更新 fynx-proto 依赖

**编辑** `crates/proto/Cargo.toml`:

```toml
# 修改前:
fynx-platform = { path = "../platform" }

# 修改后:
fynx-platform = "0.1.0-alpha.1"
```

### 步骤 4: 发布 fynx-proto

```bash
cd crates/proto
cargo package --list  # 检查打包内容
cargo publish
cd ../..
```

### 步骤 5: 恢复本地依赖（可选）

为了继续本地开发，将 `crates/proto/Cargo.toml` 改回路径依赖：

```toml
# 改回:
fynx-platform = { path = "../platform" }
```

---

## ⚠️ 常见错误和解决方案

### 错误 1: 路径依赖错误

```
error: failed to verify manifest at `Cargo.toml`
Caused by:
  all dependencies must have a version requirement specified when publishing.
  dependency `fynx-platform` does not specify a version
```

**原因**: Cargo.toml 使用了路径依赖 `{ path = "../platform" }`

**解决方案**:
1. 先发布 `fynx-platform`
2. 将依赖改为版本号 `"0.1.0-alpha.1"`
3. 再发布依赖它的 crate

### 错误 2: 版本不存在

```
error: failed to select a version for `fynx-platform`
```

**原因**: crates.io 还没有索引完成

**解决方案**: 等待 60 秒后重试

### 错误 3: 发布空 crate

```
warning: manifest has no documentation, homepage or repository
```

**原因**: 尝试发布未完成的 crate (protect/detect/exploit)

**解决方案**: 不要发布这些 crate，只发布 platform 和 proto

---

## 🔄 发布后操作

### 1. 创建 Git 标签

```bash
git tag -a v0.1.0-alpha.1 -m "Release v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

### 2. 创建 GitHub Release

访问: https://github.com/Rx947getrexp/fynx/releases/new

- Tag: `v0.1.0-alpha.1`
- Title: `Fynx v0.1.0-alpha.1 - Initial Alpha Release`
- Description: 使用 `RELEASE_READY.md` 中的模板

### 3. 验证发布

**检查 crates.io**:
- https://crates.io/crates/fynx-platform/0.1.0-alpha.1
- https://crates.io/crates/fynx-proto/0.1.0-alpha.1

**等待文档构建** (5-10分钟):
- https://docs.rs/fynx-platform
- https://docs.rs/fynx-proto

**测试安装**:
```bash
cargo new test-fynx
cd test-fynx
cargo add fynx-proto@0.1.0-alpha.1
cargo build
```

---

## 📊 依赖关系图

```
fynx-platform (无依赖)
    ↓
fynx-proto (依赖 platform)

fynx-protect (空壳，不发布)
fynx-detect (空壳，不发布)
fynx-exploit (空壳，不发布)
fynx-rustsec (空壳，不发布)
```

**发布顺序**: platform → proto

---

## 🎯 发布检查清单

**发布前**:
- [ ] 所有测试通过 (`cargo test --workspace`)
- [ ] 无编译警告 (`cargo build --release`)
- [ ] 已登录 crates.io (`cargo login`)
- [ ] Git 历史已清理 (无 Co-Authored-By)

**发布 fynx-platform**:
- [ ] `cd crates/platform`
- [ ] `cargo package --list` 检查内容
- [ ] `cargo publish`
- [ ] 等待 60 秒

**发布 fynx-proto**:
- [ ] 更新 Cargo.toml: `fynx-platform = "0.1.0-alpha.1"`
- [ ] `cd crates/proto`
- [ ] `cargo package --list` 检查内容
- [ ] `cargo publish`
- [ ] 恢复 Cargo.toml 路径依赖

**发布后**:
- [ ] 验证 crates.io 页面
- [ ] 等待 docs.rs 构建
- [ ] 创建 Git 标签
- [ ] 创建 GitHub Release
- [ ] 测试安装

---

## 💡 提示

1. **不要着急**: 在发布 fynx-proto 之前，一定要等待 fynx-platform 索引完成
2. **使用脚本**: 自动化脚本可以避免手动错误
3. **保留路径依赖**: 发布后恢复路径依赖，方便本地开发
4. **不发布空壳**: 只在 crate 有实际内容时才发布

---

**问题？** 查看 [PUBLISHING.md](PUBLISHING.md) 或 [RELEASE_READY.md](RELEASE_READY.md)
