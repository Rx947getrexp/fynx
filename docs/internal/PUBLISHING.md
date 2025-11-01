# Fynx 发布指南

本文档描述如何将 Fynx 各个 crate 发布到 crates.io。

**状态**: ✅ 准备就绪
**最后更新**: 2025-10-19

---

## 📋 发布前检查清单

### ✅ 已完成项

- [x] **LICENSE 文件**: MIT 和 Apache-2.0 许可证已添加
- [x] **仓库 URL**: 更新为 `https://github.com/Rx947getrexp/fynx`
- [x] **版本号**: 设置为 `0.1.0-alpha.1`
- [x] **作者信息**: 更新为 "Fynx Core Team"
- [x] **编译警告**: 已修复
- [x] **测试**: 172 个测试全部通过
- [x] **文档**: rustdoc 100% 覆盖
- [x] **SSH 文档**: 整理到 `docs/ssh/` 目录

### ⚠️ 待处理项

- [ ] **GitHub 仓库**: 需要创建/配置 `Rx947getrexp/fynx`
- [ ] **CI/CD**: 建议添加 GitHub Actions
- [ ] **CONTRIBUTING.md**: 建议添加贡献指南
- [ ] **路径依赖**: 需要先发布 `fynx-platform`

---

## 🚀 发布顺序

由于 `fynx-proto` 依赖 `fynx-platform`，必须按以下顺序发布：

### 1. 发布 fynx-platform (基础库)

```bash
cd crates/platform

# 检查打包内容
cargo package --list

# 测试打包
cargo package --allow-dirty

# 实际发布
cargo publish
```

**预期内容**:
- `src/lib.rs` - 核心错误类型和 trait
- `README.md` - 说明文档
- `Cargo.toml` - 元数据

### 2. 更新 fynx-proto 依赖

发布 `fynx-platform` 后，更新 `crates/proto/Cargo.toml`:

```toml
[dependencies]
# 从路径依赖改为版本依赖
fynx-platform = "0.1.0-alpha.1"
```

### 3. 发布 fynx-proto (SSH 协议)

```bash
cd crates/proto

# 检查打包内容
cargo package --list

# 测试打包
cargo package --allow-dirty

# 实际发布
cargo publish
```

**预期内容**:
- 所有 SSH 模块源代码 (`src/ssh/`)
- 测试文件 (`tests/`)
- 示例代码 (`examples/`)
- `README.md`, `INTEROP_RESULTS.md`, `OPENSSH_TESTING.md`

---

## 📦 发布命令详解

### 检查打包内容

```bash
# 查看将要包含在 crate 中的文件
cargo package --list -p fynx-platform
cargo package --list -p fynx-proto
```

### 测试打包（不上传）

```bash
# 允许未提交的更改进行测试打包
cargo package --allow-dirty -p fynx-platform

# 验证打包结果
ls -lh target/package/fynx-platform-0.1.0-alpha.1.crate
```

### 实际发布

```bash
# 需要先登录 crates.io
cargo login <YOUR_API_TOKEN>

# 发布到 crates.io
cargo publish -p fynx-platform
cargo publish -p fynx-proto
```

---

## 🔧 发布后配置

### 1. 更新 README badges

```markdown
[![crates.io](https://img.shields.io/crates/v/fynx-proto.svg)](https://crates.io/crates/fynx-proto)
[![Documentation](https://docs.rs/fynx-proto/badge.svg)](https://docs.rs/fynx-proto)
[![License](https://img.shields.io/crates/l/fynx-proto)](LICENSE-MIT)
```

### 2. 创建 Git 标签

```bash
git tag -a v0.1.0-alpha.1 -m "Release v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

### 3. 创建 GitHub Release

在 GitHub 仓库创建 Release:
- Tag: `v0.1.0-alpha.1`
- Title: "Fynx v0.1.0-alpha.1 - Initial Alpha Release"
- 描述: 参考 `RELEASE_NOTES.md`

---

## 📝 发布说明模板

创建 `RELEASE_NOTES.md`:

```markdown
# Fynx v0.1.0-alpha.1 - Initial Alpha Release

**发布日期**: 2025-10-19
**状态**: Alpha (实验性)

## 🎉 首次发布

这是 Fynx 的首次公开发布，包含基础 SSH 协议实现。

## 📦 发布的 Crates

- `fynx-platform` v0.1.0-alpha.1 - 核心平台和类型
- `fynx-proto` v0.1.0-alpha.1 - SSH 协议实现

## ✨ 主要功能

### SSH 客户端
- ✅ TCP 连接和版本交换
- ✅ 密钥交换 (Curve25519)
- ✅ 加密/MAC (ChaCha20-Poly1305, AES-GCM)
- ✅ 密码认证
- ✅ 公钥认证 (Ed25519, RSA, ECDSA)
- ✅ 命令执行
- ✅ known_hosts 支持 (MITM 检测)
- ✅ 私钥加载 (PEM, OpenSSH 格式)

### SSH 服务器
- ✅ 基础服务器监听
- ✅ 密钥交换
- ✅ 密码认证
- ✅ 公钥认证 (Ed25519)
- ✅ authorized_keys 支持

## 📊 代码质量

- **测试**: 172 个单元测试，100% 通过率
- **Unsafe代码**: 0 行
- **文档覆盖**: 100% rustdoc
- **RFC合规**: RFC 4251-4254

## ⚠️ 限制和注意事项

### Alpha 版本警告
此版本为 **实验性 Alpha 版本**，不建议用于生产环境。API 可能会有破坏性变更。

### 未实现的功能
- 端口转发 (Local/Remote/Dynamic)
- SFTP 协议
- SCP 支持
- ssh-agent 集成
- 证书认证
- X11 转发

详见: [docs/ssh/TODO.md](docs/ssh/TODO.md)

### 已知问题
- RSA/ECDSA 服务器端签名验证未完全实现
- 仅支持 Curve25519 密钥交换
- 未实现压缩

## 🔗 资源

- **文档**: https://docs.rs/fynx-proto
- **仓库**: https://github.com/Rx947getrexp/fynx
- **Issues**: https://github.com/Rx947getrexp/fynx/issues
- **SSH 文档**: [docs/ssh/README.md](docs/ssh/README.md)

## 🙏 致谢

感谢所有为 Fynx 项目做出贡献的开发者和 Rust 社区。

## 📞 支持

- **Issues**: https://github.com/Rx947getrexp/fynx/issues
- **Discussions**: https://github.com/Rx947getrexp/fynx/discussions
```

---

## 🔄 后续版本发布流程

### 小版本发布 (0.1.x)

1. 更新版本号
2. 更新 CHANGELOG.md
3. 运行测试
4. 提交更改
5. 发布到 crates.io
6. 创建 Git 标签

### 大版本发布 (0.x.0)

1. 完成功能开发
2. 运行完整测试套件
3. 更新所有文档
4. 进行代码审查
5. 发布测试版 (beta)
6. 收集反馈
7. 正式发布

---

## ❓ 常见问题

### Q: 如何撤回已发布的版本？

A: **不能撤回**。crates.io 不允许删除已发布的版本。只能发布新版本 (yank)。

```bash
# 标记版本为 yanked (不推荐下载，但不删除)
cargo yank --vers 0.1.0-alpha.1 -p fynx-proto

# 取消 yank
cargo yank --undo --vers 0.1.0-alpha.1 -p fynx-proto
```

### Q: 发布失败怎么办？

A: 检查以下常见问题:

1. **版本号重复**: 不能发布已存在的版本
2. **名称冲突**: crate 名称已被占用
3. **依赖问题**: 路径依赖或不存在的依赖
4. **文件缺失**: README, LICENSE 等
5. **大小限制**: 单个 crate 不超过 10MB

### Q: 如何更新已发布的 crate？

A: 增加版本号并重新发布:

```bash
# 在 Cargo.toml 中更新版本
version = "0.1.1-alpha.1"

# 重新发布
cargo publish
```

---

## 📚 参考资源

- [Cargo Book - Publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [crates.io Policies](https://crates.io/policies)
- [Semantic Versioning](https://semver.org/)

---

**维护者**: Fynx Core Team
**最后审核**: 2025-10-19
