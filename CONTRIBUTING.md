# 贡献指南

感谢您考虑为 Fynx 做出贡献！本文档将帮助您了解如何参与项目。

**最后更新**: 2025-10-19

---

## 🌟 贡献方式

### 1. 报告 Bug

发现 Bug？请创建一个 Issue:

1. 访问 [Issues](https://github.com/Rx947getrexp/fynx/issues)
2. 点击 "New Issue"
3. 选择 "Bug Report" 模板
4. 填写所有必需信息:
   - **环境**: OS, Rust 版本, Fynx 版本
   - **重现步骤**: 详细的复现步骤
   - **预期行为**: 应该发生什么
   - **实际行为**: 实际发生了什么
   - **最小可复现示例**: 简化的代码示例

### 2. 功能请求

有好主意？我们很乐意听取:

1. 访问 [Discussions](https://github.com/Rx947getrexp/fynx/discussions)
2. 选择 "Ideas" 分类
3. 描述您的想法:
   - **用例**: 这个功能解决什么问题？
   - **提议方案**: 您认为应该如何实现？
   - **替代方案**: 考虑过其他方法吗？

### 3. 提交代码

#### 准备工作

```bash
# 1. Fork 仓库并克隆
git clone https://github.com/YOUR_USERNAME/fynx.git
cd fynx

# 2. 添加上游仓库
git remote add upstream https://github.com/Rx947getrexp/fynx.git

# 3. 创建开发分支
git checkout -b feature/my-feature

# 4. 安装开发工具
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny
```

#### 开发流程

```bash
# 1. 编写代码
# - 遵循代码风格
# - 添加测试
# - 更新文档

# 2. 运行测试
cargo test --all-features --workspace

# 3. 格式化代码
cargo fmt --all

# 4. 运行 Clippy
cargo clippy --all-features -- -D warnings

# 5. 构建文档
cargo doc --no-deps --all-features

# 6. 提交更改
git add .
git commit -m "feat: add awesome feature"

# 7. 推送到您的 fork
git push origin feature/my-feature

# 8. 创建 Pull Request
```

---

## 📋 代码规范

### Rust 代码风格

遵循标准 Rust 风格指南:

```bash
# 格式化所有代码
cargo fmt --all

# 检查格式
cargo fmt --all -- --check
```

**关键规则**:
- 使用 4 空格缩进
- 行长度不超过 100 字符
- 使用有意义的变量名
- 公共 API 必须有文档

### Commit 消息规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**类型 (Type)**:
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 格式修改 (不影响代码逻辑)
- `refactor`: 重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具相关

**示例**:
```
feat(ssh): add port forwarding support

Implement local and remote port forwarding according to RFC 4254.

Closes #123
```

### 文档规范

所有公共 API 必须有 rustdoc 注释:

```rust
/// Connects to an SSH server.
///
/// # Arguments
///
/// * `addr` - Server address (e.g., "example.com:22")
///
/// # Returns
///
/// Returns an established SSH client on success.
///
/// # Errors
///
/// Returns an error if connection fails or handshake fails.
///
/// # Example
///
/// ```rust,no_run
/// use fynx_proto::ssh::SshClient;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = SshClient::connect("example.com:22").await?;
/// # Ok(())
/// # }
/// ```
pub async fn connect(addr: &str) -> FynxResult<Self> {
    // ...
}
```

---

## ✅ 测试要求

### 单元测试

每个新功能必须有对应的测试:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let result = my_function();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_async_function() {
        let result = async_function().await.unwrap();
        assert!(result.is_valid());
    }
}
```

### 测试覆盖率

- 目标覆盖率: **≥ 80%**
- 关键路径: **100%**

```bash
# 运行所有测试
cargo test --all-features --workspace

# 查看测试覆盖率 (需要 tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --all-features
```

### 集成测试

对于重要功能，添加集成测试:

```rust
// tests/integration_test.rs
use fynx_proto::ssh::SshClient;

#[tokio::test]
async fn test_full_connection_flow() {
    // 完整的连接、认证、执行流程测试
}
```

---

## 🔍 代码审查标准

您的 Pull Request 将根据以下标准审查:

### 1. 功能性
- [ ] 功能正确实现
- [ ] 没有引入回归
- [ ] 边界情况已处理

### 2. 代码质量
- [ ] 遵循 Rust 最佳实践
- [ ] 没有 unsafe 代码 (除非绝对必要)
- [ ] 错误处理完善
- [ ] 代码可读性好

### 3. 测试
- [ ] 有充分的单元测试
- [ ] 所有测试通过
- [ ] 覆盖率达标

### 4. 文档
- [ ] 公共 API 有 rustdoc
- [ ] 示例代码可运行
- [ ] README 更新 (如需)

### 5. 风格
- [ ] `cargo fmt` 通过
- [ ] `cargo clippy` 无警告
- [ ] Commit 消息规范

---

## 🚀 Pull Request 流程

### 1. 创建 PR

- **标题**: 简洁描述变更 (使用 Conventional Commits)
- **描述**: 详细说明:
  - 解决的问题
  - 实现方案
  - 破坏性变更 (如有)
  - 相关 Issue

### 2. 自查清单

创建 PR 前，确保:

```markdown
- [ ] 所有测试通过 (`cargo test --all-features`)
- [ ] 代码已格式化 (`cargo fmt`)
- [ ] Clippy 无警告 (`cargo clippy`)
- [ ] 文档已更新
- [ ] CHANGELOG.md 已更新 (对于功能/修复)
```

### 3. 审查过程

- 维护者将审查您的 PR
- 可能会要求修改
- 请及时回应审查意见
- 通过审查后将合并

### 4. 合并后

- 您的贡献将出现在 CHANGELOG
- 重大贡献者会被添加到 CONTRIBUTORS.md

---

## 🎯 新手友好的 Issues

寻找简单的起点？查找带有以下标签的 Issues:

- `good first issue`: 新手友好
- `help wanted`: 需要帮助
- `documentation`: 文档改进
- `enhancement`: 功能增强

---

## 💬 获取帮助

遇到问题？以下是获取帮助的途径:

1. **文档**: 查看 [docs/](docs/) 目录
2. **Discussions**: [GitHub Discussions](https://github.com/Rx947getrexp/fynx/discussions)
3. **Issues**: 搜索现有 Issues
4. **Email**: team@fynx.dev

---

## 🔒 安全问题

**请勿在公开 Issue 中报告安全漏洞！**

如发现安全问题:

1. 发送邮件至: security@fynx.dev
2. 包含详细信息 (受影响版本、复现步骤等)
3. 我们将在 48 小时内回复
4. 修复后会在 SECURITY.md 中公开致谢

详见: [SECURITY.md](SECURITY.md)

---

## 📜 行为准则

### 我们的承诺

为了营造开放和友好的环境，我们承诺:

- **尊重**: 尊重不同观点和经验
- **包容**: 欢迎所有背景的贡献者
- **专业**: 保持专业和礼貌
- **协作**: 鼓励团队合作

### 不可接受的行为

- 使用性化语言或图像
- 人身攻击或侮辱性评论
- 骚扰行为
- 发布他人隐私信息
- 其他不道德或不专业的行为

### 执行

违反行为准则可能导致:

1. 警告
2. 临时封禁
3. 永久封禁

举报: team@fynx.dev

---

## 📚 学习资源

### Rust 学习
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Rustlings](https://github.com/rust-lang/rustlings)

### SSH 协议
- [RFC 4251-4254](https://datatracker.ietf.org/doc/html/rfc4251)
- [OpenSSH Documentation](https://www.openssh.com/)
- [SSH Protocol Details](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)

### 项目文档
- [架构设计](docs/ARCHITECTURE.md)
- [开发标准](docs/STANDARDS.md)
- [SSH 文档](docs/ssh/README.md)

---

## 🙏 致谢

感谢所有贡献者！您的努力让 Fynx 变得更好。

特别感谢:
- [All Contributors](https://github.com/Rx947getrexp/fynx/graphs/contributors)
- Rust 社区
- 所有提供反馈的用户

---

## 📄 许可证

通过贡献代码，您同意您的贡献将按照 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 许可证授权。

---

**维护者**: Fynx Core Team

**联系方式**:
- **Issues**: https://github.com/Rx947getrexp/fynx/issues
- **Discussions**: https://github.com/Rx947getrexp/fynx/discussions
- **Email**: team@fynx.dev

感谢您的贡献！ 🎉
