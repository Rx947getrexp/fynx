# Fynx 文档中心

欢迎来到 Fynx 项目文档中心！这里包含了项目的完整技术文档。

## 📚 文档导航

### 新手入门

从这里开始了解 Fynx：

1. **[项目 README](../README.md)** - 项目概述和快速开始
2. **[架构设计](ARCHITECTURE.md)** - 理解整体架构
3. **[命名规范](NAMING.md)** - 了解命名约定

### 开发指南

开发 Fynx 模块时参考这些文档：

1. **[模块设计规范](MODULE_DESIGN.md)** - 模块开发标准和接口定义
2. **[开发标准](STANDARDS.md)** - 代码质量、测试、CI/CD 要求
3. **[安全策略](SECURITY.md)** - OpenSSF 合规和安全开发实践

### 模块文档

每个模块的详细文档：

- **fynx-platform**: [docs.rs](https://docs.rs/fynx-platform)
- **fynx-proto**: [docs.rs](https://docs.rs/fynx-proto)
- **fynx-protect**: [docs.rs](https://docs.rs/fynx-protect)
- **fynx-detect**: [docs.rs](https://docs.rs/fynx-detect)
- **fynx-exploit**: [docs.rs](https://docs.rs/fynx-exploit)

## 📖 文档列表

### 核心文档

| 文档 | 说明 | 受众 |
|------|------|------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 项目架构设计、模块职责、依赖关系 | 所有开发者 |
| [MODULE_DESIGN.md](MODULE_DESIGN.md) | 模块开发规范、接口定义、代码示例 | 模块开发者 |
| [NAMING.md](NAMING.md) | 命名约定、目录结构、代码风格 | 所有开发者 |
| [STANDARDS.md](STANDARDS.md) | 开发流程、质量标准、工具链配置 | 所有开发者 |
| [SECURITY.md](SECURITY.md) | 安全策略、OpenSSF 合规、漏洞报告 | 安全研究员、开发者 |

### 项目管理

| 文档 | 说明 |
|------|------|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | 贡献指南 |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | 行为准则 |
| [CHANGELOG.md](../CHANGELOG.md) | 变更日志 |
| [LICENSE-MIT](../LICENSE-MIT) | MIT 许可证 |
| [LICENSE-APACHE](../LICENSE-APACHE) | Apache 2.0 许可证 |

## 🎯 按角色查看

### 我是新贡献者

推荐阅读顺序：

1. [README](../README.md) - 了解项目
2. [CONTRIBUTING.md](../CONTRIBUTING.md) - 如何贡献
3. [ARCHITECTURE.md](ARCHITECTURE.md) - 理解架构
4. [STANDARDS.md](STANDARDS.md) - 开发标准
5. 选择一个模块开始贡献

### 我要开发新模块

推荐阅读顺序：

1. [ARCHITECTURE.md](ARCHITECTURE.md) - 了解模块在整体架构中的位置
2. [MODULE_DESIGN.md](MODULE_DESIGN.md) - 学习模块设计规范
3. [NAMING.md](NAMING.md) - 遵循命名约定
4. [STANDARDS.md](STANDARDS.md) - 满足质量标准
5. [SECURITY.md](SECURITY.md) - 确保安全合规

### 我要报告安全漏洞

直接查看：

- [SECURITY.md](SECURITY.md) - 漏洞报告流程和联系方式

### 我是安全审计员

推荐阅读：

1. [SECURITY.md](SECURITY.md) - OpenSSF 合规检查清单
2. [ARCHITECTURE.md](ARCHITECTURE.md) - 理解攻击面
3. [MODULE_DESIGN.md](MODULE_DESIGN.md) - 了解接口和数据流
4. [STANDARDS.md](STANDARDS.md) - 验证开发实践

## 🔍 快速查询

### 如何...

- **添加新依赖？** → [STANDARDS.md # 依赖管理](STANDARDS.md#依赖管理)
- **创建新模块？** → [MODULE_DESIGN.md # 模块通用规范](MODULE_DESIGN.md#模块通用规范)
- **发布新版本？** → [STANDARDS.md # 发布流程](STANDARDS.md#发布流程)
- **报告 Bug？** → [CONTRIBUTING.md](../CONTRIBUTING.md)
- **配置 CI？** → [STANDARDS.md # CI/CD 流程](STANDARDS.md#cicd-流程)

### 规范在哪里？

- **模块命名** → [NAMING.md # 模块命名](NAMING.md#模块命名)
- **代码风格** → [MODULE_DESIGN.md # 代码风格](MODULE_DESIGN.md#代码风格)
- **提交信息** → [STANDARDS.md # 提交规范](STANDARDS.md#提交规范)
- **API 文档** → [MODULE_DESIGN.md # 文档规范](MODULE_DESIGN.md#文档规范)
- **测试要求** → [MODULE_DESIGN.md # 测试规范](MODULE_DESIGN.md#测试规范)

## 📝 文档维护

### 文档版本

所有文档都包含版本号和最后更新日期：

```markdown
**文档版本**: 0.1.0
**最后更新**: 2025-01-17
**维护者**: Fynx Core Team
```

### 更新文档

文档更新流程：

1. 修改文档内容
2. 更新 "最后更新" 日期
3. 如有重大变更，增加版本号
4. 提交 PR 并标注 `docs` 标签
5. 至少 1 位审查员批准

### 文档问题

发现文档问题？

- 打开 [Issue](https://github.com/<org>/fynx/issues/new?labels=documentation)
- 或直接提交 PR 修复

## 🌐 外部资源

### Rust 生态

- [Rust 官方文档](https://doc.rust-lang.org/)
- [The Rust Programming Language Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

### 安全标准

- [OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### 协议标准

- [SSH RFCs](https://www.rfc-editor.org/search/rfc_search_detail.php?title=ssh)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [IPsec RFCs](https://www.rfc-editor.org/search/rfc_search_detail.php?title=ipsec)

---

**需要帮助？**

- 💬 [GitHub Discussions](https://github.com/<org>/fynx/discussions)
- 📧 [team@fynx.dev](mailto:team@fynx.dev)
- 🔒 [security@fynx.dev](mailto:security@fynx.dev) (安全问题)

**文档版本**: 0.1.0
**最后更新**: 2025-01-17
