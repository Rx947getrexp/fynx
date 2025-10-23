# SSH 未开发功能清单

本文档记录 Fynx SSH 实现中计划但尚未开发的功能。

**最后更新**: 2025-10-19
**状态**: 📋 计划中

---

## 📋 功能分类

### 🔴 高优先级（推荐下一步实现）

#### 1. 端口转发（Port Forwarding）
**优先级**: 🔴 高
**预计工作量**: 5-7 天
**依赖**: 通道管理（已完成）

##### 功能描述
- **Local Forward**: `-L` 本地端口转发到远程
- **Remote Forward**: `-R` 远程端口转发到本地
- **Dynamic Forward**: `-D` SOCKS 代理

##### 技术要点
```rust
// Local forwarding: localhost:8080 -> remote:80
client.local_forward("localhost:8080", "remote:80").await?;

// Remote forwarding: remote:8080 -> localhost:80
client.remote_forward("0.0.0.0:8080", "localhost:80").await?;

// Dynamic forwarding: SOCKS5 proxy on localhost:1080
client.dynamic_forward("localhost:1080").await?;
```

##### RFC 参考
- RFC 4254 Section 7: TCP/IP Port Forwarding

##### 实现建议
1. Stage 8.1: Local port forwarding
2. Stage 8.2: Remote port forwarding
3. Stage 8.3: Dynamic forwarding (SOCKS5)

---

#### 2. SFTP 协议支持
**优先级**: 🔴 高
**预计工作量**: 7-10 天
**依赖**: 通道管理（已完成）

##### 功能描述
- 文件上传/下载
- 目录操作（ls, mkdir, rmdir）
- 文件属性获取/设置
- 符号链接支持
- 文件锁定

##### 技术要点
```rust
// SFTP session
let sftp = client.sftp().await?;

// Upload file
sftp.upload("local.txt", "/remote/path/file.txt").await?;

// Download file
sftp.download("/remote/path/file.txt", "local.txt").await?;

// List directory
let entries = sftp.readdir("/remote/path").await?;

// File attributes
let stat = sftp.stat("/remote/file").await?;
```

##### RFC 参考
- [draft-ietf-secsh-filexfer](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13) - SFTP v6 (推荐实现 v3)

##### 实现建议
1. Stage 8.4: SFTP 基础协议（v3）
2. Stage 8.5: 文件传输优化
3. Stage 8.6: 扩展属性支持

---

#### 3. 会话管理（Session Management）
**优先级**: 🔴 高
**预计工作量**: 3-5 天
**依赖**: 通道管理（已完成）

##### 功能描述
- 多通道并发管理
- 会话复用（ControlMaster）
- 连接池
- 断线重连
- Keep-alive 心跳

##### 技术要点
```rust
// Connection pooling
let pool = SshConnectionPool::new(config);
let conn = pool.get("user@host").await?;

// Keep-alive
client.set_keepalive(Duration::from_secs(60))?;

// Session multiplexing
let session = client.session();
let chan1 = session.channel().await?;
let chan2 = session.channel().await?;
```

##### 实现建议
1. Stage 8.7: 多通道管理
2. Stage 8.8: 连接池
3. Stage 8.9: 断线重连机制

---

### 🟡 中优先级（可选增强）

#### 4. ssh-agent 支持
**优先级**: 🟡 中
**预计工作量**: 3-4 天
**依赖**: 公钥认证（已完成）

##### 功能描述
- 连接到 ssh-agent
- 请求密钥列表
- 使用 agent 进行签名
- Agent forwarding

##### 技术要点
```rust
// Connect to ssh-agent
let agent = SshAgent::connect()?;

// List keys
let keys = agent.list_identities().await?;

// Use agent for authentication
client.authenticate_agent("user", &agent).await?;

// Agent forwarding
client.set_agent_forwarding(true)?;
```

##### 协议参考
- [draft-ietf-secsh-agent](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04) - SSH Agent Protocol

##### 实现建议
1. Stage 7.5: Agent 协议实现
2. Stage 7.6: Agent forwarding

---

#### 5. SCP 支持
**优先级**: 🟡 中
**预计工作量**: 2-3 天
**依赖**: 命令执行（已完成）

##### 功能描述
- 文件上传（scp local remote）
- 文件下载（scp remote local）
- 递归目录复制
- 进度显示

##### 技术要点
```rust
// SCP upload
client.scp_upload("local.txt", "remote:/path/file.txt").await?;

// SCP download
client.scp_download("remote:/path/file.txt", "local.txt").await?;

// Recursive copy
client.scp_upload_dir("local_dir", "remote:/path/").await?;
```

##### 实现建议
1. Stage 8.10: SCP 基础实现
2. Stage 8.11: 递归复制和进度

---

#### 6. 性能优化
**优先级**: 🟡 中
**预计工作量**: 持续进行
**依赖**: 核心功能（已完成）

##### 优化方向
- **零拷贝**: 减少内存复制
- **批量操作**: 批量发送小包
- **并发优化**: 多通道并行传输
- **缓冲调优**: 优化 TCP 窗口大小
- **压缩**: zlib 压缩支持

##### 技术要点
```rust
// Enable compression
config.compression = CompressionAlgorithm::Zlib;

// Buffer tuning
config.send_buffer_size = 256 * 1024; // 256KB
config.recv_buffer_size = 256 * 1024;

// Parallel transfer
let tasks: Vec<_> = files.iter()
    .map(|f| tokio::spawn(upload(f)))
    .collect();
```

##### 实现建议
1. Stage 9.1: 零拷贝优化
2. Stage 9.2: 压缩支持
3. Stage 9.3: 性能基准测试

---

### 🟢 低优先级（长期计划）

#### 7. 证书认证（Certificate Authentication）
**优先级**: 🟢 低
**预计工作量**: 5-7 天
**依赖**: 公钥认证（已完成）

##### 功能描述
- SSH 证书格式解析
- 证书签名验证
- CA 密钥管理
- 证书撤销列表（CRL）

##### 协议参考
- [PROTOCOL.certkeys](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) - OpenSSH Certificate

##### 实现建议
1. Stage 7.7: 证书解析
2. Stage 7.8: 证书验证

---

#### 8. X11 转发
**优先级**: 🟢 低
**预计工作量**: 4-5 天
**依赖**: 通道管理（已完成）

##### 功能描述
- X11 显示转发
- X11 认证 cookie
- MIT-MAGIC-COOKIE-1

##### 技术要点
```rust
// Enable X11 forwarding
client.set_x11_forwarding(true)?;

// Execute GUI application
client.execute("xeyes").await?;
```

##### RFC 参考
- RFC 4254 Section 6.3.1: X11 Forwarding

---

#### 9. 密钥交换扩展
**优先级**: 🟢 低
**预计工作量**: 3-4 天
**依赖**: 密钥交换（已完成）

##### 未实现的 KEX 算法
- `diffie-hellman-group14-sha256` (推荐)
- `diffie-hellman-group16-sha512`
- `diffie-hellman-group-exchange-sha256`
- `ecdh-sha2-nistp521`

##### 实现建议
- Stage 4.5: 额外 DH 组
- Stage 4.6: Group Exchange

---

#### 10. 主机密钥算法扩展
**优先级**: 🟢 低
**预计工作量**: 2-3 天
**依赖**: 主机密钥（已完成）

##### 未完整实现的算法
- RSA 签名验证（客户端有，服务器待完善）
- ECDSA 签名验证（客户端有，服务器待完善）
- `rsa-sha2-256` 服务器端完整支持
- `rsa-sha2-512` 服务器端完整支持

##### 实现建议
- Stage 7.9: 完善服务器端 RSA/ECDSA 验证

---

## 📊 实现优先级矩阵

| 功能 | 用户需求 | 技术难度 | 工作量 | 总优先级 |
|-----|---------|---------|--------|---------|
| 端口转发 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | 5-7天 | 🔴 高 |
| SFTP | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 7-10天 | 🔴 高 |
| 会话管理 | ⭐⭐⭐⭐ | ⭐⭐⭐ | 3-5天 | 🔴 高 |
| ssh-agent | ⭐⭐⭐ | ⭐⭐⭐ | 3-4天 | 🟡 中 |
| SCP | ⭐⭐⭐ | ⭐⭐ | 2-3天 | 🟡 中 |
| 性能优化 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 持续 | 🟡 中 |
| 证书认证 | ⭐⭐ | ⭐⭐⭐ | 5-7天 | 🟢 低 |
| X11 转发 | ⭐ | ⭐⭐⭐ | 4-5天 | 🟢 低 |
| KEX 扩展 | ⭐⭐ | ⭐⭐ | 3-4天 | 🟢 低 |
| 主机密钥扩展 | ⭐⭐ | ⭐⭐ | 2-3天 | 🟢 低 |

---

## 🎯 推荐开发路线图

### Phase 2 (v0.2.0) - 高级特性
**预计时间**: 4-6 周

1. **Week 1-2**: 端口转发（Local + Remote + Dynamic）
2. **Week 3-4**: SFTP 基础协议（v3）
3. **Week 5**: 会话管理（多通道、连接池）
4. **Week 6**: 测试、优化、文档

**发布标准**:
- 端口转发完整测试
- SFTP 基本操作可用
- 会话管理稳定
- 文档完整

### Phase 3 (v0.3.0) - 增强与优化
**预计时间**: 3-4 周

1. **Week 1**: ssh-agent 支持
2. **Week 2**: SCP 实现
3. **Week 3**: 性能优化（零拷贝、压缩）
4. **Week 4**: 测试、文档、发布

**发布标准**:
- ssh-agent 基本功能
- SCP 文件传输
- 性能基准测试
- 优化文档

### Phase 4 (v0.4.0) - 完善与扩展
**预计时间**: 2-3 周

1. **Week 1**: 证书认证
2. **Week 2**: KEX 和主机密钥扩展
3. **Week 3**: 完善测试和文档

**发布标准**:
- 证书认证可选支持
- 更多 KEX 算法
- 完整测试覆盖

---

## 🔗 其他协议（非 SSH）

### DTLS 协议
**状态**: 📋 未开始
**优先级**: 🟡 中
**预计工作量**: 4-6 周

- DTLS 1.2 实现
- 握手协议
- 记录层协议
- 重传机制

### IPSec 协议
**状态**: 📋 未开始
**优先级**: 🟢 低
**预计工作量**: 8-10 周

- IKEv2 协议
- ESP/AH 协议
- 隧道模式
- 传输模式

### PKCS#11/HSM
**状态**: 📋 未开始
**优先级**: 🟢 低
**预计工作量**: 4-6 周

- PKCS#11 C 绑定
- HSM 设备管理
- 密钥操作
- 证书管理

---

## 📝 如何贡献

如果您想实现某个未开发功能：

1. **查看此文档**: 了解功能描述和技术要点
2. **创建 Issue**: 在 GitHub 上创建功能请求
3. **讨论设计**: 在 Discussions 中讨论实现方案
4. **创建 Stage 计划**: 参考现有 `STAGEX_Y_PLAN.md` 格式
5. **实现功能**: 遵循开发标准
6. **提交 PR**: 包含代码、测试、文档
7. **更新此文档**: 将功能从"未开发"移到"已完成"

---

## 📞 联系方式

- **Issues**: https://github.com/Rx947getrexp/fynx/issues
- **Discussions**: https://github.com/Rx947getrexp/fynx/discussions
- **Email**: team@fynx.dev

---

**维护者**: Fynx Core Team
**最后审核**: 2025-10-19
