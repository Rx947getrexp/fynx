# Stage 7.4: known_hosts 文件支持（客户端）

**阶段**: Stage 7 - 公钥认证与密钥管理
**子阶段**: 7.4 - known_hosts 支持（Week 6）
**开始日期**: 2025-10-19
**预计完成**: 2025-10-22
**状态**: 📋 计划中

---

## 🎯 目标

实现 OpenSSH 兼容的 known_hosts 文件支持，为 SSH 客户端提供主机密钥验证功能，防止中间人（MITM）攻击。

### 成功标准

- [ ] 解析 known_hosts 文件（标准格式 + 哈希格式）
- [ ] 主机密钥验证（匹配已知主机）
- [ ] 哈希主机名匹配（|1|salt|hash 格式）
- [ ] 通配符主机模式（*.example.com）
- [ ] 添加新主机密钥
- [ ] 更新变更的主机密钥
- [ ] 未知主机警告
- [ ] 严格主机密钥检查模式：
  - `strict` - 拒绝未知主机
  - `ask` - 提示用户确认
  - `accept-new` - 自动添加新主机
  - `no` - 接受所有（不安全，仅测试用）
- [ ] 10+ 单元测试全部通过
- [ ] 完整的 rustdoc 文档

---

## 📋 详细任务

### Task 1: known_hosts 文件格式解析

**优先级**: 🔴 高
**预计时间**: 1 天

#### known_hosts 文件格式

```text
# 标准格式 (明文主机名)
example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

# 哈希格式 (隐藏主机名)
|1|salt|hash ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

# 带端口号
[example.com]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAA...

# 通配符模式
*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

# 多个主机名 (逗号分隔)
host1,host2,host3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

# Negation (排除模式)
*.example.com,!bad.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

# 注释
# This is a comment
```

#### 子任务

1. **创建 known_hosts.rs 模块**
   - [ ] 定义 KnownHost 结构体
   - [ ] 定义 KnownHostsFile 结构体
   - [ ] 定义 HostKeyStatus 枚举

2. **主机名格式解析**
   - [ ] 解析明文主机名
   - [ ] 解析哈希主机名（|1|salt|hash 格式）
   - [ ] 解析带端口号的主机名（[host]:port）
   - [ ] 解析通配符模式（*.example.com）
   - [ ] 解析多主机名（逗号分隔）
   - [ ] 解析否定模式（!host）

3. **公钥格式解析**
   - [ ] 解析 ssh-ed25519 公钥
   - [ ] 解析 ssh-rsa 公钥
   - [ ] 解析 ecdsa-sha2-* 公钥
   - [ ] 解析 rsa-sha2-256/512 公钥

4. **文件加载**
   - [ ] 从文件路径加载
   - [ ] 从字符串解析
   - [ ] 跳过注释和空行
   - [ ] 错误处理（格式错误行）

5. **测试**
   - [ ] test_parse_standard_format
   - [ ] test_parse_hashed_format
   - [ ] test_parse_with_port
   - [ ] test_parse_wildcard
   - [ ] test_parse_multi_host
   - [ ] test_load_from_file

---

### Task 2: 主机密钥验证逻辑

**优先级**: 🔴 高
**预计时间**: 1.5 天

#### 验证流程

```
1. 从 known_hosts 加载已知主机
2. 提取连接主机名和端口
3. 查找匹配的主机记录：
   a. 标准匹配：host:port == known_host
   b. 哈希匹配：HMAC(salt, "host:port") == hash
   c. 通配符匹配：host matches pattern
4. 比较主机密钥：
   a. 如果匹配 → 验证通过
   b. 如果不匹配 → 密钥变更警告
   c. 如果未找到 → 未知主机处理
```

#### 子任务

1. **主机匹配逻辑**
   - [ ] 实现标准主机名匹配
   - [ ] 实现哈希主机名匹配（HMAC-SHA1）
   - [ ] 实现通配符匹配（*.example.com）
   - [ ] 实现端口号匹配
   - [ ] 实现多主机名匹配
   - [ ] 实现否定模式匹配

2. **密钥验证**
   - [ ] 实现 verify_host_key() 方法
   - [ ] 主机密钥比较（算法 + 数据）
   - [ ] 返回 HostKeyStatus 枚举：
     - `Known` - 已知且匹配
     - `Changed` - 已知但密钥变更
     - `Unknown` - 未知主机

3. **错误处理**
   - [ ] 文件不存在（创建新文件）
   - [ ] 格式错误（跳过并警告）
   - [ ] 权限错误（警告用户）

4. **测试**
   - [ ] test_verify_known_host
   - [ ] test_verify_hashed_host
   - [ ] test_verify_wildcard_host
   - [ ] test_detect_key_change
   - [ ] test_detect_unknown_host

---

### Task 3: 主机密钥检查策略

**优先级**: 🔴 高
**预计时间**: 1 天

#### 检查策略

```rust
pub enum StrictHostKeyChecking {
    /// 严格模式：拒绝所有未知和变更的密钥
    Strict,
    /// 询问模式：提示用户确认未知和变更的密钥
    Ask,
    /// 接受新主机：自动添加未知主机，但拒绝密钥变更
    AcceptNew,
    /// 不检查：接受所有主机（不安全，仅测试用）
    No,
}
```

#### 子任务

1. **实现检查策略**
   - [ ] Strict 模式实现
   - [ ] Ask 模式实现（回调接口）
   - [ ] AcceptNew 模式实现
   - [ ] No 模式实现

2. **用户交互接口**
   - [ ] 定义 UserPromptCallback trait
   - [ ] 实现默认回调（标准输入）
   - [ ] 支持自定义回调

3. **集成到 SshClient**
   - [ ] 在 connect() 流程中添加主机密钥验证
   - [ ] 在 SshClientConfig 中添加策略配置
   - [ ] 添加 known_hosts 文件路径配置

4. **测试**
   - [ ] test_strict_mode_rejects_unknown
   - [ ] test_accept_new_mode_adds_host
   - [ ] test_ask_mode_callback
   - [ ] test_no_mode_accepts_all

---

### Task 4: 主机密钥管理

**优先级**: 🟡 中
**预计时间**: 1 天

#### 子任务

1. **添加新主机密钥**
   - [ ] 实现 add_host_key() 方法
   - [ ] 格式化为 known_hosts 行
   - [ ] 追加到文件末尾
   - [ ] 文件权限处理（0600）

2. **更新变更的密钥**
   - [ ] 实现 update_host_key() 方法
   - [ ] 删除旧记录
   - [ ] 添加新记录
   - [ ] 原子性写入（临时文件 + rename）

3. **删除主机密钥**
   - [ ] 实现 remove_host_key() 方法
   - [ ] 过滤匹配的记录
   - [ ] 重写文件

4. **主机名哈希化**
   - [ ] 实现 hash_hostname() 函数
   - [ ] HMAC-SHA1 哈希算法
   - [ ] Base64 编码
   - [ ] |1|salt|hash 格式

5. **测试**
   - [ ] test_add_host_key
   - [ ] test_update_host_key
   - [ ] test_remove_host_key
   - [ ] test_hash_hostname

---

### Task 5: 集成与文档

**优先级**: 🟢 低
**预计时间**: 0.5 天

#### 子任务

1. **集成到 SshClient**
   - [ ] 修改 connect() 方法
   - [ ] 在密钥交换后验证主机密钥
   - [ ] 根据策略处理验证结果

2. **配置选项**
   - [ ] SshClientConfig::strict_host_key_checking
   - [ ] SshClientConfig::known_hosts_file
   - [ ] SshClientConfig::hash_known_hosts

3. **rustdoc 文档**
   - [ ] KnownHostsFile 文档
   - [ ] StrictHostKeyChecking 文档
   - [ ] 示例代码

4. **更新 README**
   - [ ] 添加 known_hosts 使用示例
   - [ ] 安全最佳实践

---

## 🔧 技术细节

### known_hosts 文件结构

#### 标准格式
```
<hostnames> <keytype> <base64-key> [comment]
```

#### 哈希格式
```
|1|<salt>|<hash> <keytype> <base64-key> [comment]
```

- `salt`: Base64 编码的随机盐值
- `hash`: Base64(HMAC-SHA1(salt, "host:port"))

### 主机名匹配算法

```rust
fn matches_hostname(pattern: &str, hostname: &str, port: u16) -> bool {
    // 1. 构造完整主机名
    let full_host = if port == 22 {
        hostname.to_string()
    } else {
        format!("[{}]:{}", hostname, port)
    };

    // 2. 哈希格式匹配
    if pattern.starts_with("|1|") {
        return verify_hashed_hostname(pattern, &full_host);
    }

    // 3. 通配符匹配
    if pattern.contains('*') {
        return wildcard_match(pattern, &full_host);
    }

    // 4. 标准匹配
    pattern == full_host
}
```

### 哈希验证算法

```rust
fn verify_hashed_hostname(hashed: &str, hostname: &str) -> bool {
    // |1|salt|hash
    let parts: Vec<&str> = hashed.split('|').collect();
    if parts.len() != 4 || parts[0] != "" || parts[1] != "1" {
        return false;
    }

    let salt = base64::decode(parts[2])?;
    let expected_hash = base64::decode(parts[3])?;

    // HMAC-SHA1(salt, hostname)
    let mut hmac = HmacSha1::new_from_slice(&salt)?;
    hmac.update(hostname.as_bytes());
    let computed_hash = hmac.finalize().into_bytes();

    // 常量时间比较
    constant_time_eq(&computed_hash, &expected_hash)
}
```

---

## 📦 依赖

### 新增 Cargo 依赖

```toml
[dependencies]
# 用于 HMAC-SHA1（哈希主机名验证）
hmac = "0.12"
sha1 = "0.10"

# 用于通配符匹配
glob = "0.3"  # 或者自己实现简单的通配符匹配
```

### 已有依赖

```toml
base64 = "0.22"  # Base64 编码/解码
subtle = "2.5"   # 常量时间比较
```

---

## 📐 架构设计

### 文件结构

```
crates/proto/src/ssh/
├── known_hosts.rs  # 新增：known_hosts 文件支持
├── client.rs       # 修改：集成主机密钥验证
└── ...
```

### API 设计

```rust
/// known_hosts 文件
pub struct KnownHostsFile {
    entries: Vec<KnownHost>,
    path: PathBuf,
}

impl KnownHostsFile {
    /// 从文件加载
    pub fn from_file<P: AsRef<Path>>(path: P) -> FynxResult<Self>;

    /// 从字符串解析
    pub fn from_string(content: &str) -> FynxResult<Self>;

    /// 验证主机密钥
    pub fn verify_host_key(
        &self,
        hostname: &str,
        port: u16,
        key_type: &str,
        key_data: &[u8],
    ) -> HostKeyStatus;

    /// 添加主机密钥
    pub fn add_host_key(
        &mut self,
        hostname: &str,
        port: u16,
        key_type: &str,
        key_data: &[u8],
        hash: bool,
    ) -> FynxResult<()>;

    /// 更新主机密钥
    pub fn update_host_key(
        &mut self,
        hostname: &str,
        port: u16,
        key_type: &str,
        key_data: &[u8],
    ) -> FynxResult<()>;

    /// 保存到文件
    pub fn save(&self) -> FynxResult<()>;
}

/// 单个 known_hosts 条目
pub struct KnownHost {
    /// 主机名模式（标准、哈希、通配符）
    hostname_pattern: String,
    /// 密钥类型
    key_type: String,
    /// 公钥数据
    key_data: Vec<u8>,
}

/// 主机密钥验证状态
pub enum HostKeyStatus {
    /// 已知且匹配
    Known,
    /// 已知但密钥变更
    Changed {
        old_key_type: String,
        old_key_data: Vec<u8>,
    },
    /// 未知主机
    Unknown,
}

/// 严格主机密钥检查策略
pub enum StrictHostKeyChecking {
    Strict,
    Ask,
    AcceptNew,
    No,
}

/// 用户提示回调
pub trait UserPromptCallback {
    /// 询问用户是否接受未知主机密钥
    fn prompt_unknown_host(
        &self,
        hostname: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> FynxResult<bool>;

    /// 警告主机密钥变更
    fn warn_key_changed(
        &self,
        hostname: &str,
        port: u16,
        old_fingerprint: &str,
        new_fingerprint: &str,
    ) -> FynxResult<bool>;
}
```

---

## 🧪 测试计划

### 单元测试（10+）

1. **文件解析测试**
   - test_parse_standard_format
   - test_parse_hashed_format
   - test_parse_with_port
   - test_parse_wildcard
   - test_parse_multi_host
   - test_parse_comment_lines

2. **主机匹配测试**
   - test_match_standard_hostname
   - test_match_hashed_hostname
   - test_match_wildcard
   - test_match_with_port
   - test_no_match

3. **密钥验证测试**
   - test_verify_known_host
   - test_detect_key_change
   - test_detect_unknown_host

4. **密钥管理测试**
   - test_add_host_key
   - test_update_host_key
   - test_hash_hostname

### 集成测试（2+）

1. **test_client_with_known_hosts**
   - 客户端连接已知主机
   - 验证主机密钥
   - 连接成功

2. **test_client_reject_unknown_host**
   - 严格模式拒绝未知主机
   - 连接失败

---

## 📊 进度跟踪

**总进度**: 0% (未开始)

### 计划时间分配

- **Day 1**: Task 1 - 文件格式解析
- **Day 2**: Task 2 - 主机密钥验证逻辑（上半部分）
- **Day 3**: Task 2 - 主机密钥验证逻辑（下半部分）+ Task 3 - 检查策略
- **Day 4**: Task 4 - 主机密钥管理 + Task 5 - 集成与文档

---

## ✅ 完成标准

- [ ] 核心功能实现完成（解析、验证、管理）
- [ ] 所有单元测试通过（10+ tests）
- [ ] 集成测试通过（2+ tests）
- [ ] cargo build 成功（无警告）
- [ ] cargo clippy 通过（无警告）
- [ ] 100% rustdoc 文档覆盖
- [ ] 错误处理完善
- [ ] 代码审查通过

---

## 🔗 参考文档

- **OpenSSH Manual**: sshd(8), ssh_config(5) - known_hosts format
- **RFC 4251**: SSH Protocol Architecture
- **OpenSSH Source**: `hostfile.c`, `hostfile.h` - known_hosts implementation

---

**文档版本**: 1.0
**创建日期**: 2025-10-19
**最后更新**: 2025-10-19
**负责人**: Fynx Core Team
**阶段状态**: 📋 计划中
