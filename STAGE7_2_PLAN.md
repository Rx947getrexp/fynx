# Stage 7.2: 公钥认证实现

**阶段**: Stage 7 - 公钥认证与密钥管理
**子阶段**: 7.2 - 公钥认证实现（Week 3-4）
**开始日期**: 2025-10-18
**预计完成**: 2025-10-25
**状态**: 🚧 进行中

---

## 🎯 目标

实现完整的SSH公钥认证协议（RFC 4252），支持客户端和服务器端的公钥认证流程。

### 成功标准

- [ ] 客户端公钥认证（SSH_MSG_USERAUTH_REQUEST publickey）
- [ ] 服务器端公钥验证
- [ ] 签名生成（RSA, Ed25519, ECDSA）
- [ ] 签名验证（RSA, Ed25519, ECDSA）
- [ ] try-then-sign 流程（先查询，再签名）
- [ ] authorized_keys 文件解析
- [ ] 公钥指纹计算（MD5, SHA256）
- [ ] 8+ 集成测试全部通过
- [ ] OpenSSH 互操作测试通过
- [ ] 完整的 rustdoc 文档

---

## 📋 详细任务

### Task 1: 公钥认证协议消息

**优先级**: 🔴 高
**预计时间**: 1 天

#### 消息类型扩展

在 `message.rs` 中添加公钥认证消息：

```rust
// SSH_MSG_USERAUTH_REQUEST with publickey method
pub struct UserAuthPKRequest {
    pub username: String,
    pub service: String,
    pub method: String,  // "publickey"
    pub has_signature: bool,
    pub algorithm: String,  // "ssh-ed25519", "ssh-rsa", etc.
    pub public_key: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

// Signature blob structure
pub struct PublicKeySignature {
    pub algorithm: String,
    pub signature: Vec<u8>,
}
```

#### 子任务

1. **消息序列化**
   - [ ] UserAuthPKRequest 编码
   - [ ] UserAuthPKRequest 解码
   - [ ] 签名数据构造（session_id + message）
   - [ ] 签名 blob 编码/解码

2. **测试**
   - [ ] test_userauth_pk_request_encode
   - [ ] test_userauth_pk_request_decode
   - [ ] test_signature_blob_format
   - [ ] test_signature_data_construction

---

### Task 2: 客户端公钥认证

**优先级**: 🔴 高
**预计时间**: 2 天

#### 认证流程

```
Client                          Server
------                          ------
1. SSH_MSG_USERAUTH_REQUEST
   (has_signature=false)    -->
                            <-- 2. SSH_MSG_USERAUTH_PK_OK
                                   (if key is acceptable)
3. SSH_MSG_USERAUTH_REQUEST
   (has_signature=true)     -->
                            <-- 4. SSH_MSG_USERAUTH_SUCCESS
                                   or SSH_MSG_USERAUTH_FAILURE
```

#### 子任务

1. **客户端 API**
   - [ ] `authenticate_with_key(username, private_key)` 函数
   - [ ] try-then-sign 逻辑（两次请求）
   - [ ] 签名数据构造
   - [ ] 使用 PrivateKey::sign() 生成签名

2. **签名生成**
   - [ ] Ed25519 签名生成
   - [ ] RSA-SHA2-256 签名生成（如果支持RSA）
   - [ ] ECDSA 签名生成（如果支持ECDSA）

3. **集成到 SshClient**
   - [ ] 修改 `authenticate()` 方法支持公钥
   - [ ] 自动加载默认私钥（~/.ssh/id_ed25519 等）
   - [ ] 密码回调支持（加密私钥）

4. **测试**
   - [ ] test_client_pk_auth_ed25519
   - [ ] test_client_pk_auth_try_then_sign
   - [ ] test_client_pk_auth_wrong_key
   - [ ] test_client_pk_auth_encrypted_key

---

### Task 3: 服务器端公钥认证

**优先级**: 🔴 高
**预计时间**: 2 天

#### 子任务

1. **authorized_keys 解析**
   - [ ] 创建 `authorized_keys.rs` 模块
   - [ ] 解析标准格式：`algorithm base64-key comment`
   - [ ] 支持选项：`no-port-forwarding`, `command=` 等
   - [ ] 公钥匹配逻辑

2. **AuthorizedKeys 结构**
   ```rust
   pub struct AuthorizedKey {
       pub options: Vec<String>,
       pub algorithm: String,
       pub key_data: Vec<u8>,
       pub comment: String,
   }
   
   pub struct AuthorizedKeysFile {
       pub keys: Vec<AuthorizedKey>,
   }
   ```

3. **签名验证**
   - [ ] 使用 HostKey trait 验证签名
   - [ ] Ed25519 签名验证
   - [ ] RSA-SHA2-256 签名验证
   - [ ] ECDSA 签名验证

4. **服务器认证处理**
   - [ ] 在 `SshServer` 中处理 SSH_MSG_USERAUTH_REQUEST (publickey)
   - [ ] try 阶段：返回 SSH_MSG_USERAUTH_PK_OK
   - [ ] sign 阶段：验证签名
   - [ ] 加载用户的 authorized_keys 文件

5. **测试**
   - [ ] test_authorized_keys_parse
   - [ ] test_authorized_keys_with_options
   - [ ] test_server_pk_auth_verify
   - [ ] test_server_pk_auth_reject_invalid

---

### Task 4: 公钥指纹

**优先级**: 🟡 中
**预计时间**: 1 天

#### 子任务

1. **指纹计算**
   - [ ] MD5 格式：`MD5:xx:xx:...:xx` (legacy)
   - [ ] SHA256 格式：`SHA256:base64` (modern)
   - [ ] 公钥格式化（SSH wire format）

2. **Fingerprint 结构**
   ```rust
   pub struct Fingerprint {
       algorithm: String,
       hash: Vec<u8>,
   }
   
   impl Fingerprint {
       pub fn md5(public_key: &[u8]) -> Self;
       pub fn sha256(public_key: &[u8]) -> Self;
       pub fn display(&self) -> String;
   }
   ```

3. **测试**
   - [ ] test_fingerprint_md5
   - [ ] test_fingerprint_sha256
   - [ ] test_fingerprint_display_format

---

### Task 5: 集成测试

**优先级**: 🟢 低
**预计时间**: 1 天

#### 子任务

1. **端到端测试**
   - [ ] test_client_server_pk_auth_ed25519
   - [ ] test_client_server_pk_auth_multiple_keys
   - [ ] test_authorized_keys_integration
   - [ ] test_pk_auth_fallback_to_password

2. **OpenSSH 互操作**
   - [ ] 连接到真实 OpenSSH 服务器
   - [ ] 使用真实私钥认证
   - [ ] 验证与 ssh-keygen 的兼容性

---

## 🔧 技术细节

### 签名数据格式（RFC 4252 Section 7）

```
string    session identifier
byte      SSH_MSG_USERAUTH_REQUEST
string    user name
string    service name
string    "publickey"
boolean   TRUE (has signature)
string    public key algorithm name
string    public key to be used for authentication
```

### authorized_keys 格式

```
# 标准格式
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host

# 带选项
no-port-forwarding,command="/usr/bin/ls" ssh-ed25519 AAAAC3... user@host

# 注释
# This is a comment
```

### 公钥 wire 格式（用于指纹计算）

```
string    algorithm name
string    algorithm-specific public key data
```

---

## 📦 依赖

- **已完成**: Stage 7.1 (私钥加载) ✅
- **需要**: 
  - auth 模块现有框架
  - hostkey 模块（签名验证）
  - privatekey 模块（签名生成）

### Cargo 依赖

已有足够依赖，无需添加新的。可能需要：
```toml
# 用于指纹计算
md-5 = "0.10"  # 已有
sha2 = "0.10"  # 已有
base64 = "0.22"  # 已有
```

---

## 📊 进度跟踪

**总进度**: 0% (0/8+ 测试通过)

### 每日目标

- **Day 1**: 消息类型定义和序列化
- **Day 2**: 客户端公钥认证实现
- **Day 3**: authorized_keys 解析
- **Day 4**: 服务器端签名验证
- **Day 5**: 公钥指纹和集成测试
- **Day 6-7**: OpenSSH 互操作测试和文档

---

**文档版本**: 1.0
**创建日期**: 2025-10-18
**最后更新**: 2025-10-18
**负责人**: Fynx Core Team
