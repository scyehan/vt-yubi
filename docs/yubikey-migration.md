# VT YubiKey Migration Plan

## Background

VT 当前依赖 macOS Keychain 存储密钥 + Touch ID 验证身份，限制了只能在有指纹的 Mac 上使用。改用 YubiKey (5Ci / 5C Nano) 作为后端可以：

- 在无 Touch ID 的 Mac Mini 上使用
- 支持 Linux
- 后续可扩展到 Windows

## 当前 macOS 依赖清单

### Keychain 存储（3 个 item）

| Key | 内容 | 用途 |
|-----|------|------|
| `rusty.vault.passcode` | 64B: passcode(32B) + auth_token(32B) | 密钥派生、HTTP auth |
| `rusty.vault.passphrase` | 加密后的 32B AES-256 密钥 | 实际加解密用的 passphrase |
| `rusty.vault.ssh_keys` | 加密的 JSON blob | 所有 SSH 私钥 |

### Touch ID 调用点（6 处）

| 位置 | 场景 |
|------|------|
| `serve.rs:200` | HTTP `/decrypt` 端点 |
| `ssh_agent.rs:440-466` | SSH agent sign / decrypt@vt |
| `ssh_agent.rs:713` | auth@vt 扩展（始终提示） |
| `ssh_cli.rs` | ssh add/remove/remove-all/comment/show |
| `cli.rs:695,771` | secret export / rotate-passcode |

### 其他平台绑定

| 模块 | macOS API | 跨平台替代 |
|------|-----------|-----------|
| SSH agent socket | `UnixListener` | Windows: named pipe |
| `inject` 命令 | `libc::fork()` | Windows: `CreateProcess` |
| 进程自省 | `proc_pidinfo` / `proc_pidpath` | Linux: `/proc/pid/`; Windows: `OpenProcess` |
| 信号处理 | SIGINT/SIGTERM | Windows: `SetConsoleCtrlHandler` |

## YubiKey 方案设计

### 选用接口：PIV + HMAC-SHA1

**PIV（主要）** — 通过 `yubikey` crate：
- Slot 9d (Key Management) 存储 RSA/ECC 密钥
- 用 PIV 公钥加密 master passphrase，密文存本地文件
- 解密操作在 YubiKey 硬件内完成
- 同时替代 Keychain（存储）和 Touch ID（认证）

**HMAC-SHA1 challenge-response（辅助）：**
- 用于 `auth@vt` 轻量级人在场验证
- 只需物理触摸，无需 PIN

### PIV 策略配置

| 策略 | 设置 | 效果 |
|------|------|------|
| PIN Policy | `ONCE` | 仅 `vt serve` 启动时输入一次 PIN |
| Touch Policy | `ALWAYS` | 每次 sign/decrypt 需物理触摸 |

日常体验：启动输一次 PIN，之后只需触摸 YubiKey。

### 存储方案

Keychain 存储改为本地加密文件：

```
~/.vt/
├── config.toml          # YubiKey serial, slot 配置
├── passphrase.enc       # PIV 公钥加密的 master passphrase
├── ssh_keys.enc         # master passphrase 加密的 SSH keys blob
└── auth_token.enc       # PIV 公钥加密的 auth token
```

### 密钥派生链（简化）

```
当前:
  vt init → random passcode + auth_token → keychain
  passcode → double-SHA256 → passphrase_secret → decrypt passphrase from keychain

YubiKey:
  vt init → PIV key pair 生成在 YubiKey slot 9d
         → random passphrase → PIV 公钥加密 → passphrase.enc
         → random auth_token → PIV 公钥加密 → auth_token.enc
  使用时: passphrase.enc → YubiKey PIV 解密（需触摸）→ 明文 passphrase
```

YubiKey 本身就是认证因子，不再需要 passcode 中间层。

### Ed25519 限制

PIV 只支持 RSA 和 ECDSA P-256/P-384，不支持 Ed25519。

- Ed25519 SSH 密钥：仍软件签名，YubiKey 触摸做访问门控
- ECDSA P-256/P-384 密钥：可选在 YubiKey 硬件上生成（私钥永不离开设备）
- 功能上与当前 Touch ID 模型等价

## 实现步骤

### Phase 1: Trait 抽象（不破坏现有功能）

1. 定义 `trait SecretStore`：

```rust
trait SecretStore {
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}
```

2. 定义 `trait UserPresence`：

```rust
trait UserPresence {
    fn verify(&self, reason: &str) -> Result<bool>;
}
```

3. 将现有 Keychain/Touch ID 代码封装为 `KeychainStore` + `TouchIdPresence`
4. 全部调用点改为使用 trait

### Phase 2: YubiKey Backend

1. 新增依赖 `yubikey` crate
2. 实现 `YubiKeyStore`（PIV 加密/解密 + 本地文件）
3. 实现 `YubiKeyPresence`（PIV touch / HMAC challenge-response）
4. `vt init` 增加 `--backend yubikey` 选项
5. 运行时根据配置选择 backend

### Phase 3: 移除 macOS 限制

1. `#[cfg(target_os = "macos")]` 改为 feature flag
2. Linux 下使用 `pcsclite` 访问 YubiKey
3. 进程自省适配 Linux `/proc/pid/`

### Phase 4: Windows 适配（可选）

1. SSH agent 改用 named pipe
2. `inject` 命令用 `CreateProcess` 替代 `fork`
3. 进程自省用 Win32 API

## 依赖变更

```toml
# 新增
yubikey = "0.8"             # PIV 接口
yubico-manager = "0.9"      # HMAC challenge-response (可选)

# 改为 optional
security-framework = { version = "...", optional = true }
localauthentication-rs = { version = "...", optional = true }

[features]
default = ["macos-backend"]
macos-backend = ["security-framework", "localauthentication-rs"]
yubikey-backend = ["yubikey"]
```

## PC/SC 平台支持

| 平台 | 驱动 | 备注 |
|------|------|------|
| macOS | 内置 SmartCard framework | 零配置 |
| Linux | `pcsclite` | 需安装 `pcscd` 服务 |
| Windows | 内置 WinSCard | 零配置 |
