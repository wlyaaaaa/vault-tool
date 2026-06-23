# Vault v1.1.0 — 本地加密保险库

纯 Python 离线加密工具。Windows 下**零第三方依赖**（仅标准库 + 内置 `bcrypt.dll`）；Linux / macOS 需 `pip install cryptography`。

- 密钥派生：**scrypt**（内存硬，抗 GPU/ASIC 暴力破解）
- 对称加密：**AES-256-GCM**（带认证标签，可检测篡改）
- 抗量子：AES-256 对量子 Grover 算法仍有等效 128 位强度，足够安全
- 支持任意文件类型、含子目录；仍兼容解密旧版 `VAULT01`

---

## ⚠️ 安全的真正天花板：密码本身

再强的算法也救不了弱密码。攻击者不会硬碰 AES-256，而是**猜密码**逐个验证。

- 量子计算机：威胁的是 RSA/椭圆曲线等**非对称**加密；本工具用对称 AES，**不受影响**。
- 国家级超算：瓶颈是你密码的「熵」。10 位随机字符 ≈ 2⁶⁶，配合 scrypt 已极难，但**不是绝对无解**；若是"有意义"的密码（单词/生日/键盘连排），实际只有 30~40 位熵，很快被破。

**强烈建议**：用更长的口令——6 个以上随机单词（如 `correct-horse-battery-staple-river-stone`），或 16 位以上随机串。**长度比复杂度更管用。**

---

## 目录结构

```
项目目录/
├── vault_tool.py     # 唯一脚本，加密/解密/升级入口
├── vault.enc         # 加密后的保险库文件
├── vault.enc.v1bak   # 升级时自动生成的旧库备份（确认后可删）
├── vault.log         # 操作日志（仅记录时间戳，不含密码或内容）
├── source/           # 【加密时手动创建】放入要加密的任意文件
└── decrypted/        # 解密临时输出，阅后自动安全删除
```

---

## 使用方法

### 交互式菜单

运行：`python vault_tool.py`

- **存在 `vault.enc`** → 进入菜单：
  - `[1]` 解密查看，解密成功后可选两种查看方式（见下）
  - `[2]` 用 `source/` 里的文件重新加密（覆盖；**这是"加入更多文件"的方式**）
  - `[3]` 一键升级到最新加密（仅旧版 VAULT01 出现，明文不落盘，自动备份+自检）
  - `[4]` 修改密码
  - `[5]` 查看库信息（不需要密码）

### 两种查看方式（控制明文是否可恢复）

| 方式 | 明文是否落盘 | 强行杀进程/断电后 | 适用 |
|------|------|------|------|
| `[1]` 不落盘安全查看（默认） | **否，只在内存** | **不可恢复** ✅ | 看密码/文本笔记 |
| `[2]` 解压到 `decrypted/` | 是 | 正常退出/Ctrl+C 自动清除；**强杀可能残留** ⚠️ | 需用外部程序打开图片/PDF 等 |

- 不落盘模式下，二进制/超大文件无法在终端显示，需要时改用 `[2]`。
- 程序**启动时**若发现上次崩溃残留的 `decrypted/`，会自动安全清除。
- 残余风险：内存理论上可能被系统换页到 pagefile；如需极致安全，请在内存充足、未休眠的环境下使用不落盘模式。
- **不存在 `vault.enc` 且 `source/` 有文件** → 直接进入加密
- 加入更多文件的流程：把新文件放进 `source/` → 运行 → 选 `[2]` 重新加密

### CLI 模式

无需交互菜单，直接执行子命令：

```bash
python vault_tool.py --version          # 显示版本号
python vault_tool.py encrypt            # 加密 source/ 目录
python vault_tool.py decrypt            # 解密到 decrypted/
python vault_tool.py decrypt --no-disk  # 不落盘安全查看
python vault_tool.py info               # 查看库信息（不需要密码）
python vault_tool.py passwd             # 修改密码
python vault_tool.py migrate            # 升级旧版 VAULT01 → VAULT02
```

---

## 跨平台说明

| 平台 | 依赖 |
|------|------|
| Windows | **零依赖**——标准库 + 系统内置 `bcrypt.dll` |
| Linux / macOS | 需安装 `pip install cryptography` |

---

## 操作日志

`vault.log` 记录每次操作的时间戳（**不含密码或明文内容**），用于审计和排错。该文件已加入 `.gitignore`，不会被提交。

---

## 加密参数（VAULT02）

| 参数 | 值 |
|------|-----|
| 密钥派生 | scrypt（N=2¹⁷, r=8, p=1，约 128 MB 内存/次） |
| 对称加密 | AES-256-GCM |
| Salt | 32 字节随机 |
| Nonce | 12 字节随机 |
| 认证 | 16 字节 GCM tag，并将文件头作为 AAD 一并认证 |
| 容器 | tar 打包（保留子目录结构）后整体加密 |

---

## 注意事项

- **密码丢失 = 数据永久丢失**，无任何找回机制。
- `vault.enc` 可安全备份到任何地方（无密码无法解密）。
- Windows 使用内置 `bcrypt.dll`；Linux/macOS 需 `pip install cryptography`。
- **SSD 安全删除的局限**：脚本对原文做一遍随机覆写后删除，但 SSD 因磨损均衡/TRIM，覆写**不保证**抹掉原始数据。最可靠的是"明文尽量不落盘、看完即焚"。

---

## 文件格式（vault.enc 内部结构）

**VAULT02（当前）**
```
[7 bytes]   魔数 "VAULT02"
[1 byte]    KDF id (1 = scrypt)
[12 bytes]  N, r, p（各 big-endian uint32）
[2 bytes]   salt 长度 (uint16) + salt
[2 bytes]   nonce 长度 (uint16) + nonce
[16 bytes]  GCM 认证标签 (tag)
[8 bytes]   密文长度 (big-endian uint64)
[M bytes]   AES-256-GCM 密文（内含 tar 包）
```
注：从魔数到 nonce 的整个头部作为 GCM 的 AAD 一并认证，篡改头部也会被发现。

**VAULT01（旧版，仅兼容解密）**：PBKDF2-SHA256(60万次) + AES-256-CBC + PKCS#7。
