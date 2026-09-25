# vault-tool — 本地文件加密与恢复

把明确选择的文件和目录加密为 `vault.enc`，需要时在本机输入密码查看、搜索、导出或维护。它是离线文件工具，不是在线保险库、密码找回服务，也不替代 Password Center（密码中心）。

本机维护目录是 `E:\Projects\Tools\vault-tool`，当前版本 `2.3.1`。公开工具仓库与私人密文仓库 `wlyaaaaa/Key` 分开；密码、密钥文件和解密正文不得进入公开仓库。

## 快速开始

```powershell
python vault_tool.py
```

密码只在本地提示中输入，不放进聊天、命令行参数、环境变量、脚本、日志或 Git。密钥文件按其完整字节参与派生；密码或必要密钥文件遗失，没有找回机制。

| 目标 | 入口 | 当前行为 |
|---|---|---|
| 新建库 | `encrypt` | 加密 `source/`，默认保留原件；`--cleanup-source` 只清理本次已归档且仍完全一致的文件。 |
| 给已有库追加 | 菜单“加密／添加文件” | 在内存中合并当前密码对应层；未解锁槽位保持密文字节不变，原件保留。 |
| 改密码 | `passwd` | 只重加密当前解锁的 VAULT03 槽位，保留另一槽与原 KDF。 |
| 改密钥文件／扩容 | `rebuild --out <new.enc>` | 创建经过读回验证的新副本，原库不替换；可显式输入第二个已知密码以保留两层。 |
| 旧格式升级 | `migrate` | 独立事务升级；VAULT02 保留原 scrypt 参数，VAULT01 明确改用当前 scrypt。 |
| 不落盘看文本 | `decrypt --no-disk` | 明文仅用于本地终端显示；stdout 仍属于明文边界，不应由 AI 捕获。 |
| 导出 | `decrypt` / `decrypt --extract` | 写入明确 `decrypted/`；冲突不覆盖；部分导出返回 `ok=false, result=partial` 和分类计数，回执保留实际写入事实。 |
| 结构/计划 | `info` / `doctor` / `assess` / `plan` | 元数据只读；支持 `--vault-file` 精确目标，不回退到默认库。 |
| 操作预演 | `plan --operation ...` | 返回目标、资源预算、是否会写明文、是否需凭据等元数据，不执行动作。 |
| 凭据计划 | `credential-plan` | 区分原槽改密、共享密钥文件变化、迁移和重建。 |
| 恢复环境自测 | `recovery-check --self-test` | 只用虚构密码与内存载荷验证当前运行时，不解密真实库。 |
| 双密码容器 | `decoy` | 诱饵层与真实层分别验证；容量不足拒绝，原库保留。 |
| 图片携带密文 | `hide` / `unhide` | 只在图片尾部追加/恢复密文，不增加新加密层。 |
| 清理残留明文 | `clean-plaintext --confirm` | 独立显式动作；诊断命令不再隐式触发。 |

## 文件入库与原件保全

当前默认是“先可靠生成并验证密文，再决定是否清理输入”，而不是把删除明文当成加密成功的一部分。

1. `encrypt` 对 `source/` 建立稳定快照，检查原始路径、链接/重解析点、对象身份、大小与修改时间，并确认读取期间文件没有变化。路径上只放行 PCConfig 在 `C:\ProgramData\PCConfig\PersonalVault\vault-links.json` 登记、实际为挂载点/联接且目标一致的加密盘根；登记表缺失或无效、未登记、目标不符或符号链接一律拒绝，可信根以下仍逐级检查。
2. 打包后先在内存中验证候选密文，再写同目录临时密文、刷新到磁盘、读回并重新验证，最后提交目标。
3. 覆盖已有 `vault.enc` 时，旧密文先保存为不会覆盖已有备份的独立恢复副本。
4. 默认保留 `source/`。只有显式 `--cleanup-source` 才逐文件清理；Windows 清理在同一个独占句柄中比较对象身份与 SHA-256，并由同一句柄完成逻辑删除；新增、变化、正在被使用、硬链接或无法确认的对象全部保留。不具备这一独占删除实现的平台会保留原件，不退回存在竞态的覆写删除。
5. 追加文件时，旧库当前层只在内存中展开并与新输入合并，不把旧内容先落到 `source/`。
6. 新建库会为 gzip 载荷预留有界编辑空间，降低小幅编辑立即撞到固定槽容量的概率；已有库槽位不会静默扩大。

需要扩大容量、改变共享密钥文件标志，或重建两密码容器时使用 `rebuild --out`。新副本成功前，原库始终保留。

## 查看、导出与明文去向

```powershell
python vault_tool.py decrypt --no-disk
python vault_tool.py decrypt
python vault_tool.py decrypt --extract
```

- CLI 支持小型可读文本直接显示；图片、PDF、二进制和大文件应明确导出后用对应程序打开。
- `:copy` 的剪贴板清理依赖当前进程存活，不是系统级保证。
- GUI 查看/编辑把正文限制在本地进程/窗口，不把正文、密钥文件路径或密码返回模型。
- 导出采用逐文件临时写入、校验、无覆盖提交。已存在且内容相同的文件计入 `already_count`；不同内容或并发新建的同名目标计入 `conflict_count`。存在冲突或不支持成员时返回部分完成，不冒称全部成功。
- 如果导出在某文件中途失败，回执仍会如实标记是否已经向磁盘写过明文字节；不能再用“完整文件计数为 0”冒充“没有落盘”。
- 本次交互导出结束可清理本次输出；旧残留使用独立的 `clean-plaintext --confirm`。诊断和普通启动不顺带清除旧目录，文本/JSON 输出不改变这一点。
- SSD 上覆盖删除不能保证物理介质所有历史块消失；“安全删除”只描述当前文件系统对象处理，不作绝对介质承诺。

## 格式、KDF 与资源预算

VAULT03 使用 tar+gzip、AES-256-GCM，以及 scrypt 或可选 Argon2id。密码可以混入密钥文件 SHA-256 摘要作为第二因子。

- 默认 scrypt 参数为 `N=2^17, r=8, p=1`；交互新建可校准到约 0.6 秒。
- Argon2id 需要 `argon2-cffi`。Windows 的 AES/scrypt 使用系统 CNG 和 Python 标准库；Linux/macOS AES 需要 `cryptography`。
- 在真正运行 KDF 前，容器参数同时检查正值、参数关系、内存和普通工作量预算。合法但异常昂贵的旧库只能在明确 `--allow-expensive-kdf` 恢复选择下尝试，硬内存上限不放宽。
- 归档成员数、声明解压总量和本地文本大小有独立预算。能识别容器格式不等于任意体积都应整体进内存。
- VAULT02 是 scrypt + AES-GCM；VAULT01 是 PBKDF2-SHA256 + AES-CBC，兼容读取不等于认证强度相同。
- 结构检查通过只证明字节布局/参数可接受，不证明密码正确、内容真实或整套恢复已经验收。

## 改密、迁移、双槽与重建

`passwd` 对 VAULT03 只更新当前密码打开的槽位；未解锁槽位保持原密文字节不变。共享密钥文件标志不能在不知道另一槽凭据的情况下安全地原地修改，因此会引导到 `rebuild`。

```powershell
python vault_tool.py credential-plan --vault-file <vault.enc> --change keyfile --json
python vault_tool.py rebuild --out <new.enc>
```

`rebuild` 可只复制当前已验证层，同时保留原库；如果本人同时提供另一个已知密码，则要求它打开不同槽位，再把两层都验证后写入新副本。它不猜测隐藏层是否存在。

`migrate`、`decoy`、`passwd` 和本地编辑均使用统一密文事务：候选验证、临时密文、读回、并发目标检查、提交、最终验证与必要回滚。`migrate` / `decoy` 会保留不会覆盖旧文件的密文恢复副本；`decoy_source/` 默认保留。

双密码只证明软件中的两份内容/密码行为。它不是现实胁迫环境、旧备份、快照或第三方观察下“不可证明存在”的绝对承诺。

## AI-safe 元数据与精确目标

```powershell
python vault_tool.py info --vault-file <vault.enc> --json
python vault_tool.py doctor --vault-file <vault.enc> --json
python vault_tool.py assess --vault-file <vault.enc> --json
python vault_tool.py plan --vault-file <vault.enc> --json
python vault_tool.py plan --operation decrypt-export --vault-file <vault.enc> --output-path <dir> --json
python vault_tool.py credential-plan --vault-file <vault.enc> --change password --json
python vault_tool.py recovery-check --vault-file <vault.enc> --self-test --json
```

这些路径不收真实密码、不解密真实库、不列出 `source/` / `decrypted/` 私人文件名，也不执行建议。显式 `--vault-file` 只评估该目标；损坏或不存在的目标不会静默改评默认 `vault.enc`。

已安装的 `vault-workflow` Skill 提供本地 UI 与脱敏 JSON wrapper：
- `PromptOnly` 只收集并丢弃输入，不打开库。
- `LocalView` / `LocalEdit` 要求明确 `-VaultFile`。
- `Encrypt` 保留输入；`DecryptExport` 只写明确输出目录；`ChangePassword` 保留未解锁槽位。
- CLI、GUI 和 Skill 的改密/导出/编辑共用 `vault_tool.py` 的归档、槽位和事务原语，避免不同入口安全行为漂移。
- `VerifyPassword` 是一次性本地检查，不建立可复用授权会话。

## 私人 Key 仓库

见 [Key 仓库工作流](docs/key-repository-workflow.md)。

`Publish-KeyVaultToGitHub.ps1` 只向现场确认 PRIVATE 的目标发布明确密文；`-WhatIf` 在真正创建本地请求临时文件之前返回预演结果。真实写入后从默认分支读回 Git blob，并比较远端字节数与 SHA-256；只有上传和字节回读都成立才报告 `upload_performed=true`、`readback_verified=true`。

`ProtectRemoteReadme` 与普通发布分开：
- `WhatIf` 只读仓库/分支/树路径元数据，不读 README 正文。
- 只有 README 字节完整等于受管安全占位文本，才认定“已经保护”；仅包含 marker 不算。此路径返回 `existing_stub_verified`，不声称验证过既有密文或密码。
- 如果 `vault/vault.enc` 已存在而 README 仍是普通正文，拒绝覆盖既有密文。
- 真正变更前重新核对仓库私有性和固定提交的完整树，截断的树不能证明文件不存在。变更后回读分支头、README 和密文，并核对 SHA-256；若更新响应丢失则只回读、不盲目重复写，仍不能确定时 effect 为 `null`，而不是误报“没有修改”。Base64 正常换行和较大文件的固定 blob 回读均受支持。
- 不重写旧 Git 历史。

## 验证边界

```powershell
python -m pytest test_vault_tool.py test_readonly_diagnostics.py test_recovery_regressions.py test_final_audit.py test_vault_links.py -q -p no:cacheprovider
pwsh -NoProfile -File scripts/Test-Publish-KeyVaultToGitHub.ps1
```

2026-09-18 的正式核心回归使用虚构文件、虚构密码和隔离临时目录：**137 项测试、30 项子用例通过**。新增覆盖包括双槽改密/合并保全、默认原件保留与精确快照清理、事务写回/回滚、并发目标、导出回执、KDF 工作预算、精确目标计划、凭据计划、恢复环境虚构自测、非覆盖备份和双层新副本重建。

`vault-workflow` 另有本地操作、GUI/事务、wrapper 与远端保护虚构测试；`authorization-file-broker` 另有批量往返、续作、PCAF UI、并发冲突和原审计缺陷回归。最终验收分别看来源测试、Skill smoke、PCConfig 验证器和 Git 默认分支回读，不能互相替代。

本轮没有读取或修改真实保险库密码、密钥文件或解密正文，也没有为了测试而改真实私人 Key README/密文。强杀、断电和全新机器上的真人凭据恢复属于物理/人工环境验收，不由虚构回归冒充。

## 2.3.1 最终复核

本次复核补齐了 2.3.0 尚未覆盖的实际缺口：受保护 PCAF 安装同步、GitHub 正常换行解码、固定源树与丢失响应处理、编辑器归档/文本资源预算、部分导出的真实回执，以及清理原件的独占句柄保护。新库的编辑余量现在同时用于 CLI、Skill 新建和重建；编辑窗口显示当前槽容量。

验收分别记录源码回归、已安装 Skill、PCAF 固定解释器与安装文件/清单一致性、远端只读预演和默认分支发布回读。测试计数按不同用例去重，不把聚合 runner 再次运行的用例重复相加。真实密码、私人解密正文、物理断电和新机器恢复没有被冒称为本轮已实测；工程验收也不声称密码学或软件绝对无缺陷。
