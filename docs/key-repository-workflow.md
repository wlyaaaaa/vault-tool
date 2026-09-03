# Key 仓库加密备份流程

`vault-tool` 是公开工具仓库；`wlyaaaaa/Key` 是私有密文仓库。两者不要混在一起。

## 推荐流程

1. 明确本次文件范围，以及是新建、追加还是整库替换。引导式追加使用 `python vault_tool.py` 的菜单；下面的启动脚本只处理当前 `source/`，不会自动合并旧库。
2. 把需要备份的文件复制进 `E:\Projects\Tools\vault-tool\source\`，或用脚本参数复制。原路径副本与会被成功清理的暂存原文不同；不要把唯一原件的去向含糊带过。
3. 对已经准备好的明确整库内容，在本地可见终端运行：

   ```powershell
   E:\Projects\Tools\vault-tool\scripts\Start-KeyVaultEncrypt.ps1
   ```

4. 只在本地终端密码提示里输入保险库密码。不要把密码发到聊天、命令行参数、环境变量、脚本、日志或 Git；如果建库时选择了密钥文件，恢复也需要同一份字节。
5. 生成 `E:\Projects\Tools\vault-tool\vault.enc` 后，对这一份明确内容做本地恢复核对。双密码库必须区别本次打开的层与整份容器；一个密码打开成功不证明另一层仍在。
6. 确认可恢复后，先预演上传到已经确认的私人目标：

   ```powershell
   E:\Projects\Tools\vault-tool\scripts\Publish-KeyVaultToGitHub.ps1 -WhatIf
   ```

7. 明确执行时去掉 `-WhatIf`。脚本不会克隆 `wlyaaaaa/Key`，拒绝非私有目标；只把真实 404 当成新文件，其他前置错误和 PUT 失败都停止。
8. 发布后脚本从默认分支读取实际目标的 Git blob（文件内容对象），比较远端字节长度及 SHA-256。只有实际上传与字节回读都成立才报告成功。

成功 JSON 中的 `upload_performed`、`readback_verified` 均为 `true`，并提供 `repo/path/branch/commit_sha/blob_sha/bytes/sha256`。预演时两字段为 `false`。真实写入后回读失败，远端可能已经变化：先核对现状，不要盲目重复上传。

扩展名只表示允许处理的输入类别，不能证明文件确已加密。远端字节一致也只证明保存了同一份密文；它不验证密码、密钥文件或恢复机器环境，不能替代第 5 步。

## 更强模式

- 双因子：给 `Start-KeyVaultEncrypt.ps1` 传 `-KeyFile <离线文件>`。
- 明确选择另一 KDF（密码派生函数）：传 `-Kdf argon2`，加密和恢复机器都必须有 `argon2-cffi`。缺依赖时失败，不静默改成 scrypt。
- 隐写：先用 `vault_tool.py hide` 把 `vault.enc` 藏进图片，再用 `Publish-KeyVaultToGitHub.ps1 -AllowStegoFile -VaultFile <图片路径>` 上传。

## 密码纪律

如果保险库密码曾经出现在聊天、截图、日志、shell history 或任何可同步位置，应视为临时密码。正式长期保险库建议重新加密并换成只在本地终端输入的新密码。

`vault-tool` 可以协助 AI 做目录准备、测试、密文上传和文档维护；AI 不需要知道最终密码。

## 与其他入口分开

已安装 Skill 的 `VerifyRemote` 只核对目标与树路径，`safe_readme_present` 只表示 README 路径存在，不是密文字节回读。`LocalView/LocalEdit` 是本人明确操作指定库的本地界面，不是普通备份必经步骤。

`ProtectRemoteReadme` 是另一项需要明确请求的动作：在本地辅助进程读取固定提交的 README、两次本地密码确认、自检后，在同一非强制提交中写密文和替代说明。它不合并已有库，不重写旧历史；`WhatIf` 不读取正文。不得因为只是要上传一份密文，就顺带执行这项正文变更。
