# Key 仓库加密备份流程

`vault-tool` 是公开工具仓库；`wlyaaaaa/Key` 是私有密文仓库。两者不要混在一起。

## 推荐流程

1. 把需要备份的明文放进 `E:\Projects\Tools\vault-tool\source\`，或用脚本参数复制进去。
2. 在本地可见终端运行：

   ```powershell
   E:\Projects\Tools\vault-tool\scripts\Start-KeyVaultEncrypt.ps1
   ```

3. 只在本地终端密码提示里输入保险库密码。不要把密码发到聊天、命令行参数、脚本、日志或 Git。
4. 生成 `E:\Projects\Tools\vault-tool\vault.enc` 后，先本地解密演练一次。
5. 确认可恢复后，用 GitHub API 上传密文到私有 `Key` 仓库：

   ```powershell
   E:\Projects\Tools\vault-tool\scripts\Publish-KeyVaultToGitHub.ps1
   ```

这个发布脚本不会克隆 `wlyaaaaa/Key`，并且会拒绝上传到非私有仓库。

## 更强模式

- 双因子：给 `Start-KeyVaultEncrypt.ps1` 传 `-KeyFile <离线文件>`。
- 更强 KDF：传 `-Kdf argon2`，但恢复机器必须安装 `argon2-cffi`。
- 隐写：先用 `vault_tool.py hide` 把 `vault.enc` 藏进图片，再用 `Publish-KeyVaultToGitHub.ps1 -AllowStegoFile -VaultFile <图片路径>` 上传。

## 密码纪律

如果保险库密码曾经出现在聊天、截图、日志、shell history 或任何可同步位置，应视为临时密码。正式长期保险库建议重新加密并换成只在本地终端输入的新密码。

`vault-tool` 可以协助 AI 做目录准备、测试、密文上传和文档维护；AI 不需要知道最终密码。
