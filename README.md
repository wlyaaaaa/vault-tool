# vault-tool 本地文件加密

- **这是什么：** 把选定的文件加密成 `vault.enc`，以后在本机输入密码就能查看或取出。
- **我怎么用：** 在本目录运行 `python vault_tool.py`，按菜单选加密、查看或导出；原文件默认保留。
- **怎么知道正常：** 加密后，用原密码（和需要的密钥文件）在本机实际打开一次，核对里面的文件。
- **坏了怎么提醒我：** 没有自动提醒，出问题直接跟 AI 说。
- **让 AI 做什么：** 检查加密文件的信息和操作步骤。密码只在本机自己输入，不发给 AI。

私人 Key 仓库的密文备份和回读步骤见 [Key 仓库工作流](docs/key-repository-workflow.md)。密码或必需的密钥文件丢了，就无法找回。

实况接入单在 [docs/live.contract.json](docs/live.contract.json)。源码规模和更多数据按需更新：
`python vault_tool.py doctor --json --live-output docs/live.snapshot.json`。
如需本人份，另加 `--owner-live-output <私有位置的JSON> --vault-file <明确的密文文件>`；仅查外部元数据和旧日志动作前缀，不读容器。
本人份放本机登记的私有运行目录，不能写进公开源码目录。本机沿既有每晚自检刷新外部元数据；源文件未变时静态快照保留原取数时刻。
相关验证：`python -m unittest discover -v`；`pwsh -NoProfile -File scripts/Test-Publish-KeyVaultToGitHub.ps1`（均使用虚构数据）。
