# Codex 插件验收

日期：2026-11-20（Asia/Shanghai）。范围为本地市场上的 `si-mcp-skills` 0.1.0。环境为 Windows、Codex CLI 0.167.0-alpha.4.1、uv 0.13.9 和 Python 3.13。Codex 使用临时配置目录。

| 验收项 | 操作与实际结果 |
| --- | --- |
| 本地市场与安装 | 在仓库根目录运行 `codex plugin marketplace add .`、`codex plugin list --marketplace si-mcp-skills --available --json` 和 `codex plugin add si-mcp-skills@si-mcp-skills --json`。市场列出 0.1.0，安装缓存内的 17 个 Skill 源文件与仓库一致。 |
| Codex 发现 Skill | App Server 的 `plugin/read` 确认插件已安装、已启用，并列出 `si-mcp-skills:hook-detect`。在仓库外执行 `skills/list`，返回的 Skill 路径位于安装缓存，所属插件 ID 为 `si-mcp-skills@si-mcp-skills`。 |
| 安装态 CLI | 在仓库外对安装缓存中的 `hook_detect.py` 执行 `uv run --no-project --offline --script <脚本路径> --help`，退出码为 0，列出 `verify-transport`、`module` 和 `process`。 |
| 独立分发发现 | `npx --offline --yes skills add . --list` 从仓库根目录发现一个独立 Skill `hook-detect`。 |
| 离线契约 | `uv run --no-project --offline test/skill-contract/01_cli_contract.py -v` 通过 5 项。相同方式运行 `test/mcp-contract/01_transport_contract.py` 通过 14 项。 |

实际 `simcp.exe` 握手、活进程扫描和远程市场安装未执行。研究预览版活进程证据见 [2026-11-19 Skill 安装态 E2E](skill-e2e-2026-11-19.md)，首版门槛见[首版验收清单](initial-release.md)。
