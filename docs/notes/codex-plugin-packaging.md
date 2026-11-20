# Codex 插件封装

日期：2026-11-20。适用范围为 Hook Detect 研究预览版。

仓库市场清单位于 [`.agents/plugins/marketplace.json`](../../.agents/plugins/marketplace.json)，市场和插件的 ID 均为 `si-mcp-skills`。市场中的本地来源指向仓库内的 [`plugins/si-mcp-skills/`](../../plugins/si-mcp-skills/)。插件清单为 [`.codex-plugin/plugin.json`](../../plugins/si-mcp-skills/.codex-plugin/plugin.json)，其中 `skills` 指向该插件内的 [`skills/`](../../plugins/si-mcp-skills/skills/)。Hook Detect 的入口、脚本和输出参考放在同一个 Skill 目录中，供 Codex 安装和 Skills CLI 分发。

安装命令见[仓库 README](../../README.zh-CN.md#安装到-codex)。此前通过符号链接独立安装的用户可将链接更新到 [新 Skill 目录](../../plugins/si-mcp-skills/skills/hook-detect/)。

Windows 上由 `uv` 按脚本的 PEP 723 元数据运行 Python 3.13 入口。按 [ADR 0001](../adr/0001-python-mcp-skill-and-read-only-boundary.md)，Typer CLI 的 `ph_utils` 层使用调用者提供的绝对路径和 SHA-256 校验并启动本机 `simcp.exe`。插件只分发 Skill，`simcp.exe` 需由调用者自行准备。

安装与发现的实测结果见 [2026-11-20 Codex 插件验收](../checklist/codex-plugin-2026-11-20.md)。
