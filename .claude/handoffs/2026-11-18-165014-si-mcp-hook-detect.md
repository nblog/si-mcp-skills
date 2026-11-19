# Handoff: System Informer MCP Hook Detect Skill

## Session Metadata
- Created: 2026-11-18 16:50:14 (Asia/Shanghai)
- Project: C:\Users\r0th3r\Desktop\Repos\example\si-mcp-skills
- Branch: `main` (unborn; no commits)
- Session duration: about 15 minutes of research, experiments and handoff preparation

## Handoff Chain

- Continues from: no prior handoff; read old design session `01a1ec9e-003d-71d3-813d-44800fd3944a` as historical design evidence.
- Supersedes: no documents in the old repo. The user selected a new delivery model, not an in-place rewrite of its C++ plugin.

## Current State Summary

用户决定把 System Informer Hook 检测从 C++ 插件迁移为只读 Codex Skill。已读取旧会话和旧项目设计，完成离线分析及 MCP 连接可行性验证，产物留在工作区，未提交。已经确认 **Python SDK 能直接连接本机 `simcp.exe` 并获取结构化模块结果**；敏感内存读取在新 stdio 连接上的授权与满块响应尚未验证。没有正式 `SKILL.md`、扫描器或发布验收；不要把研究 PoC 当成交付功能。

## Architecture Overview

`SKILL.md` 只负责触发、用户授权、扫描范围、命令与结果解释。单一 PEP 723 Python CLI 驱动受信任的 System Informer MCP stdio adapter；处理结构化响应，在 Python 内完成 PE/RVA 对齐、证据和覆盖分类。模块扫描器复用于进程模式；所有活进程采集通过 System Informer MCP。磁盘 PE 解析、合成测试和文档可使用对应本地工具。

## Critical Files

| File | Purpose | Relevance |
|---|---|---|
| `AGENTS.md` | 仓库工作规则 | 正式文档入口尚未建立，先明确新设计基线；研究和实验留 `.codex-tracking`；验收不可虚报 |
| `.codex-tracking/README.md` | 索引 | 所有本轮证据与提案入口 |
| `.codex-tracking/research/hook-detect-mcp-2026-11-18.md` | 调研、实测矩阵、参考来源 | 详述哪些验证过、哪些未验证，以及保留的检测边界 |
| `.codex-tracking/plans/hook-detect-mcp.md` | 工作顺序、输出口径和验收提案 | 新会话按第 1 阶段推进 |
| `skills/hook-detect/scripts/probe.py` | LIEF + Capstone 离线实验 | 无 live 调用；单个导出窗口，不能定性 Hook |

### Key Patterns Discovered

先验证目标身份和读覆盖，后作比较。在比对中分清磁盘 offset、映像 RVA、运行 VA；报告中分清 `finding` 与 `coverage`；无差异只描述成功比较的范围。名称相同的 x86/x64 模块必须按映像身份和地址区分。

## Work Completed

### Tasks Finished

- [x] 阅读旧项目 `../si-hook-detect/docs` 和旧会话，提炼保留的检测与首版边界。
- [x] 用 PEP 723、LIEF `1.0.0`、Capstone `5.0.9` 跑通 32/64 位磁盘导出与指令、旧 5 字节响应的等/不等回放。
- [x] 验证离线接受 65536、拒绝 65537、截断 payload 与错误 sequence。
- [x] 直连实验验证 SDK `1.30.0`/listing/`structuredContent`；记录 `mcpc@0.8.0` 握手后 listing 校验失败，临时配置和桥接会话已清理。

## Files Modified

| File | Changes | Rationale |
|---|---|---|
| `.codex-tracking/README.md` | 新建导航 | 减少重读旧会话 |
| `.codex-tracking/research/hook-detect-mcp-2026-11-18.md` | 调研和验证证据 | 区分已观察与待证假设 |
| `.codex-tracking/plans/hook-detect-mcp.md` | 阶段与门槛 | 帮助下一会话执行 |
| `skills/hook-detect/scripts/probe.py` | 离线 PoC | 尽早证明依赖和边界可行 |

## Decisions Made

| Decision | Options Considered | Rationale |
|---|---|---|
| 选 Skill + Python，保留模块检测模型 | 继续基于 C++ 的宿主插件 | 用户指定新方向；不用耦合宿主菜单、ABI 与 SDK |
| 批量采集通过已实测的 Python MCP SDK | LLM 搬 hex、mcpc 0.8.0、Win32 回退 | 避开模型输出截断，兼容本机协议，保留唯一采集入口 |
| 首版保留 IAT 独立阶段；分项给覆盖 | 仅检查几处入口或只报一致性分数 | 与旧需求对齐；IAT/EAT 独立，不报误导性全覆盖 |

## Immediate Next Steps

1. **先复跑离线 PoC，并固化最小 adapter 契约核验**：先用无敏感的 `get_process_modules`，确认 SDK `1.30.0`、结构化响应、工具白名单、身份和预算断言。核验源于显式可信 `simcp.exe` 配置；不要写入全局 MCP 配置。
2. 仅在有授权的可控样本上尝试 `5` / `4096` / `65536` 字节实读，原始响应不进模型、日志或文件；新连接需要用户确认时停下，先完成人工确认前能够执行的工作。
3. 依 `AGENTS.md` 对齐新仓库的正式范围与文档入口，再推进 `SKILL.md`、模块扫描、EAT、IAT；固定不变的规则用代码和测试表达。沿用研究记录，不重复做全面文献调研。

### Blockers/Open Questions

- 新 stdio 连接中的敏感读确认和满块输出仍待实测。不因为旧会话曾获得许可就执行超出授权的读操作。
- `skills/` 不等同 Codex 自动发现目录；先显式加载，再选安装或插件发布，不改全局配置。
- 可信磁盘对应、动态重定位、API sets/延迟导入解析覆盖仍未实现；不强行宣称全部支持。

### Deferred Items

- 进程级并发、多目标扫描、跳转来源归因、ARM64、任何 GUI、发布与安装。旧仓库不变。

## Important Context

- 只用于授权目标的防御性诊断；不注入、改写、暂停、提权、关闭防护或外传数据。主代码不使用 Win32 作为 MCP 失败后的替代进程读路径。
- 工具描述的硬边界 `1..65536` 未以 JSON Schema `maximum` 表达，必须在脚本中执行限制。4096 只是首读提示。进程序号与模块地址必须重取，报告要处理卸载与重用。
- 回放 `LoadLibraryW` 得到 `raw_equal`；`LoadLibraryExW` 得到 `raw_different` 且内存解码为直接跳转。后者仅是已比较窗口上的疑似重定向证据，未确认来源或恶意性。

## Assumptions Made

- 用户之前的 MCP-only 限制继续适用于活进程操作；后续明确要求的 Codex 会话查阅、文件/脚本与一手资料调研允许相应工具。
- 已验证环境是本机 Windows x64 CPython 3.13，分析目标可为 x86/WOW64 或 x64；不要把进程实验中的 PID、地址和系统文件版本写入正式扫描器。

## Potential Gotchas

- `mcpc@0.8.0` 当前校验 `tools/list` 缺字段；不要把它的失败等同 MCP 服务不可用。
- `resolve_symbol` 是辅助而非可信 baseline；`MZ`、路径相同和数字签名各自都不证明内存映像未改变。
- 当前 PoC 不做重定位、基线匹配与整体覆盖；`raw_different` 不能提升成 Hook 结论。

## Environment State

### Tools/Services Used

- Windows x64、PowerShell、`uv 0.13.9`、CPython `3.13.17`，System Informer `4.0.26255.346`，未提升且无 KSI。MCP 数据 schema 版本 1；已测试 `simcp.exe` / stdio 和 SDK `1.30.0`。
- `main` 无 commit；已有的 `AGENTS.md`、`README.md`、`README.zh-CN.md` 未修改。草稿文件在当前实际工作区，不使用新 worktree。

### Active Processes

- 没有本轮驻留的 watcher、桥接会话、测试进程或服务；System Informer 与用户进程由用户原本启动。

### Environment Variables

- 不需新的环境变量或密钥。`PYTHONUTF8` 仅在生成和验证交接时临时启用。

## Related Resources

- 旧项目 `../si-hook-detect/docs/README.md`，历史设计入口。
- 一手资料及可复验命令集中在 `.codex-tracking/research/hook-detect-mcp-2026-11-18.md`。
