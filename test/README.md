# 研究验证

从仓库根目录执行。各入口自行用 PEP 723 声明依赖；`--offline` 依赖已缓存的安装包。以下为研究验证，还不是正式扫描器验收。

| 分组 | 入口 | 范围 |
|---|---|---|
| `mcp-contract` | [01_transport_contract.py](mcp-contract/01_transport_contract.py) | 合成 MCP 响应、只读工具白名单、模块身份和预算；不连接 MCP。 |
| `mcp-contract` | [replay_probe.py](mcp-contract/replay_probe.py) | 磁盘导出窗口试验；可从 stdin 比对合成读取响应，单条最多 65535 字节。原在 `skills/hook-detect/scripts/probe.py`。 |
| `mcp-contract` | [transport_probe.py](mcp-contract/transport_probe.py) | 用明确审阅的本机 `simcp.exe` 和固定哈希连 stdio，仅枚举当前探针进程的模块元数据，进程内存读取预算为零。原在 `.codex-tracking/experiments/`。 |
| `pe-baseline` | [01_lief_layout.py](pe-baseline/01_lief_layout.py) | 合成 x86/x64 PE 文件布局、映像布局与首读目录声明。 |
| `inline-evidence` | [01_capstone_jumps.py](inline-evidence/01_capstone_jumps.py) | 合成 x86/x64 跳转、截断与作为立即数的 opcode 字节。 |
| `hook-detect` | [03_wxwork_region_diff.py](hook-detect/03_wxwork_region_diff.py) | 当前主路径：完整转储磁盘可执行节与运行时可执行页交集，先 diff 得 patch RVA，再用 Capstone 判定 inline/返回补丁。 |
| `hook-detect` | [04_wxwork_eat_iat.py](hook-detect/04_wxwork_eat_iat.py) | EAT 语义比较与 IAT 实际指针/可信预期地址校验；API set 未解析时保持 unknown。 |
| `hook-detect` | [02_scan_evidence.py](hook-detect/02_scan_evidence.py) | 离线验证相等窗口、非入口 direct jump、既有指令操作数改动、入口返回补丁、跨读取重定位和短读拒绝。 |
| `hook-detect` | [05_table_evidence.py](hook-detect/05_table_evidence.py) | 离线验证 EAT 槽位改写、IAT 直连与转发预期地址。 |
| `hook-detect` | [01_wxwork_export_probe.py](hook-detect/01_wxwork_export_probe.py) | 历史导出入口对照；重叠窗口会产生相邻导出归因错误，不作为 patch 发现源。 |
| `skill-contract` | [01_cli_contract.py](skill-contract/01_cli_contract.py) | 正式 Skill 元数据、Typer 命令、显式目标、固定依赖和 65535 硬边界。 |

```powershell
uv run --no-project --offline test/mcp-contract/01_transport_contract.py -v
uv run --no-project --offline test/pe-baseline/01_lief_layout.py -v
uv run --no-project --offline test/inline-evidence/01_capstone_jumps.py -v
uv run --no-project --offline test/hook-detect/02_scan_evidence.py -v
uv run --no-project --offline test/hook-detect/05_table_evidence.py -v
uv run --no-project --offline test/skill-contract/01_cli_contract.py -v
uv run --no-project --offline test/mcp-contract/replay_probe.py C:/Windows/SysWOW64/KernelBase.dll LoadLibraryW
uv run --no-project --offline test/mcp-contract/replay_probe.py C:/Windows/System32/KernelBase.dll LoadLibraryExW
```

`hook-detect` 的活进程实验不会隐式选择本机可执行文件；调用者必须显式提供人工审阅的 `simcp.exe` 绝对路径和 SHA-256：

```powershell
uv run --no-project --offline test/hook-detect/01_wxwork_export_probe.py --simcp '<审阅后的绝对路径>' --sha256 '<审阅时核对的 SHA-256>' --process-name WXWork.exe --workers 4
```

当前 region-first 实测入口：

```powershell
uv run --no-project --offline test/hook-detect/03_wxwork_region_diff.py --simcp '<审阅后的绝对路径>' --sha256 '<审阅时核对的 SHA-256>' --process-name WXWork.exe --workers 2
uv run --no-project --offline test/hook-detect/04_wxwork_eat_iat.py --simcp '<审阅后的绝对路径>' --sha256 '<审阅时核对的 SHA-256>' --process-name WXWork.exe --workers 2
```

在已审阅的本机安装上单独复验非敏感 stdio：

```powershell
uv run --no-project --offline test/mcp-contract/transport_probe.py --simcp '<审阅后的本机绝对路径>' --sha256 '<审阅时核对的 SHA-256>'
```

实际结果见 [2026-11-18 设计差异与验证](../.codex-tracking/research/hook-detect-design-review-2026-11-18.md)、[2026-11-19 WXWork 导出入口历史实测](../.codex-tracking/research/hook-detect-wxwork-2026-11-19.md)、[2026-11-19 region-first 实测](../.codex-tracking/research/hook-detect-region-first-2026-11-19.md)和[安装态 Skill E2E](../docs/checklist/skill-e2e-2026-11-19.md)。没有跨组辅助模块、构建产物或项目级类型检查路径；Python 缓存与历史临时运行环境由根目录 `.gitignore` 排除。
