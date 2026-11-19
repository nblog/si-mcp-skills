# Hook Detect 研究预览版结项

日期：2026-11-19。状态：已完成；这是可安装执行的研究预览，不是首版发布。

## 完成范围

- 新增 `skills/hook-detect/SKILL.md` 与只读输出解释说明。
- 新增 Typer + PEP 723 入口 `skills/hook-detect/scripts/hook_detect.py`：
  - `verify-transport`：self 元数据与零内存预算；
  - `module` / `process`：显式 PID、模块名或 `NAME@BASE` 消歧，可选 inline/EAT/IAT 阶段。
- `lib/ph_utils` 固化可信 `simcp.exe` pin、MCP 工具白名单、structured response 校验、身份/分页/freshness 校验、RPC/时间/响应/内存预算和 65,535 硬上限。
- `lib/pe` 固化 LIEF 磁盘基线、节/RVA/raw-offset 映射、重定位归一化、运行时可执行区间交集和分块读取。
- `lib/detect` 固化 region-first patch 分类、EAT 语义比较、IAT 预期地址解析、delay 冷状态与 unknown 状态。
- 输出报告不包含原始内存 payload 或完整模块路径；路径以哈希表示。

## 验证

- CLI 契约测试在 `test/skill-contract/01_cli_contract.py`。
- 安装态 E2E 记录见 [Skill 安装态 E2E 验收](../../checklist/skill-e2e-2026-11-19.md)。
- 研究算法与旧证据见[2026-11-19 研究验证](../../checklist/research-validation-2026-11-19.md)。

## 未完成与后续

1. IAT 的 API set 解析仍是全进程唯一直接导出 fallback，不能作为首版全覆盖。
2. 磁盘基线尚未做强文件身份/替换闭环；当前为路径、大小、机器、映射头和重定位一致性配对。
3. `process --all-modules` 尚未在全部 WXWork 模块上完成预算/覆盖验收。
4. 回放命令、报告 schema 的独立验收和正式发布记录仍未完成；见[首版验收清单](../../checklist/initial-release.md)。
