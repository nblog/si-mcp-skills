# 实施方案

日期：2026-11-19。状态：研究预览版已实现；本文保留目标结构与剩余迁移顺序。测试与安装态 E2E 见[研究验证](../checklist/research-validation-2026-11-19.md)、[Skill E2E](../checklist/skill-e2e-2026-11-19.md)。

## 目标结构

```text
skills/hook-detect/
  SKILL.md
  scripts/
    hook_detect.py          # Typer + PEP 723 唯一 CLI 入口
    lib/
      config.py             # Pydantic v2 BaseConfig 与固定边界
      ph_utils/
        mcp.py              # SDK session、工具白名单、structured response 校验
        models.py           # 进程/模块/页/读取响应模型
        budget.py           # RPC、时间、响应、内存预算与取消
      pe/
        baseline.py         # LIEF 磁盘/映像布局、节、重定位、导入/导出
        regions.py          # 磁盘/运行时可执行区间与分块读取计划
      detect/
        inline.py           # diff、patch 合并、Capstone 分类
        eat.py
        iat.py
      report.py
```

`hook_detect.py` 只负责命令、参数校验、装配和输出；不得复制算法。本地库通过脚本所在目录显式加入 `sys.path`，不依赖调用者当前目录或全局 venv。PEP 723 依赖使用 [ADR 0003](../adr/0003-mcp-compatibility-pin.md) 规定的 MCP 精确版本与分析库最低版本，并在报告中记录实际解析版本；后续如果拆成多文件仍保留唯一入口元数据。

## CLI 命令

- `hook_detect.py module --pid PID --process-name NAME --module NAME[@BASE] ...`
- `hook_detect.py process --pid PID --process-name NAME [--all-modules | --module NAME[@BASE] ...] ...`
- `hook_detect.py verify-transport --simcp PATH --sha256 HASH ...`
- `hook_detect.py replay --fixture PATH`：离线回放 MCP/PE fixture，不启动服务。

默认输出 JSON 到文件，终端只打印摘要。命令必须提供 `--output`、预算、模块选择和结果格式选项；不提供任何进程变更、提权、任意工具名或任意命令参数。

## 迁移步骤

1. **固化配置与 ph_utils**：把 `test/hook-detect/01_wxwork_export_probe.py` 中已验证的可信 pin、structured response、身份、分页、预算和读取校验抽出；保留 transport 离线测试。
2. **固化 PE 基线**：迁移 `scan_evidence.py` 的 LIEF 布局、重定位、文件偏移/RVA 区分和头校验；为 `parse_from_dump` 与稀疏读取补独立测试。
3. **region-first inline**：迁移 `03_wxwork_region_diff.py` 流程，保持完整可执行节交集、patch-first、512 阈值和边界分类；导出信息只做归因。
4. **EAT**：迁移 `04_wxwork_eat_iat.py` 的导出目录/槽位/名称比较，补充转发字符串、目录损坏、部分读取和无导出 fixture。
5. **IAT**：迁移语义预期、delay 冷状态和转发链；把当前“唯一同名导出”降级为研究 fallback，正式路径实现目标 ApiSetMap 或可信 schema 解析。
6. **进程覆盖**：实现显式模块集合/全部模块、共享预算、失败隔离、取消和模块重名消歧；先用回放再做授权实测。
7. **Skill 包装**：核心验收通过后编写 `SKILL.md`，说明触发条件、授权/范围、固定入口、输出解读和不适用场景；不在提示词中复制算法细节。

## 测试组织

- `test/mcp-contract/`：transport、structured response、工具白名单、身份与预算。
- `test/pe-baseline/`：LIEF 文件/映像布局、头、节、目录和重定位。
- `test/inline-evidence/`：Capstone 指令与误报边界。
- `test/hook-detect/`：region diff、EAT/IAT、离线分类和授权实测研究入口。

研究脚本可以保留历史对照，但 README 必须标明主路径；正式实现迁移后，测试不得 import `skills/` 内部模块来绕过 CLI 契约，除单元级 fixture 外优先通过入口和回放验证。

## 完成定义

- x86/x64 离线 fixture 与授权实测样本均可用同一 CLI 复现；
- 输出能解释每个模块和阶段的覆盖、partial/gap/unknown；
- IAT 权威 API set/转发解析达到首版门槛；
- 明确 Skill 安装或显式链接方式；
- 未授权敏感操作在代码和 Skill 指令中均无入口。
