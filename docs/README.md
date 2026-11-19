# Hook Detect Skill 文档

本目录是 `si-mcp-skills` 的正式设计基线。`test/` 与 `.codex-tracking/` 中的记录是研究证据和验收输入；进入本目录的结论必须已经与当前目标范围对齐，并在后续实现和验收中持续维护。

## 阅读顺序

1. [ADR 0001：Python MCP Skill 平台与只读边界](adr/0001-python-mcp-skill-and-read-only-boundary.md)：为什么从旧 C++ 插件迁移到 Python/MCP Skill，以及不可突破的安全边界。
2. [ADR 0002：region-first 检测顺序](adr/0002-region-first-detection.md)：为什么 inline 发现必须从可执行区域 diff 开始，导入/导出不能作为定位信源。
3. [扫描设计](notes/scan-design.md)：模块身份、PE 基线、inline、EAT、IAT、进程覆盖和输出状态的当前约束。
4. [实施方案](notes/implementation-plan.md)：从研究入口迁移到 `skills/hook-detect/scripts/` 的文件职责、阶段和验收顺序。
5. [首版验收清单](checklist/initial-release.md)：发布前必须逐项通过的门槛；IAT 是独立必过项。
6. [2026-11-19 研究验证记录](checklist/research-validation-2026-11-19.md)：已执行的离线与 WXWork 实测证据，不等于发布验收。

## 文档职责

- `adr/` 保存决策及其取舍；决策被替代时新增 ADR 并回标旧决策，不覆盖历史脉络。
- `notes/scan-design.md` 保存当前有效的设计与契约，是实现和测试必须遵守的说明。
- `notes/implementation-plan.md` 保存分阶段落地方案；完成阶段后把事实迁入当前说明或结项记录，避免把过程草稿当作长期设计。
- `checklist/` 保存验收范围、命令、结果和最小证据。未执行项保持未勾选；复验新增日期记录，不覆盖历史。
- 未来已完成任务在 `notes/implemented/` 建结项记录；被替代说明进入 `notes/archived/`。当前尚未发布正式 Skill，因此这些子目录暂不预建。
