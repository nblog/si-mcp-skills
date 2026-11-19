# 2026-11-19 研究验证记录

日期：2026-11-19（Asia/Shanghai）。状态：已执行。本文是研究验证，不是首版发布验收；命令与机器证据见 [test README](../../test/README.md)和 `.codex-tracking/research/`。

## 环境

- Windows x64，CPython `3.13`，uv `0.13.9`。
- Python MCP SDK `1.30.0`，LIEF `1.0.0`，Capstone `5.0.9`，Typer `0.20.0`，Pydantic `2.12.5`。
- System Informer `4.0.26255.346`，`simcp.exe` SHA-256 `a071edf7e7e55404fdaaaeb3a947aa74f265018459c923849bb2602a6750730e`，未提升，KSI `none`。
- WXWork 目标：PID `20504`，sequence `997`，WOW64 `kernel32.dll` 与 `KernelBase.dll`；扫描前后目标稳定。

## 已执行

- [x] 新 stdio transport 使用固定 `simcp.exe` 与 SDK `1.30.0`，返回 `structuredContent`，self 模块样本两次一致，零进程内存读取。
- [x] LIEF x86/x64 文件布局与连续 dump 布局离线验证；首读 4096 只能证明目录声明，不能证明目录内容已取得。
- [x] Capstone 验证 direct/indirect jump、截断、立即数字节和入口返回补丁。
- [x] region-first 完整比较 `kernel32.dll` 444,345 字节、`KernelBase.dll` 2,641,954 字节；共发现三个 5 字节 patch，读取 gap 为 0。
- [x] 三个 WXWork 断言：`LoadLibraryExW` direct jump、`WriteFile` direct jump、`SetUnhandledExceptionFilter` entry return patch。
- [x] EAT：两个模块共 3,707 个函数槽位、3,707 个命名导出映射和 308 个转发字符串全部一致，无 EAT 改写发现。
- [x] IAT：2,260 个导入条目中 1,309 个建立可信预期且全部 equal；159 个为未解析 delay import 冷状态；792 个因 API set/候选不唯一保持 unknown。连续读取覆盖 2,419 个 4 字节地址，其中 159 个是槽位间填充地址，不计入导入条目。

Region-first 机器证据：`.codex-tracking/research/hook-detect-wxwork-region-diff-2026-11-19.json`。EAT/IAT 机器证据：`.codex-tracking/research/hook-detect-wxwork-eat-iat-2026-11-19.json`。输出不含原始内存 payload。

## 发现的问题

- 导出 32-byte 重叠窗口会把相邻 `WriteFile` patch 归因到 `UnlockFileEx`；该历史入口仅保留对照。
- LIEF `ExportEntry.address` 对转发项不能代表 EAT 槽位；实现必须使用 `function_rva` 并单独保留转发信息。
- delay import 的磁盘冷值是按 preferred base 存放的绝对地址，运行时需按目标基址归一化后才能与实际指针比较。
- 当前 API set 解析只有全进程唯一同名直接导出 fallback；787 个 `kernel32.dll` 槽位仍未知，不能满足首版 IAT 覆盖要求。

## 结论

只读 MCP 数据面、region-first inline、EAT 语义比较和部分 IAT 语义预期已经闭环。正式实现前仍需权威 API set/转发覆盖、更强磁盘基线配对、全部模块预算验证和 CLI/Skill 包装。
