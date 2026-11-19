# ADR 0001：Python MCP Skill 平台与只读边界

日期：2026-11-19。状态：已接受；Python 依赖版本策略由 [ADR 0003](0003-mcp-compatibility-pin.md) 补充。

## 背景

旧项目 `../si-hook-detect` 采用 System Informer C++ 插件，通过宿主菜单、Ph APIs 和 LIEF C++ 完成扫描。用户决定将交付迁移为本仓库的 Codex Skill，并要求正式入口为 Typer CLI、PEP 723 内联依赖和 Pydantic v2 配置。研究阶段已经验证：

- Python MCP SDK `1.30.0` 可通过固定哈希的本机 `simcp.exe` 建立 stdio 会话，并获得 `structuredContent`。
- LIEF Python `1.0.0` 能分别解析磁盘布局与映像 dump；Capstone `5.0.9` 能区分跳转、立即数和截断。
- 只读的模块枚举、页枚举和进程内存读取足以完成授权样本上的 region/EAT/IAT 验证。

## 决策

1. 正式平台为 Python + Typer + PEP 723 + Pydantic v2，通过 System Informer MCP 获取目标数据；不再继续 C++ 宿主插件路线。
2. `ph_utils` 是唯一的 MCP 边界，负责可信执行文件 pin、会话、工具白名单、structured response 校验、身份复验、预算、超时和取消。扫描算法不直接使用 Win32 进程读取，也不因 MCP 失败回退到本机 API。
3. 所有目标操作保持只读。禁止注入、暂停/恢复、修改内存、终止进程、创建 dump、关闭防护、提权或把原始内存 payload 写入对话、日志和报告。
4. `simcp.exe` 必须来自人工审阅的绝对路径与 SHA-256 pin；执行文件升级后必须重新审阅，不能自动信任新哈希。
5. 客户端固定单次进程内存读取上限 `65535` 字节。配置可以降低预算，不能提高该硬上限。`page_size=4096` 是首读提示，不是系统页大小或读取上限。
6. 结果必须区分完成、部分、无法比较、目标变化、不适用与未知；不得把预算耗尽、读取失败或未解析 API set 写成“无发现”。

## 取舍

- 相比 C++ 插件，Python 版不再依赖宿主 ABI、菜单生命周期和本机构建工具链，更容易作为 Skill 分发和离线回放；代价是需要严格管理 MCP 会话、原生依赖版本和响应预算。
- MCP-only 使数据面可审计、可回放，并复用 System Informer 的访问边界；代价是并发受单一 `ClientSession` 串行化影响，且工具端确认/权限失败必须显式报告。
- Pydantic v2 strict 模型用于信任边界字段，减少字符串/整数强转；内部热路径可用已验证的普通对象降低开销。

## 后果

后续实现必须从 `ph_utils` 请求目标数据，测试用合成 MCP 响应或显式授权的实测入口。任何需要敏感读取、提权或扩大目标范围的验收都必须在执行前明确授权；历史授权不能自动带入新目标。
