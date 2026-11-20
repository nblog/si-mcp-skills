---
title: si-mcp-skills
description: 围绕 System Informer MCP 服务构建的插件与 Agent Skills。
ms.date: 2026-11-20
---

[English](README.md) | [简体中文](README.zh-CN.md)

[![skills.sh](https://skills.sh/b/nblog/si-mcp-skills)](https://skills.sh/nblog/si-mcp-skills)

## 介绍

围绕 [System Informer](https://github.com/systeminformer/systeminformer) MCP 服务构建的插件，当前版本为研究预览版。

| Skill | 描述 |
|---|---|
| [hook-detect](plugins/si-mcp-skills/skills/hook-detect/) | Windows 进程和模块的只读扫描，检查 inline patch、EAT 变化与 IAT 重定向。 |

> [!CAUTION]
> 扫描要求已审阅的 `simcp.exe` 和显式授权目标（PID 与精确进程名）；扫描器只读内存且不修改进程。

## 安装插件

```powershell
codex plugin marketplace add nblog/si-mcp-skills
```

## 独立安装 Skill

Codex、Claude Code、GitHub Copilot 等兼容代理可通过 Skills CLI 安装。

```powershell
npx skills add nblog/si-mcp-skills
```
