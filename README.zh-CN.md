---
title: si-mcp-skills
description: 围绕 System Informer MCP 服务构建的实用 Agent Skills。
ms.date: 2026-11-19
---

[English](README.md) | [简体中文](README.zh-CN.md)

[![skills.sh](https://skills.sh/b/nblog/si-mcp-skills)](https://skills.sh/nblog/si-mcp-skills)

## 介绍

围绕 [System Informer](https://github.com/systeminformer/systeminformer) MCP 服务构建的实用 Agent Skills 集合。

| Skill | 描述 |
|---|---|
| [hook-detect](skills/hook-detect/) | 面向已授权 Windows 进程的 PE 模块只读扫描器：inline patch、EAT 变化与 IAT 重定向。研究预览版。 |

> [!CAUTION]
> 扫描要求显式授权目标（PID 与精确进程名）和已审阅的 `simcp.exe`；扫描器只读内存且不修改进程。

## 使用

快速安装，支持 Codex、Claude Code、GitHub Copilot 等代理：

```powershell
npx skills add nblog/si-mcp-skills
```
