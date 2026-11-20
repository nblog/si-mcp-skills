---
title: si-mcp-skills
description: Plugins and agent skills built around the System Informer MCP server.
ms.date: 2026-11-20
---

[English](README.md) | [简体中文](README.zh-CN.md)

[![skills.sh](https://skills.sh/b/nblog/si-mcp-skills)](https://skills.sh/nblog/si-mcp-skills)

## Introduction

Plugins built around the [System Informer](https://github.com/systeminformer/systeminformer) MCP server. The current version is a research preview.

| Skill | Description |
|---|---|
| [hook-detect](plugins/si-mcp-skills/skills/hook-detect/) | Read-only scanning of Windows processes and modules for inline patches, EAT changes, and IAT redirection. |

> [!CAUTION]
> Scans require a reviewed `simcp.exe` and an explicitly authorized target (PID and exact process name); the scanner reads memory only and never modifies processes.

## Install the plugin

```powershell
codex plugin marketplace add nblog/si-mcp-skills
```

## Install the standalone skill

Codex、Claude Code, GitHub Copilot, and other compatible agents can install it through the Skills CLI.

```powershell
npx skills add nblog/si-mcp-skills
```
