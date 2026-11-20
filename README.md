---
title: si-mcp-skills
description: Practical agent skills built around the System Informer MCP server.
ms.date: 2026-11-19
---

[English](README.md) | [简体中文](README.zh-CN.md)

[![skills.sh](https://skills.sh/b/nblog/si-mcp-skills)](https://skills.sh/nblog/si-mcp-skills)

## Introduction

A collection of practical agent skills built around the [System Informer](https://github.com/systeminformer/systeminformer) MCP server.

| Skill | Description |
|---|---|
| [hook-detect](skills/hook-detect/) | Read-only scanner for Windows processes/modules: inline patches, EAT changes, and IAT redirection. |

> [!CAUTION]
> Scans require a reviewed `simcp.exe` and an explicitly authorized target (PID and exact process name); the scanner reads memory only and never modifies processes.

## Usage

Quick install; works with Codex, Claude Code, GitHub Copilot, and other agents:

```powershell
npx skills add nblog/si-mcp-skills
```
