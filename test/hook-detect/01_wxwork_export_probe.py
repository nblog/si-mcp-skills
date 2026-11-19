# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mcp==1.30.0",
#   "lief==1.0.0",
#   "capstone==5.0.9",
#   "typer==0.20.0",
#   "pydantic==2.12.5",
# ]
# ///

"""Historical read-only WXWork export-entry comparison.

This was an intermediate experiment and is not the patch-discovery source:
overlapping 32-byte windows can attribute a neighboring patch to the wrong
export. Use 03_wxwork_region_diff.py for region-first discovery.
"""

import asyncio
import hashlib
import importlib.metadata
import json
import logging
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

import anyio
import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult
from pydantic import BaseModel, ConfigDict, Field

from scan_evidence import MAX_FILE_BYTES, MAX_READ_BYTES, ScanGap, load_baseline, window_result


ROOT = Path(__file__).resolve().parents[2]
SDK_VERSION = "1.30.0"
REQUIRED_TOOLS = {
    "get_process",
    "list_processes",
    "get_process_modules",
    "get_process_memory_regions",
    "read_process_memory",
}
KNOWN_ASSERTS = {
    "kernelbase.dll": {"LoadLibraryExW"},
    "kernel32.dll": {"WriteFile", "SetUnhandledExceptionFilter"},
}


class Config(BaseModel):
    """Strict research defaults; user options cannot weaken fixed boundaries."""

    model_config = ConfigDict(strict=True, extra="forbid")

    page_size: Literal[4096] = 4096
    patch_block_size: Literal[512] = 512
    max_read_bytes: Literal[65535] = 65535
    rpc_limit: int = Field(default=8192, ge=32, le=16384)
    total_seconds: float = Field(default=300, ge=30, le=600)
    rpc_seconds: float = Field(default=10, ge=1, le=30)
    max_reply_bytes: int = Field(default=8 * 1024 * 1024, ge=128 * 1024)
    max_total_reply_bytes: int = Field(default=512 * 1024 * 1024, ge=1024 * 1024)
    max_memory_bytes: int = Field(default=64 * 1024 * 1024, ge=64 * 1024)
    max_modules: int = Field(default=256, ge=1, le=512)
    max_exports_per_module: int = Field(default=2048, ge=1, le=8192)
    max_snapshot_age_seconds: int = Field(default=30, ge=5, le=120)


class ProbeError(ValueError):
    """A fixed reason code that does not expose server responses."""


def require(condition, reason):
    if not condition:
        raise ProbeError(reason)


def unwrap(exc):
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def trusted_executable(path: Path, expected_sha256: str) -> Path:
    require(os.name == "nt", "windows_required")
    require(bool(re.fullmatch(r"[A-Za-z]:[\\/].+", str(path))), "local_absolute_path_required")
    require(path.name.lower() == "simcp.exe", "simcp_filename_required")
    require(bool(re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256)), "sha256_required")
    for part in (path, *path.parents):
        require(not (part.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),
                "reparse_path_rejected")
    resolved = path.resolve(strict=True)
    require(resolved.is_file() and resolved.stat().st_size <= 16 * 1024 * 1024,
            "invalid_executable_file")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    require(digest == expected_sha256.lower(), "executable_hash_mismatch")
    return resolved


@dataclass
class Budget:
    config: Config
    started: float
    calls: int = 0
    reply_bytes: int = 0
    memory_bytes: int = 0
    memory_calls: int = 0
    max_read_size: int = 0

    def remaining(self):
        left = self.config.total_seconds - (time.monotonic() - self.started)
        require(left > 0, "time_budget_exhausted")
        return min(self.config.rpc_seconds, left)

    def reserve(self):
        self.remaining()
        require(self.calls < self.config.rpc_limit, "rpc_budget_exhausted")
        self.calls += 1

    def accept(self, reply: CallToolResult):
        size = len(reply.model_dump_json().encode("utf-8"))
        require(size <= self.config.max_reply_bytes, "reply_budget_exhausted")
        require(self.reply_bytes + size <= self.config.max_total_reply_bytes,
                "total_reply_budget_exhausted")
        self.reply_bytes += size

    def reserve_memory(self, size):
        require(1 <= size <= self.config.max_read_bytes, "read_size_boundary")
        require(self.memory_bytes + size <= self.config.max_memory_bytes,
                "memory_byte_budget_exhausted")
        self.memory_bytes += size
        self.memory_calls += 1
        self.max_read_size = max(self.max_read_size, size)


def structured(reply: CallToolResult):
    require(reply.isError is False, "mcp_tool_error")
    require(isinstance(reply.structuredContent, dict), "structured_content_required")
    return reply.structuredContent


def fresh(record, config):
    require(record.get("updates_paused") is False, "provider_paused_or_unknown")
    stamp = record.get("snapshot_time")
    require(isinstance(stamp, str), "snapshot_time_required")
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        raise ProbeError("invalid_snapshot_time") from None
    require(parsed.tzinfo is not None, "snapshot_timezone_required")
    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    require(-5 <= age <= config.max_snapshot_age_seconds, "snapshot_outside_time_window")


def parse_address(value):
    require(isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]+", value)),
            "invalid_address")
    return int(value, 16)


def identity(record, pid):
    require(type(record.get("pid")) is int and record["pid"] == pid, "pid_mismatch")
    sequence = record.get("process_sequence_number")
    require(type(sequence) is int and sequence > 0, "invalid_process_sequence")
    return pid, sequence


@dataclass(frozen=True)
class ModuleRow:
    name: str
    path: str
    kind: str
    base: int
    size: int
    load_time: str | None

    @classmethod
    def parse(cls, row):
        name, path, kind = row.get("name"), row.get("file_path"), row.get("type")
        base, size, load_time = row.get("base_address"), row.get("size"), row.get("load_time")
        require(isinstance(name, str) and bool(name), "invalid_module_name")
        require(isinstance(path, str) and Path(path).is_absolute(), "invalid_module_path")
        require(isinstance(kind, str), "invalid_module_type")
        require(isinstance(load_time, str) or load_time is None, "invalid_module_load_time")
        return cls(name, path, kind, parse_address(base), size, load_time)

    @property
    def key(self):
        return (self.base, self.size, Path(self.path).resolve().as_posix().casefold(), self.kind,
                self.load_time)


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    executable: bool


class Scanner:
    def __init__(self, session, config: Config, budget: Budget):
        self.session = session
        self.config = config
        self.budget = budget
        self.used_tools = []
        self.phase = "initialize"
        self.memory_lock = asyncio.Lock()

    async def rpc(self, phase, operation):
        self.phase = phase
        self.budget.reserve()
        with anyio.fail_after(self.budget.remaining()):
            return await operation()

    async def call(self, name, args):
        require(name in REQUIRED_TOOLS, "tool_not_allowed")
        async def operation():
            self.used_tools.append(name)
            return await self.session.call_tool(name, args)
        reply = await self.rpc(name, operation)
        self.budget.accept(reply)
        return structured(reply)

    async def handshake(self):
        init = await self.rpc("initialize", self.session.initialize)
        require(init.protocolVersion == "2025-11-25", "unexpected_protocol_version")
        listing = await self.rpc("tools/list", self.session.list_tools)
        require(listing.nextCursor is None, "tool_catalogue_incomplete")
        names = [tool.name for tool in listing.tools]
        require(len(names) == len(set(names)) and REQUIRED_TOOLS <= set(names),
                "required_tools_missing_or_duplicate")
        return len(names)

    async def find_process(self, process_name, explicit_pid):
        require(bool(re.fullmatch(r"[^/\\:?*\"<>|]{1,128}", process_name)), "invalid_process_name")
        record = await self.call("list_processes", {"name_contains": process_name, "limit": 100})
        fresh(record, self.config)
        rows = record.get("processes")
        require(isinstance(rows, list), "invalid_process_rows")
        parsed = []
        for row in rows:
            require(isinstance(row, dict) and row.get("name", "").casefold() == process_name.casefold(),
                    "process_name_not_exact")
            pid = row.get("pid")
            sequence = row.get("process_sequence_number")
            require(type(pid) is int and type(sequence) is int and sequence > 0, "invalid_process_identity")
            start = row.get("start_time")
            require(isinstance(start, str), "invalid_process_start_time")
            parsed.append((datetime.fromisoformat(start), pid, sequence))
        if explicit_pid is not None:
            matches = [item for item in parsed if item[1] == explicit_pid]
            require(len(matches) == 1, "explicit_pid_not_found")
            selected = matches[0]
        else:
            require(parsed, "process_not_found")
            selected = min(parsed)
        pid, sequence = selected[1], selected[2]
        current = await self.call("get_process", {"pid": pid})
        fresh(current, self.config)
        require(identity(current, pid) == (pid, sequence), "process_identity_changed")
        return pid, sequence

    async def modules(self, pid, sequence):
        rows, offset = [], 0
        while True:
            record = await self.call("get_process_modules", {"pid": pid, "limit": 200, "offset": offset})
            fresh(record, self.config)
            require(identity(record, pid) == (pid, sequence), "process_identity_changed")
            require(record.get("enumeration_complete") is True, "module_enumeration_incomplete")
            require(record.get("offset") == offset, "module_page_offset_mismatch")
            page = record.get("modules")
            total = record.get("total_count")
            truncated = record.get("truncated")
            require(isinstance(page, list) and type(total) is int and type(truncated) is bool,
                    "invalid_module_page")
            require(truncated == (total > offset + len(page)), "invalid_module_truncation")
            rows.extend(ModuleRow.parse(row) for row in page)
            offset += len(page)
            if offset >= total:
                break
            require(offset < self.config.max_modules + 200, "module_budget_exhausted")
        require(0 < len(rows) <= self.config.max_modules, "module_count_boundary")
        require(len({row.base for row in rows}) == len(rows), "duplicate_module_base")
        return rows

    async def executable_regions(self, pid, sequence):
        regions, offset, snapshots, totals = [], 0, set(), set()
        while True:
            record = await self.call("get_process_memory_regions",
                                     {"pid": pid, "limit": 200, "offset": offset})
            fresh(record, self.config)
            require(identity(record, pid) == (pid, sequence), "process_identity_changed")
            page_snapshot = record.get("snapshot_id")
            require(type(page_snapshot) is int, "invalid_region_snapshot")
            snapshots.add(page_snapshot)
            require(record.get("offset") == offset, "region_page_offset_mismatch")
            page = record.get("regions")
            total, truncated = record.get("total_count"), record.get("truncated")
            totals.add(total)
            require(isinstance(page, list) and type(total) is int and type(truncated) is bool,
                    "invalid_region_page")
            require(truncated == (total > offset + len(page)), "invalid_region_truncation")
            for row in page:
                require(isinstance(row, dict), "invalid_region_row")
                size = row.get("size")
                protection = row.get("protection")
                require(type(size) is int and size > 0, "invalid_region_size")
                require(isinstance(protection, str) or protection is None, "invalid_region_protection")
                if row.get("state") == "commit" and row.get("type") == "image":
                    start = parse_address(row.get("base_address"))
                    regions.append(Region(start, start + size, "X" in (protection or "")))
            offset += len(page)
            if offset >= total:
                break
        regions.sort(key=lambda region: region.start)
        require(all(a.end <= b.start for a, b in zip(regions, regions[1:])),
                "overlapping_or_unsorted_regions")
        # WXWork changes private regions while it runs. Keep every fresh page and
        # report the observation instead of mistaking that churn for target death.
        return ([region for region in regions if region.executable], len(snapshots),
                sorted(totals))

    async def read(self, pid, sequence, address, size):
        self.budget.reserve_memory(size)
        async with self.memory_lock:
            record = await self.call("read_process_memory",
                                     {"pid": pid, "process_sequence_number": sequence,
                                      "address": hex(address), "size": size})
        fresh(record, self.config)
        require(identity(record, pid) == (pid, sequence), "process_identity_changed")
        require(parse_address(record.get("address")) == address, "read_address_mismatch")
        require(record.get("size") == size, "read_size_mismatch")
        payload = record.get("hex")
        require(isinstance(payload, str) and len(payload) == 2 * size
                and bool(re.fullmatch(r"[0-9a-fA-F]+", payload)), "read_payload_invalid")
        return bytes.fromhex(payload)


def covers(regions, start, end):
    for region in regions:
        if region.start <= start and end <= region.end:
            return True
        if region.start >= end:
            break
    return False


def lookup_module(modules, address):
    for row in modules:
        if row.base <= address < row.base + row.size:
            return row.name, address - row.base
    return None, None


async def scan_module(scanner, pid, sequence, row, regions, modules, worker_limit):
    result = {"module": row.name, "type": row.kind,
              "path_sha256": hashlib.sha256(row.path.encode("utf-8")).hexdigest(),
              "status": "gap", "reason": None}
    try:
        path = Path(row.path)
        require(path.is_file() and path.stat().st_size <= MAX_FILE_BYTES, "disk_file_missing_or_oversize")
        async with worker_limit:
            baseline = await asyncio.to_thread(load_baseline, path, row.size, row.base)
            header_size = min(scanner.config.page_size, row.size)
            async with scanner.memory_lock:
                scanner.budget.reserve_memory(header_size)
                record = await scanner.call("read_process_memory",
                                            {"pid": pid, "process_sequence_number": sequence,
                                             "address": hex(row.base), "size": header_size})
            fresh(record, scanner.config)
            require(identity(record, pid) == (pid, sequence), "process_identity_changed")
            require(parse_address(record.get("address")) == row.base and record.get("size") == header_size,
                    "header_read_mismatch")
            payload = record.get("hex")
            require(isinstance(payload, str) and len(payload) == 2 * header_size,
                    "header_payload_invalid")
            header = bytes.fromhex(payload)
            baseline.check_headers(header)

            named_exports = [(name, entries[0]) for name, entries in baseline.exports.items()
                             if len(entries) == 1]
            result["named_exports"] = len(named_exports)
            if len(named_exports) > scanner.config.max_exports_per_module:
                named_exports = named_exports[:scanner.config.max_exports_per_module]
                result["status"] = "partial"
                result["reason"] = "export_limit_reached"
            else:
                result["status"] = "completed"

            findings, assert_entries, compared, skipped = [], [], 0, 0
            candidates = []
            for export_name, (rva, forwarded) in named_exports:
                try:
                    section, export_rva = baseline.export_window(export_name, 32)
                except ScanGap:
                    skipped += 1
                    continue
                candidates.append((export_name, section, export_rva))
            candidates.sort(key=lambda item: (item[1].start, item[2]))
            groups = []
            for candidate in candidates:
                if (groups and candidate[1] is groups[-1][-1][1]
                        and candidate[2] + 32 - groups[-1][0][2] <= scanner.config.max_read_bytes):
                    groups[-1].append(candidate)
                else:
                    groups.append([candidate])
            result["read_groups"] = len(groups)
            for group in groups:
                section, start = group[0][1], group[0][2]
                end = group[-1][2] + 32
                if not covers(regions, row.base + start, row.base + end):
                    skipped += len(group)
                    continue
                expected_group = baseline.expected(section, start, end - start)
                live_group = await scanner.read(pid, sequence, row.base + start, end - start)
                for export_name, _, export_rva in group:
                    offset = export_rva - start
                    expected = expected_group[offset:offset + 32]
                    live = live_group[offset:offset + 32]
                    evidence = window_result(expected, live, baseline.mode, row.base + export_rva)
                    compared += 1
                    if evidence["status"] != "equal":
                        target = evidence.get("branch_target")
                        if target is not None:
                            target_module, target_rva = lookup_module(modules, target)
                            if target_module is not None:
                                evidence["branch_target_module"] = target_module
                                evidence["branch_target_rva"] = target_rva
                        finding = {"export": export_name, "rva": export_rva, **evidence}
                        findings.append(finding)
                    if KNOWN_ASSERTS.get(Path(row.path).name.casefold(), set()) and export_name in KNOWN_ASSERTS[Path(row.path).name.casefold()]:
                        assert_entries.append({"export": export_name, "rva": export_rva, **evidence})
            result.update(export_entries_compared=compared,
                          export_entries_skipped=skipped,
                          findings=findings)
            if assert_entries:
                result["assert_entries"] = assert_entries
    except (ProbeError, ScanGap, OSError, ValueError) as exc:
        result.update(status="gap", reason=str(exc) if isinstance(exc, ScanGap) else "mcp_or_local_gap")
        result["reason_code"] = str(exc) if isinstance(exc, (ProbeError, ScanGap)) else type(exc).__name__
    return result


async def live_scan(simcp, sha256, process_name, explicit_pid, workers, config_values):
    config = Config(**config_values)
    budget = Budget(config=config, started=time.monotonic())
    executable = trusted_executable(simcp, sha256)
    require(importlib.metadata.version("mcp") == SDK_VERSION, "unexpected_sdk_version")
    state = {"scanner": None}
    result = {"schema_version": 1, "research_only": True, "status": "failed",
              "coverage": "named_export_entries"}
    try:
        with open(os.devnull, "w") as errlog:
            logging.disable(logging.CRITICAL)
            with anyio.fail_after(config.total_seconds):
                params = StdioServerParameters(command=str(executable), args=[], cwd=str(executable.parent))
                async with stdio_client(params, errlog=errlog) as (read, write):
                    async with ClientSession(read, write,
                                             read_timeout_seconds=timedelta(seconds=config.rpc_seconds)) as session:
                        scanner = Scanner(session, config, budget)
                        state["scanner"] = scanner
                        catalogue = await scanner.handshake()
                        pid, sequence = await scanner.find_process(process_name, explicit_pid)
                        modules = await scanner.modules(pid, sequence)
                        regions, region_snapshots, region_totals = await scanner.executable_regions(pid, sequence)
                        worker_limit = asyncio.Semaphore(workers)
                        module_results = await asyncio.gather(*[
                            scan_module(scanner, pid, sequence, row, regions, modules, worker_limit)
                            for row in modules
                        ])
                        final_process = await scanner.call("get_process", {"pid": pid})
                        require(identity(final_process, pid) == (pid, sequence),
                                "process_identity_changed_after_scan")
                        final_modules = await scanner.modules(pid, sequence)
                        original = {row.key for row in modules}
                        final = {row.key for row in final_modules}
                        target_stable = original == final
                        status_counts = {}
                        for module_result in module_results:
                            status_counts[module_result["status"]] = status_counts.get(module_result["status"], 0) + 1
                        assert_results = []
                        expected_asserts = {
                            ("KernelBase.dll", "LoadLibraryExW"): "inline_candidate",
                            ("kernel32.dll", "WriteFile"): "inline_candidate",
                            ("kernel32.dll", "SetUnhandledExceptionFilter"): "entry_return_patch",
                        }
                        observed_asserts = {
                            (module_result["module"], entry["export"]): entry["status"]
                            for module_result in module_results
                            for entry in module_result.get("assert_entries", [])
                        }
                        for key, expected in expected_asserts.items():
                            observed = observed_asserts.get(key)
                            assert_results.append({
                                "module": key[0], "export": key[1],
                                "expected": expected, "observed": observed,
                                "passed": observed == expected,
                            })
                        require(all(item["passed"] for item in assert_results), "known_hook_assert_failed")
                        result.update(status="passed", catalogue_tools=catalogue, pid=pid,
                                      process_sequence_number=sequence,
                                      module_count=len(modules),
                                      runtime_executable_image_regions=len(regions),
                                      region_snapshot_count=region_snapshots,
                                      region_total_counts=region_totals,
                                      target_stable=target_stable,
                                      module_status_counts=status_counts,
                                      assert_validation=assert_results,
                                      modules=module_results)
    except (Exception, KeyboardInterrupt) as exc:
        exc = unwrap(exc)
        reason = "cancelled" if isinstance(exc, KeyboardInterrupt) else (
            str(exc) if isinstance(exc, (ProbeError, ScanGap)) else
            "transport_closed" if isinstance(exc, McpError) and exc.error.message == "Connection closed" else
            "transport_timeout" if isinstance(exc, TimeoutError) else "runtime_error")
        result.update(reason=reason)
        if not isinstance(exc, (ProbeError, ScanGap, KeyboardInterrupt)):
            result["error_type"] = type(exc).__name__
            if isinstance(exc, BaseExceptionGroup):
                leaves = []
                stack = [exc]
                while stack:
                    item = stack.pop()
                    if isinstance(item, BaseExceptionGroup):
                        stack.extend(item.exceptions)
                    else:
                        leaves.append(type(item).__name__)
                result["error_types"] = sorted(set(leaves))
    scanner = state.get("scanner")
    result.update(phase=scanner.phase if scanner else "preflight",
                  used_tools=scanner.used_tools if scanner else [],
                  budget={"rpc_limit": config.rpc_limit, "attempted_rpc": budget.calls,
                          "reply_bytes": budget.reply_bytes,
                          "total_reply_byte_limit": config.max_total_reply_bytes,
                          "memory_calls_possible": True, "memory_bytes_read": budget.memory_bytes,
                          "memory_calls": budget.memory_calls,
                          "max_read_size": budget.max_read_size,
                          "memory_byte_limit": config.max_memory_bytes,
                          "elapsed_seconds": round(time.monotonic() - budget.started, 3)})
    return result, 0 if result["status"] == "passed" else 2


app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def scan(
    simcp: Annotated[Path, typer.Option(exists=True, dir_okay=False, resolve_path=True)],
    sha256: Annotated[str, typer.Option()],
    process_name: Annotated[str, typer.Option()] = "WXWork.exe",
    pid: Annotated[int | None, typer.Option()] = None,
    workers: Annotated[int, typer.Option(min=1, max=8)] = 4,
    output: Annotated[Path, typer.Option(dir_okay=False, writable=True)] = Path(".codex-tracking/research/hook-detect-wxwork-2026-11-19.json"),
) -> None:
    """Run the bounded read-only WXWork export-entry research scan."""
    resolved_output = output if output.is_absolute() else ROOT / output
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    result, exit_code = asyncio.run(live_scan(simcp, sha256, process_name, pid, workers, {}))
    resolved_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    compact = {
        "status": result["status"], "reason": result.get("reason"), "pid": result.get("pid"),
        "modules": result.get("module_count"), "target_stable": result.get("target_stable"),
        "module_status_counts": result.get("module_status_counts"),
        "assert_validation": result.get("assert_validation"),
        "findings": [
            {"module": module["module"], **finding}
            for module in result.get("modules", [])
            for finding in module.get("findings", [])
        ][:30],
        "budget": result.get("budget"), "output": str(resolved_output),
    }
    print(json.dumps(compact, indent=2))
    raise typer.Exit(exit_code)


if __name__ == "__main__":
    app()
