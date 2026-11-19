import asyncio
import hashlib
import importlib.metadata
import itertools
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

import anyio
from config import ScanConfig
from mcp import ClientSession
from mcp.types import CallToolResult

from .budget import Budget
from .errors import PhUtilsError, require
from .models import MemoryRegion, ModuleRecord, ProcessRecord

SDK_VERSION = "1.30.0"
PROTOCOL_VERSION = "2025-11-25"
DATA_SCHEMA_VERSION = 1
SCAN_TOOLS = {
    "get_process",
    "list_processes",
    "get_process_modules",
    "get_process_memory_regions",
    "read_process_memory",
}
VERIFY_TOOLS = {"get_system_info", "get_process", "get_process_modules"}


def structured(reply: CallToolResult) -> dict:
    require(reply.isError is False, "mcp_tool_error")
    require(isinstance(reply.structuredContent, dict), "structured_content_required")
    return reply.structuredContent


def fresh(record: dict, config: ScanConfig) -> None:
    require(record.get("updates_paused") is False, "provider_paused_or_unknown")
    stamp = record.get("snapshot_time")
    require(isinstance(stamp, str), "snapshot_time_required")
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        raise PhUtilsError("invalid_snapshot_time") from None
    require(parsed.tzinfo is not None, "snapshot_timezone_required")
    age = (datetime.now(UTC) - parsed).total_seconds()
    require(-5 <= age <= config.max_snapshot_age_seconds, "snapshot_outside_time_window")


def parse_address(value: object) -> int:
    require(isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]+", value)),
            "invalid_address")
    return int(value, 16)


def process_identity(record: dict, pid: int) -> tuple[int, int]:
    require(type(record.get("pid")) is int and record["pid"] == pid, "pid_mismatch")
    sequence = record.get("process_sequence_number")
    require(type(sequence) is int and sequence > 0, "invalid_process_sequence")
    return pid, sequence


def trusted_executable(path: Path, expected_sha256: str) -> Path:
    require(os.name == "nt", "windows_required")
    require(bool(re.fullmatch(r"[A-Za-z]:[\\/].+", str(path))), "local_absolute_path_required")
    require(path.name.casefold() == "simcp.exe", "simcp_filename_required")
    require(bool(re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256)), "sha256_required")
    for item in (path, *path.parents):
        require(not (item.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),
                "reparse_path_rejected")
    resolved = path.resolve(strict=True)
    require(resolved.is_file() and resolved.stat().st_size <= 16 * 1024 * 1024,
            "invalid_executable_file")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    require(digest == expected_sha256.casefold(), "executable_hash_mismatch")
    return resolved


def require_sdk() -> None:
    require(importlib.metadata.version("mcp") == SDK_VERSION, "unexpected_sdk_version")


def parse_module(row: dict) -> ModuleRecord:
    name, path, kind = row.get("name"), row.get("file_path"), row.get("type")
    size, load_time = row.get("size"), row.get("load_time")
    require(isinstance(name, str) and bool(name), "invalid_module_name")
    require(isinstance(path, str) and Path(path).is_absolute(), "invalid_module_path")
    require(isinstance(kind, str), "invalid_module_type")
    require(type(size) is int and size > 0, "invalid_module_size")
    require(isinstance(load_time, str) or load_time is None, "invalid_module_load_time")
    return ModuleRecord(name, path, kind, parse_address(row.get("base_address")), size, load_time)


class SystemInformerClient:
    def __init__(self, session: ClientSession, config: ScanConfig, budget: Budget,
                 memory_allowed: bool = True):
        self.session = session
        self.config = config
        self.budget = budget
        self.memory_allowed = memory_allowed
        self.allowed_tools = SCAN_TOOLS if memory_allowed else VERIFY_TOOLS
        self.phase = "initialize"
        self.used_tools: list[str] = []
        self.memory_lock = asyncio.Lock()

    async def rpc(self, phase: str, operation):
        self.phase = phase
        self.budget.reserve_rpc()
        with anyio.fail_after(self.budget.remaining()):
            return await operation()

    async def call(self, name: str, args: dict) -> dict:
        require(name in self.allowed_tools, "tool_not_allowed")

        async def operation():
            self.used_tools.append(name)
            return await self.session.call_tool(name, args)

        reply = await self.rpc(name, operation)
        self.budget.accept_reply(reply)
        return structured(reply)

    async def handshake(self) -> int:
        initialized = await self.rpc("initialize", self.session.initialize)
        require(initialized.protocolVersion == PROTOCOL_VERSION, "unexpected_protocol_version")
        listing = await self.rpc("tools/list", self.session.list_tools)
        require(listing.nextCursor is None, "tool_catalogue_incomplete")
        names = [tool.name for tool in listing.tools]
        require(len(names) == len(set(names)) and self.allowed_tools <= set(names),
                "required_tools_missing_or_duplicate")
        return len(names)

    async def system_info(self) -> dict:
        record = await self.call("get_system_info", {})
        fresh(record, self.config)
        require(type(record.get("schema_version")) is int
                and record["schema_version"] == DATA_SCHEMA_VERSION,
                "unexpected_schema_version")
        return record

    async def find_process(self, process_name: str, explicit_pid: int | None = None) -> ProcessRecord:
        require(bool(re.fullmatch(r"[^/\\:?*\"<>|]{1,128}", process_name)), "invalid_process_name")
        record = await self.call("list_processes", {"name_contains": process_name, "limit": 100})
        fresh(record, self.config)
        rows = record.get("processes")
        require(isinstance(rows, list), "invalid_process_rows")
        candidates: list[tuple[datetime, ProcessRecord]] = []
        for row in rows:
            require(isinstance(row, dict), "invalid_process_row")
            require(row.get("name", "").casefold() == process_name.casefold(),
                    "process_name_not_exact")
            pid, sequence = row.get("pid"), row.get("process_sequence_number")
            name, start = row.get("name"), row.get("start_time")
            require(type(pid) is int and pid > 0 and type(sequence) is int and sequence > 0,
                    "invalid_process_identity")
            require(isinstance(name, str) and isinstance(start, str), "invalid_process_metadata")
            candidates.append((datetime.fromisoformat(start),
                               ProcessRecord(pid, sequence, name, start)))
        if explicit_pid is not None:
            matches = [item for item in candidates if item[1].pid == explicit_pid]
            require(len(matches) == 1, "explicit_pid_not_found")
            selected = matches[0][1]
        else:
            require(candidates, "process_not_found")
            selected = min(candidates, key=lambda item: (item[0], item[1].pid))[1]
        current = await self.call("get_process", {"pid": selected.pid})
        fresh(current, self.config)
        require(process_identity(current, selected.pid) == (selected.pid, selected.sequence),
                "process_identity_changed")
        return selected

    async def modules(self, process: ProcessRecord) -> list[ModuleRecord]:
        rows: list[ModuleRecord] = []
        offset = 0
        while True:
            record = await self.call("get_process_modules",
                                     {"pid": process.pid, "limit": 200, "offset": offset})
            fresh(record, self.config)
            require(process_identity(record, process.pid) == (process.pid, process.sequence),
                    "process_identity_changed")
            require(record.get("enumeration_complete") is True, "module_enumeration_incomplete")
            require(record.get("offset") == offset, "module_page_offset_mismatch")
            page, total, truncated = record.get("modules"), record.get("total_count"), record.get("truncated")
            require(isinstance(page, list) and type(total) is int and type(truncated) is bool,
                    "invalid_module_page")
            require(truncated == (total > offset + len(page)), "invalid_module_truncation")
            rows.extend(parse_module(row) for row in page)
            offset += len(page)
            if offset >= total:
                break
            require(offset <= self.config.max_modules + 200, "module_budget_exhausted")
        require(0 < len(rows) <= self.config.max_modules, "module_count_boundary")
        require(len({row.base for row in rows}) == len(rows), "duplicate_module_base")
        return rows

    async def executable_regions(self, process: ProcessRecord) -> tuple[list[MemoryRegion], int, list[int]]:
        regions: list[MemoryRegion] = []
        snapshots: set[int] = set()
        totals: set[int] = set()
        offset = 0
        while True:
            record = await self.call("get_process_memory_regions",
                                     {"pid": process.pid, "limit": 200, "offset": offset})
            fresh(record, self.config)
            require(process_identity(record, process.pid) == (process.pid, process.sequence),
                    "process_identity_changed")
            snapshot = record.get("snapshot_id")
            require(type(snapshot) is int, "invalid_region_snapshot")
            snapshots.add(snapshot)
            require(record.get("offset") == offset, "region_page_offset_mismatch")
            page, total, truncated = record.get("regions"), record.get("total_count"), record.get("truncated")
            require(isinstance(page, list) and type(total) is int and type(truncated) is bool,
                    "invalid_region_page")
            totals.add(total)
            require(truncated == (total > offset + len(page)), "invalid_region_truncation")
            for row in page:
                require(isinstance(row, dict), "invalid_region_row")
                size, protection = row.get("size"), row.get("protection")
                require(type(size) is int and size > 0, "invalid_region_size")
                require(isinstance(protection, str) or protection is None,
                        "invalid_region_protection")
                if row.get("state") == "commit" and row.get("type") == "image":
                    start = parse_address(row.get("base_address"))
                    regions.append(MemoryRegion(start, start + size, "X" in (protection or "")))
            offset += len(page)
            if offset >= total:
                break
        regions.sort(key=lambda region: region.start)
        require(all(left.end <= right.start for left, right in itertools.pairwise(regions)),
                "overlapping_or_unsorted_regions")
        return ([region for region in regions if region.executable], len(snapshots), sorted(totals))

    async def read_memory(self, process: ProcessRecord, address: int, size: int) -> bytes:
        require(self.memory_allowed, "memory_reads_not_allowed")
        self.budget.reserve_memory(size)
        async with self.memory_lock:
            record = await self.call("read_process_memory",
                                     {"pid": process.pid,
                                      "process_sequence_number": process.sequence,
                                      "address": hex(address), "size": size})
        fresh(record, self.config)
        require(process_identity(record, process.pid) == (process.pid, process.sequence),
                "process_identity_changed")
        require(parse_address(record.get("address")) == address, "read_address_mismatch")
        require(record.get("size") == size, "read_size_mismatch")
        payload = record.get("hex")
        require(isinstance(payload, str) and len(payload) == 2 * size
                and bool(re.fullmatch(r"[0-9a-fA-F]+", payload)), "read_payload_invalid")
        return bytes.fromhex(payload)

