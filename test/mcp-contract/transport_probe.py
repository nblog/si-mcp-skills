# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["mcp==1.30.0"]
# ///

"""Research-only stdio contract probe: metadata for this Python process only.

The caller supplies a reviewed absolute simcp.exe path and SHA-256. No memory
tool, arbitrary command, target PID, retry, or privilege option is exposed.
"""

import argparse
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
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError


SDK_VERSION = "1.30.0"
ALLOWED_TOOLS = frozenset({"get_system_info", "get_process", "get_process_modules"})
PAGE_ROWS = 16
MAX_RPC = 8
MAX_REPLY_BYTES = 2 * 1024 * 1024
MAX_TOTAL_REPLY_BYTES = 3 * 1024 * 1024
TOTAL_SECONDS = 30
RPC_SECONDS = 5
MAX_SNAPSHOT_AGE_SECONDS = 10


class ProbeError(ValueError):
    """A fixed, payload-free reason code suitable for the probe summary."""


def require(condition, reason):
    if not condition:
        raise ProbeError(reason)


def trusted_executable(path, expected_sha256):
    """Pin a reviewed local executable; never resolve it through PATH or data."""
    require(os.name == "nt", "windows_required")
    require(bool(re.fullmatch(r"[A-Za-z]:[\\/].+", str(path))), "local_absolute_path_required")
    require(path.name.lower() == "simcp.exe", "simcp_filename_required")
    require(bool(re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256)), "sha256_required")
    for part in (path, *path.parents):
        require(not (part.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT), "reparse_path_rejected")
    resolved = path.resolve(strict=True)
    require(resolved.is_file() and resolved.stat().st_size <= 16 * 1024 * 1024, "invalid_executable_file")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    require(digest == expected_sha256.lower(), "executable_hash_mismatch")
    return resolved, digest


@dataclass
class Budget:
    """Count attempted RPCs, accepted reply sizes, and one wall-clock deadline.

    Size checks run after SDK decoding; they are not a transport frame-size cap.
    This entry point has a fixed zero-byte, zero-call process-memory budget.
    """

    started: float = field(default_factory=time.monotonic)
    calls: int = 0
    reply_bytes: int = 0

    def remaining(self):
        remaining = TOTAL_SECONDS - (time.monotonic() - self.started)
        require(remaining > 0, "time_budget_exhausted")
        return min(RPC_SECONDS, remaining)

    def reserve(self):
        self.remaining()
        require(self.calls < MAX_RPC, "rpc_budget_exhausted")
        self.calls += 1

    def accept(self, reply):
        size = len(reply.model_dump_json().encode("utf-8"))
        require(size <= MAX_REPLY_BYTES, "reply_budget_exhausted")
        require(self.reply_bytes + size <= MAX_TOTAL_REPLY_BYTES, "total_reply_budget_exhausted")
        self.reply_bytes += size
        self.remaining()


def structured(reply):
    """Require the observed structured contract, even if JSON text is present."""
    require(reply.isError is False, "mcp_tool_error")
    require(isinstance(reply.structuredContent, dict), "structured_content_required")
    return reply.structuredContent


def fresh(record):
    require(record.get("updates_paused") is False, "provider_paused_or_unknown")
    stamp = record.get("snapshot_time")
    require(isinstance(stamp, str), "snapshot_time_required")
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        raise ProbeError("invalid_snapshot_time") from None
    require(parsed.tzinfo is not None, "snapshot_timezone_required")
    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    require(-5 <= age <= MAX_SNAPSHOT_AGE_SECONDS, "snapshot_outside_time_window")


def process_identity(record, pid):
    fresh(record)
    sequence = record.get("process_sequence_number")
    require(type(record.get("pid")) is int and record["pid"] == pid, "pid_mismatch")
    require(type(sequence) is int and sequence > 0, "invalid_process_sequence")
    return pid, sequence


@dataclass(frozen=True)
class ModuleIdentity:
    """Provider metadata identity, without claiming a verified PE baseline."""

    pid: int
    sequence: int
    base: int
    size: int
    file_path: str
    module_type: str
    load_time: str | None

    @classmethod
    def from_row(cls, row, identity):
        base_text, size = row.get("base_address"), row.get("size")
        require(isinstance(base_text, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]+", base_text)), "invalid_module_base")
        base = int(base_text, 16)
        require(type(size) is int and size > 0 and 0 < base < base + size <= 1 << 64, "invalid_module_range")
        path, kind, loaded = row.get("file_path"), row.get("type"), row.get("load_time")
        require(isinstance(path, str) and 0 < len(path) <= 32768, "module_path_required")
        require(isinstance(kind, str) and 0 < len(kind) <= 128, "module_type_required")
        require(loaded is None or isinstance(loaded, str), "invalid_module_load_time")
        return cls(*identity, base, size, path.casefold(), kind, loaded)

    def summary(self):
        return {"pid": self.pid, "process_sequence_number": self.sequence,
                "base_address": hex(self.base), "size": self.size,
                "file_path_sha256": hashlib.sha256(self.file_path.encode()).hexdigest(),
                "load_time_available": self.load_time is not None}


def module_page(record, identity):
    require(process_identity(record, identity[0]) == identity, "process_identity_changed")
    require(record.get("enumeration_complete") is True, "module_enumeration_incomplete")
    rows = record.get("modules")
    require(isinstance(rows, list) and 0 < len(rows) <= PAGE_ROWS, "invalid_module_page")
    for key, expected in (("count", len(rows)), ("offset", 0), ("limit", PAGE_ROWS)):
        require(type(record.get(key)) is int and record[key] == expected, "invalid_pagination")
    total = record.get("total_count")
    require(type(total) is int and total >= len(rows), "invalid_module_total")
    require(type(record.get("truncated")) is bool and record["truncated"] == (total > len(rows)), "invalid_truncation")
    require(all(isinstance(row, dict) for row in rows), "invalid_module_row")
    modules = tuple(ModuleIdentity.from_row(row, identity) for row in rows)
    require(len({m.base for m in modules}) == len(modules), "duplicate_module_base")
    return modules


class ReadOnlyProbe:
    """The sole tool-call gate allows fixed metadata requests for this process."""

    def __init__(self, session, budget):
        self.session, self.budget = session, budget
        self.pid = os.getpid()
        self.phase = "initialize"
        self.used_tools = []

    async def rpc(self, phase, operation):
        self.phase = phase
        self.budget.reserve()
        with anyio.fail_after(self.budget.remaining()):
            reply = await operation()
        self.budget.accept(reply)
        return reply

    async def call(self, name):
        require(name in ALLOWED_TOOLS, "tool_not_allowed")
        args = {} if name == "get_system_info" else {"pid": self.pid}
        if name == "get_process_modules":
            args.update(limit=PAGE_ROWS, offset=0)
        async def operation():
            self.used_tools.append(name)
            return await self.session.call_tool(name, args)

        return structured(await self.rpc(name, operation))

    async def run(self):
        init = await self.rpc("initialize", self.session.initialize)
        require(init.protocolVersion == "2025-11-25", "unexpected_protocol_version")
        listing = await self.rpc("tools/list", self.session.list_tools)
        require(listing.nextCursor is None, "tool_catalogue_incomplete")
        names = [tool.name for tool in listing.tools]
        require(len(set(names)) == len(names) and ALLOWED_TOOLS <= set(names), "required_tools_missing_or_duplicate")
        system = await self.call("get_system_info")
        fresh(system)
        require(type(system.get("schema_version")) is int and system["schema_version"] == 1, "unexpected_schema_version")
        # Allow one provider refresh for the newly started probe, within the deadline.
        await anyio.sleep(1.5)
        identity = process_identity(await self.call("get_process"), self.pid)
        first = module_page(await self.call("get_process_modules"), identity)
        second = module_page(await self.call("get_process_modules"), identity)
        require(first[0] in second, "module_identity_changed")
        require(process_identity(await self.call("get_process"), self.pid) == identity, "process_identity_changed")
        return {"protocol_version": init.protocolVersion, "catalogue_tools": len(names),
                "system_informer_version": system.get("system_informer_version"),
                "system_informer_elevated": system.get("system_informer_elevated"),
                "ksi_level": system.get("ksi_level"),
                "structured_content": True, "module_identity": first[0].summary(),
                "sampled_modules": len(first), "coverage": "bounded_module_metadata_sample",
                "module_identity_basis": "provider_metadata_only"}


async def live(executable, budget, state):
    with open(os.devnull, "w") as errlog:
        with anyio.fail_after(TOTAL_SECONDS):
            params = StdioServerParameters(command=str(executable), args=[], cwd=str(executable.parent))
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=RPC_SECONDS)) as session:
                    probe = ReadOnlyProbe(session, budget)
                    state["probe"] = probe
                    return await probe.run()


def reason_code(exc):
    if isinstance(exc, ProbeError):
        return str(exc)
    if isinstance(exc, BaseExceptionGroup):
        return reason_code(exc.exceptions[0])
    if isinstance(exc, TimeoutError):
        return "transport_timeout"
    if isinstance(exc, McpError):
        return "transport_closed" if exc.error.message == "Connection closed" else "mcp_request_failed"
    return "transport_or_runtime_error"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--simcp", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    budget, state = Budget(), {}
    result = {"schema_version": 1, "research_only": True, "status": "failed"}
    # The SDK's validation exceptions may embed a complete server message.
    # Emit only our fixed reason codes, never raw SDK/server stderr or traceback.
    logging.disable(logging.CRITICAL)
    try:
        version = importlib.metadata.version("mcp")
        require(version == SDK_VERSION, "unexpected_sdk_version")
        result["mcp_sdk"] = version
        executable, digest = trusted_executable(args.simcp, args.sha256)
        result["simcp_sha256"] = digest
        result.update(asyncio.run(live(executable, budget, state)))
        result["status"] = "passed"
    except (Exception, KeyboardInterrupt) as exc:
        result["reason"] = "cancelled" if isinstance(exc, KeyboardInterrupt) else reason_code(exc)
    probe = state.get("probe")
    result.update(phase=probe.phase if probe else "preflight", used_tools=probe.used_tools if probe else [],
                  budget={"rpc_limit": MAX_RPC, "attempted_rpc": budget.calls,
                          "reply_byte_limit": MAX_REPLY_BYTES, "total_reply_byte_limit": MAX_TOTAL_REPLY_BYTES,
                          "accepted_reply_bytes": budget.reply_bytes, "deadline_seconds": TOTAL_SECONDS,
                          "rpc_timeout_seconds": RPC_SECONDS, "module_page_rows": PAGE_ROWS,
                          "max_snapshot_age_seconds": MAX_SNAPSHOT_AGE_SECONDS,
                          "memory_calls": 0, "memory_bytes": 0,
                          "elapsed_seconds": round(time.monotonic() - budget.started, 3)})
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    sys.exit(main())
