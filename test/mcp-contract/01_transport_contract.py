# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["mcp==1.30.0", "lief==1.0.0", "capstone==5.0.9"]
# ///

"""Offline regressions for the read-only research probe's actual trust boundaries.

All MCP records are synthetic. No server, target process, or memory tool is used.
Run from the repository root; the live transport experiment is a separate step.
"""

import copy
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import anyio
from mcp import types
from mcp.types import CallToolResult, TextContent


import replay_probe as offline
import transport_probe as transport


IDENTITY = (1234, 5678)


def page():
    return {"pid": IDENTITY[0], "process_sequence_number": IDENTITY[1],
            "snapshot_time": datetime.now(timezone.utc).isoformat(), "updates_paused": False,
            "enumeration_complete": True, "count": 1, "total_count": 2,
            "offset": 0, "limit": transport.PAGE_ROWS, "truncated": True,
            "modules": [{"name": "same.dll", "base_address": "0x10000000",
                         "size": 4096, "file_path": "C:/fixture/same.dll",
                         "type": "module", "load_time": "2026-11-18T08:00:00Z"}]}


class ContractTests(unittest.TestCase):
    """Reject stale, ambiguous, partial, or unstructured provider metadata."""

    def test_structured_wins_over_conflicting_text(self):
        reply = CallToolResult(structuredContent={"pid": 1}, content=[TextContent(type="text", text='{"pid":2}')])
        self.assertEqual(transport.structured(reply), {"pid": 1})

    def test_errors_and_text_only_do_not_become_success(self):
        for reply in (CallToolResult(isError=True, structuredContent={}, content=[]),
                      CallToolResult(content=[TextContent(type="text", text="{}")])):
            with self.subTest(reply=reply), self.assertRaises(transport.ProbeError):
                transport.structured(reply)

    def test_process_identity_and_provider_freshness(self):
        for key, value in (("pid", 4321), ("pid", True), ("process_sequence_number", True),
                           ("process_sequence_number", 0), ("updates_paused", True),
                           ("snapshot_time", "2026-11-18T09:00:00"),
                           ("snapshot_time", "2000-01-01T00:00:00Z")):
            record = page()
            record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(transport.ProbeError):
                transport.module_page(record, IDENTITY)

    def test_bounded_page_does_not_claim_complete_coverage(self):
        self.assertEqual(len(transport.module_page(page(), IDENTITY)), 1)
        for key, value in (("count", 2), ("limit", 200), ("offset", 1),
                           ("total_count", 0), ("truncated", False), ("enumeration_complete", False)):
            record = page()
            record[key] = value
            with self.subTest(key=key), self.assertRaises(transport.ProbeError):
                transport.module_page(record, IDENTITY)

    def test_same_name_does_not_identify_same_module(self):
        first = transport.module_page(page(), IDENTITY)[0]
        for key, value in (("base_address", "0x7ffb10000000"), ("size", 8192),
                           ("file_path", "C:/other/same.dll"), ("type", "wow64_module"),
                           ("load_time", "2026-11-18T08:00:01Z")):
            record = page()
            record["modules"][0][key] = value
            with self.subTest(key=key):
                self.assertNotEqual(first, transport.module_page(record, IDENTITY)[0])

    def test_invalid_and_duplicate_address_ranges(self):
        for key, value in (("base_address", "not_an_address"), ("size", True), ("size", -1),
                           ("base_address", "0xffffffffffffffff")):
            record = page()
            record["modules"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(transport.ProbeError):
                transport.module_page(record, IDENTITY)
        record = page()
        record["modules"].append(copy.deepcopy(record["modules"][0]))
        record.update(count=2, truncated=False)
        with self.assertRaisesRegex(transport.ProbeError, "duplicate_module_base"):
            transport.module_page(record, IDENTITY)

    def test_executable_pin_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "simcp.exe"
            exe.write_bytes(b"synthetic, never executed")
            with self.assertRaisesRegex(transport.ProbeError, "executable_hash_mismatch"):
                transport.trusted_executable(exe, "0" * 64)
        with self.assertRaises(transport.ProbeError):
            transport.trusted_executable(Path("simcp.exe"), "0" * 64)

    def test_budget_limits(self):
        budget = transport.Budget()
        for _ in range(transport.MAX_RPC):
            budget.reserve()
        with self.assertRaisesRegex(transport.ProbeError, "rpc_budget_exhausted"):
            budget.reserve()
        with self.assertRaisesRegex(transport.ProbeError, "time_budget_exhausted"):
            transport.Budget(started=time.monotonic() - 31).reserve()
        reply = CallToolResult(structuredContent={"synthetic": "x" * 512}, content=[])
        with patch.object(transport, "MAX_REPLY_BYTES", 128), self.assertRaisesRegex(transport.ProbeError, "reply_budget_exhausted"):
            transport.Budget().accept(reply)
        with patch.object(transport, "MAX_TOTAL_REPLY_BYTES", 128), self.assertRaisesRegex(transport.ProbeError, "total_reply_budget_exhausted"):
            transport.Budget().accept(reply)

    def test_synthetic_memory_replay_length_and_identity(self):
        record = {"pid": 1, "process_sequence_number": 2, "address": "0x1000", "size": 65535, "hex": "90" * 65535}
        with patch.object(sys, "stdin", io.StringIO(json.dumps(record))):
            self.assertEqual(len(offline.read_mcp_reply(0x1000, 65535, 1, 2)), 65535)
        for key, value in (("hex", "90"), ("process_sequence_number", 3), ("address", "0x1001")):
            broken = record | {key: value}
            with self.subTest(key=key), patch.object(sys, "stdin", io.StringIO(json.dumps(broken))), self.assertRaises(ValueError):
                offline.read_mcp_reply(0x1000, 65535, 1, 2)

    def test_65536_rejected_at_offline_cli_entry(self):
        with patch.object(sys, "argv", ["replay_probe.py", "unused.dll", "unused", "--size", "65536"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                offline.main()
        self.assertEqual(raised.exception.code, 2)


class GateTests(unittest.IsolatedAsyncioTestCase):
    """Check that forbidden or over-budget requests never reach the SDK sender."""

    async def test_only_metadata_tools_for_self(self):
        session = AsyncMock()
        session.call_tool.return_value = CallToolResult(structuredContent={}, content=[])
        probe = transport.ReadOnlyProbe(session, transport.Budget())
        for tool in ("read_process_memory", "terminate_process", "create_process_minidump", "unknown"):
            with self.assertRaisesRegex(transport.ProbeError, "tool_not_allowed"):
                await probe.call(tool)
        session.call_tool.assert_not_called()
        await probe.call("get_process_modules")
        session.call_tool.assert_awaited_once_with("get_process_modules", {"pid": os.getpid(), "limit": 16, "offset": 0})

    async def test_budget_denial_precedes_send_and_timeout_cancels(self):
        session = AsyncMock()
        probe = transport.ReadOnlyProbe(session, transport.Budget(calls=transport.MAX_RPC))
        with self.assertRaisesRegex(transport.ProbeError, "rpc_budget_exhausted"):
            await probe.call("get_process")
        session.call_tool.assert_not_called()
        self.assertEqual(probe.used_tools, [])
        probe = transport.ReadOnlyProbe(session, transport.Budget())
        with patch.object(transport, "RPC_SECONDS", 0.01), self.assertRaises(TimeoutError):
            await probe.rpc("synthetic_wait", lambda: anyio.sleep(10))

    async def check_pipeline(self, change_module=False):
        session = AsyncMock()
        session.initialize.return_value = types.InitializeResult(
            protocolVersion="2025-11-25", capabilities=types.ServerCapabilities(),
            serverInfo=types.Implementation(name="offline-fixture", version="1"))
        session.list_tools.return_value = types.ListToolsResult(tools=[
            types.Tool(name=name, inputSchema={"type": "object"}) for name in transport.ALLOWED_TOOLS])
        pages = 0

        async def respond(name, args):
            nonlocal pages
            record = page()
            record["pid"] = os.getpid()
            if name == "get_system_info":
                record["schema_version"] = 1
            if name == "get_process_modules":
                pages += 1
                if change_module and pages == 2:
                    record["modules"][0]["base_address"] = "0x20000000"
            return CallToolResult(structuredContent=record, content=[])

        session.call_tool.side_effect = respond
        probe = transport.ReadOnlyProbe(session, transport.Budget())
        # Skip only the provider-refresh delay; the complete protocol path runs.
        with patch.object(transport.anyio, "sleep", new=AsyncMock()):
            if change_module:
                with self.assertRaisesRegex(transport.ProbeError, "module_identity_changed"):
                    await probe.run()
                self.assertEqual(probe.budget.calls, 6)
            else:
                result = await probe.run()
                self.assertEqual(result["coverage"], "bounded_module_metadata_sample")
                self.assertTrue(result["structured_content"])
                self.assertEqual(probe.budget.calls, 7)
        self.assertTrue(set(probe.used_tools) <= transport.ALLOWED_TOOLS)

    async def test_complete_synthetic_pipeline(self):
        await self.check_pipeline()

    async def test_changed_module_stops_pipeline(self):
        await self.check_pipeline(change_module=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
