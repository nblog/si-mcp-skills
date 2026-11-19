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

"""Read-only WXWork whole-executable-region diff research probe.

Patch discovery starts with disk/runtime code bytes, not import/export tables.
 Capstone classification runs only after a contiguous diff run is known.
"""

import asyncio
import importlib.metadata
import importlib.util
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import anyio
import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from scan_evidence import MAX_FILE_BYTES, ScanGap, classify_region_patch, diff_runs, load_baseline


ROOT = Path(__file__).resolve().parents[2]
TARGET_MODULES = ("KernelBase.dll", "kernel32.dll")
ASSERTS = {
    ("kernelbase.dll", "LoadLibraryExW"): "inline_candidate",
    ("kernel32.dll", "WriteFile"): "inline_candidate",
    ("kernel32.dll", "SetUnhandledExceptionFilter"): "entry_return_patch",
}


def load_probe_module():
    path = Path(__file__).with_name("01_wxwork_export_probe.py")
    spec = importlib.util.spec_from_file_location("wxwork_export_probe", path)
    loader = spec.loader if spec is not None else None
    if spec is None or loader is None:
        raise RuntimeError("research probe module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


probe = load_probe_module()


@dataclass
class Interval:
    start: int
    end: int


def executable_intersections(regions, start, end):
    result = []
    for region in regions:
        lo, hi = max(start, region.start), min(end, region.end)
        if lo < hi:
            if result and result[-1].end == lo:
                result[-1] = Interval(result[-1].start, hi)
            else:
                result.append(Interval(lo, hi))
    return result


def uncovered_runtime_exec(regions, module_start, module_end, backed_exec):
    runtime = executable_intersections(regions, module_start, module_end)
    uncovered = []
    for interval in runtime:
        cursor = interval.start
        for start, end in backed_exec:
            if end <= cursor:
                continue
            if start >= interval.end:
                break
            if start > cursor:
                uncovered.append(Interval(cursor, min(start, interval.end)))
            cursor = max(cursor, end)
            if cursor >= interval.end:
                break
        if cursor < interval.end:
            uncovered.append(Interval(cursor, interval.end))
    return uncovered


async def read_interval(scanner, pid, sequence, base, baseline, section, interval):
    expected = bytearray()
    live = bytearray()
    for offset in range(interval.start, interval.end, scanner.config.max_read_bytes):
        size = min(scanner.config.max_read_bytes, interval.end - offset)
        expected.extend(baseline.expected(section, offset - base, size))
        live.extend(await scanner.read(pid, sequence, offset, size))
    return bytes(expected), bytes(live)


async def scan_module(scanner, pid, sequence, row, regions):
    result = {
        "module": row.name,
        "path_sha256": probe.hashlib.sha256(row.path.encode("utf-8")).hexdigest(),
        "status": "gap",
    }
    try:
        path = Path(row.path)
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            raise ScanGap("disk_file_missing_or_oversize")
        baseline = await asyncio.to_thread(load_baseline, path, row.size, row.base)
        header_size = min(scanner.config.page_size, row.size)
        header = await scanner.read(pid, sequence, row.base, header_size)
        baseline.check_headers(header)

        disk_exec = [section for section in baseline.sections if section.executable]
        backed_exec = [(row.base + section.start, row.base + section.end) for section in disk_exec]
        uncovered = uncovered_runtime_exec(regions, row.base, row.base + row.size, backed_exec)
        patches, scanned, skipped = [], 0, 0
        section_results = []
        for section in disk_exec:
            section_result = {"rva": section.start, "disk_size": section.end - section.start,
                              "runtime_exec_bytes": 0, "status": "completed"}
            try:
                for interval in executable_intersections(regions, row.base + section.start,
                                                         row.base + section.end):
                    expected, live = await read_interval(scanner, pid, sequence,
                                                         row.base, baseline, section, interval)
                    scanned += len(live)
                    section_result["runtime_exec_bytes"] += len(live)
                    for low, high in diff_runs(expected, live):
                        relative = low + interval.start - row.base
                        finding = classify_region_patch(
                            expected[low:high], live[low:high], baseline.mode,
                            row.base + relative,
                        )
                        patches.append({"rva": relative, **finding})
            except (ScanGap, probe.ProbeError) as exc:
                section_result.update(status="gap", reason=str(exc))
                skipped += section.end - section.start
            section_results.append(section_result)

        result.update(status="completed", executable_sections=section_results,
                      executable_bytes_compared=scanned,
                      executable_bytes_gap=skipped,
                      runtime_exec_without_disk_exec=[{"rva": item.start - row.base,
                                                       "size": item.end - item.start}
                                                     for item in uncovered],
                      patches=patches)

        exports = {}
        for name, entries in baseline.exports.items():
            if len(entries) == 1:
                exports[name] = entries[0][0]
        assert_entries = []
        for (module_name, export_name), expected_status in ASSERTS.items():
            if module_name != row.name.casefold() or export_name not in exports:
                continue
            export_rva = exports[export_name]
            match = next((patch for patch in patches
                          if patch["rva"] <= export_rva < patch["rva"] + patch["size"]), None)
            assert_entries.append({
                "export": export_name,
                "rva": export_rva,
                "patch": match,
                "expected": expected_status,
                "observed": match["status"] if match else "no_patch_at_export",
                "passed": bool(match) and match["status"] == expected_status,
            })
        if assert_entries:
            result["assert_entries"] = assert_entries
    except (ScanGap, probe.ProbeError, OSError, ValueError) as exc:
        result.update(reason=str(exc) if isinstance(exc, ScanGap) else "mcp_or_local_gap",
                      reason_code=str(exc) if isinstance(exc, (ScanGap, probe.ProbeError))
                      else type(exc).__name__)
    return result


async def live_scan(simcp, sha256, process_name, pid, workers):
    config = probe.Config()
    budget = probe.Budget(config=config, started=time.monotonic())
    executable = probe.trusted_executable(simcp, sha256)
    probe.require(importlib.metadata.version("mcp") == probe.SDK_VERSION, "unexpected_sdk_version")
    state = {"scanner": None}
    result = {"schema_version": 1, "research_only": True, "status": "failed",
              "coverage": "disk_executable_sections_intersected_with_runtime_exec"}
    try:
        with open(os.devnull, "w") as errlog:
            logging.disable(logging.CRITICAL)
            with anyio.fail_after(config.total_seconds):
                params = StdioServerParameters(command=str(executable), args=[],
                                               cwd=str(executable.parent))
                async with stdio_client(params, errlog=errlog) as (read, write):
                    async with ClientSession(read, write,
                                             read_timeout_seconds=timedelta(seconds=config.rpc_seconds)) as session:
                        scanner = probe.Scanner(session, config, budget)
                        state["scanner"] = scanner
                        catalogue = await scanner.handshake()
                        pid, sequence = await scanner.find_process(process_name, pid)
                        modules = await scanner.modules(pid, sequence)
                        regions, snapshots, totals = await scanner.executable_regions(pid, sequence)
                        selected = [row for row in modules
                                    if row.name.casefold() in {name.casefold() for name in TARGET_MODULES}]
                        probe.require(len(selected) == len(TARGET_MODULES), "target_modules_not_found")
                        worker_limit = asyncio.Semaphore(workers)
                        async def one(row):
                            async with worker_limit:
                                return await scan_module(scanner, pid, sequence, row, regions)
                        module_results = await asyncio.gather(*(one(row) for row in selected))
                        final = await scanner.call("get_process", {"pid": pid})
                        probe.require(probe.identity(final, pid) == (pid, sequence),
                                      "process_identity_changed_after_scan")
                        final_modules = await scanner.modules(pid, sequence)
                        stable = {row.key for row in selected} <= {row.key for row in final_modules}
                        assert_results = [item for module in module_results
                                          for item in module.get("assert_entries", [])]
                        result.update(status="assert_pending", catalogue_tools=catalogue, pid=pid,
                                      process_sequence_number=sequence,
                                      module_count=len(modules), target_stable=stable,
                                      region_snapshot_count=snapshots,
                                      region_total_counts=totals,
                                      assert_validation=assert_results,
                                      modules=module_results)
                        probe.require(assert_results and all(item["passed"] for item in assert_results),
                                      "known_region_diff_assert_failed")
                        result["status"] = "passed"
    except (Exception, KeyboardInterrupt) as exc:
        exc = probe.unwrap(exc)
        if isinstance(exc, KeyboardInterrupt):
            reason = "cancelled"
        elif isinstance(exc, (probe.ProbeError, ScanGap)):
            reason = str(exc)
        elif isinstance(exc, TimeoutError):
            reason = "transport_timeout"
        else:
            reason = "runtime_error"
        result.update(reason=reason)
        if not isinstance(exc, (probe.ProbeError, ScanGap, KeyboardInterrupt)):
            result["error_type"] = type(exc).__name__
    scanner = state.get("scanner")
    result.update(phase=scanner.phase if scanner else "preflight",
                  used_tools=scanner.used_tools if scanner else [],
                  budget={"attempted_rpc": budget.calls, "reply_bytes": budget.reply_bytes,
                          "memory_calls": budget.memory_calls,
                          "memory_bytes_read": budget.memory_bytes,
                          "max_read_size": budget.max_read_size,
                          "elapsed_seconds": round(time.monotonic() - budget.started, 3)})
    return result, 0 if result["status"] == "passed" else 2


app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def scan(
    simcp: Annotated[Path, typer.Option(exists=True, dir_okay=False, resolve_path=True)],
    sha256: Annotated[str, typer.Option()],
    process_name: Annotated[str, typer.Option()] = "WXWork.exe",
    pid: Annotated[int | None, typer.Option()] = None,
    workers: Annotated[int, typer.Option(min=1, max=2)] = 2,
    output: Annotated[Path, typer.Option(dir_okay=False, writable=True)] = Path(
        ".codex-tracking/research/hook-detect-wxwork-region-diff-2026-11-19.json"
    ),
) -> None:
    """Run the bounded whole-code diff experiment."""
    destination = output if output.is_absolute() else ROOT / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    result, code = asyncio.run(live_scan(simcp, sha256, process_name, pid, workers))
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    patches = [
        {"module": module["module"], **patch}
        for module in result.get("modules", []) for patch in module.get("patches", [])
    ]
    print(json.dumps({
        "status": result["status"], "reason": result.get("reason"),
        "pid": result.get("pid"), "target_stable": result.get("target_stable"),
        "assert_validation": result.get("assert_validation"),
        "patch_count": len(patches), "patches": patches,
        "budget": result.get("budget"), "output": str(destination),
    }, indent=2))
    raise typer.Exit(code)


if __name__ == "__main__":
    app()
