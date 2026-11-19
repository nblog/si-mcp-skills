import asyncio
import hashlib
import logging
import os
from datetime import timedelta
from pathlib import Path

import anyio
from config import ScanConfig, TransportConfig
from detect.eat import scan_eat
from detect.iat import DependencyResolver, scan_iat
from detect.inline import InlineGap, classify_patch, diff_runs
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from pe.baseline import BaselineError, load_baseline
from pe.regions import (
    executable_intersections,
    read_region,
    runtime_exec_without_disk_exec,
)
from ph_utils.budget import Budget
from ph_utils.errors import PhUtilsError, require, unwrap
from ph_utils.mcp import SystemInformerClient, require_sdk, trusted_executable
from ph_utils.models import ModuleRecord, ProcessRecord

PHASES = ("inline", "eat", "iat")


def path_digest(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()


def export_attribution(baseline, patch_rva: int) -> dict | None:
    entries = [entry for entry in baseline.export_entries
               if entry.address <= patch_rva and entry.name]
    if not entries:
        return None
    nearest = max(entries, key=lambda entry: entry.address)
    if nearest.address == patch_rva:
        return {"export": nearest.name, "ordinal": nearest.ordinal, "offset": 0}
    newer = [entry for entry in baseline.export_entries
             if entry.address > patch_rva and entry.name]
    if newer and min(newer, key=lambda entry: entry.address).address <= patch_rva + 512:
        return {"export": nearest.name, "ordinal": nearest.ordinal,
                "offset": patch_rva - nearest.address, "attribution": "nearest_export"}
    return None


async def scan_inline(client: SystemInformerClient, process: ProcessRecord,
                      module: ModuleRecord, baseline, regions) -> dict:
    executable_sections = [section for section in baseline.sections if section.executable]
    uncovered = runtime_exec_without_disk_exec(regions, module, executable_sections)
    patches: list[dict] = []
    section_results: list[dict] = []
    compared = gap = 0
    for section in executable_sections:
        result = {"rva": section.start, "disk_size": section.end - section.start,
                  "runtime_exec_bytes": 0, "status": "completed"}
        try:
            for interval in executable_intersections(regions, module.base + section.start,
                                                     module.base + section.end):
                expected, live = await read_region(client, process, module, baseline,
                                                   section, interval)
                compared += len(live)
                result["runtime_exec_bytes"] += len(live)
                for low, high in diff_runs(expected, live):
                    relative = low + interval.start - module.base
                    evidence = classify_patch(expected[low:high], live[low:high],
                                              baseline.mode, module.base + relative)
                    patches.append({
                        "rva": relative,
                        **evidence,
                        **({"export_attribution": export_attribution(baseline, relative)}
                           if export_attribution(baseline, relative) else {}),
                    })
        except (BaselineError, InlineGap, PhUtilsError) as exc:
            result.update(status="gap", reason=str(exc))
            gap += section.end - section.start
        section_results.append(result)
    return {
        "status": "equal" if not patches and gap == 0 else
                  ("modified" if patches and gap == 0 else "partial"),
        "executable_sections": section_results,
        "executable_bytes_compared": compared,
        "executable_bytes_gap": gap,
        "runtime_exec_without_disk_exec": [
            {"rva": interval.start - module.base, "size": interval.end - interval.start}
            for interval in uncovered
        ],
        "patches": patches,
    }


async def scan_module(client: SystemInformerClient, process: ProcessRecord,
                      module: ModuleRecord, regions, resolver: DependencyResolver | None,
                      phases: set[str]) -> dict:
    result = {
        "module": module.name,
        "type": module.kind,
        "path_sha256": path_digest(module.path),
        "status": "gap",
        "reason": None,
    }
    try:
        path = Path(module.path)
        if not path.is_file():
            raise BaselineError("disk_file_missing")
        baseline = await asyncio.to_thread(load_baseline, path, module.size, module.base)
        result["disk_sha256"] = baseline.file_sha256
        header = await client.read_memory(process, module.base,
                                          min(client.config.page_size, module.size))
        baseline.check_headers(header)
        result["baseline"] = {
            "status": "paired",
            "machine": "i386" if baseline.mode == 4 else "amd64",
            "disk_sha256": baseline.file_sha256,
        }
        if "inline" in phases:
            result["inline"] = await scan_inline(client, process, module, baseline, regions)
        if "eat" in phases:
            result["eat"] = await scan_eat(client, process, module, baseline)
        if "iat" in phases:
            if resolver is None:
                raise PhUtilsError("iat_resolver_missing")
            result["iat"] = await scan_iat(client, process, module, baseline, resolver)
        statuses = [
            phase_result["status"] for phase_result in
            (result.get("inline"), result.get("eat"), result.get("iat"))
            if isinstance(phase_result, dict)
        ]
        # `inline=modified` and `eat=modified` are completed phases with findings.
        # Unknown/unread table or region evidence is what makes a module partial.
        incomplete = {"partial", "partial_unknown", "modified_or_gap", "gap"}
        result["status"] = ("gap" if "gap" in statuses else
                            "partial" if any(status in incomplete for status in statuses)
                            else "completed")
    except (BaselineError, InlineGap, PhUtilsError, OSError, ValueError) as exc:
        result.update(status="gap", reason=str(exc),
                      reason_code=type(exc).__name__)
    return result


def choose_modules(modules: list[ModuleRecord], requested: list[str], all_modules: bool) -> list[ModuleRecord]:
    if all_modules:
        return modules
    selected: list[ModuleRecord] = []
    for selector in requested:
        name, separator, base_text = selector.rpartition("@")
        if separator:
            try:
                base = int(base_text, 0)
            except ValueError as exc:
                raise PhUtilsError("invalid_module_base") from exc
            matches = [row for row in modules
                       if row.name.casefold() == name.casefold() and row.base == base]
        else:
            matches = [row for row in modules if row.name.casefold() == selector.casefold()]
            if len(matches) > 1:
                raise PhUtilsError("ambiguous_module_name_base_required")
        if len(matches) != 1:
            raise PhUtilsError("module_not_found:" + selector)
        selected.append(matches[0])
    return selected


async def run_verified_scan(client: SystemInformerClient, process_name: str, pid: int | None,
                            requested_modules: list[str], all_modules: bool, phases: set[str],
                            workers: int) -> dict:
    process = await client.find_process(process_name, pid)
    modules = await client.modules(process)
    selected = choose_modules(modules, requested_modules, all_modules)
    regions, region_snapshots, region_totals = await client.executable_regions(process)
    resolvers: dict[str, DependencyResolver] = {}
    if "iat" in phases:
        kinds = {row.kind for row in selected}
        for kind in kinds:
            resolver = DependencyResolver(modules, kind)
            await resolver.build_export_index(workers=min(workers, 4))
            resolvers[kind] = resolver
    semaphore = asyncio.Semaphore(workers)

    async def scan_one(row: ModuleRecord):
        async with semaphore:
            return await scan_module(client, process, row, regions,
                                     resolvers.get(row.kind), phases)

    module_results = await asyncio.gather(*(scan_one(row) for row in selected))
    final_process = await client.call("get_process", {"pid": process.pid})
    from ph_utils.mcp import fresh, process_identity
    fresh(final_process, client.config)
    if process_identity(final_process, process.pid) != (process.pid, process.sequence):
        raise PhUtilsError("process_identity_changed_after_scan")
    final_modules = await client.modules(process)
    final_identities = {row.identity for row in final_modules}
    stable = all(row.identity in final_identities for row in selected)
    counts: dict[str, int] = {}
    for item in module_results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "pid": process.pid,
        "process_sequence_number": process.sequence,
        "process_name": process.name,
        "process_start_time": process.start_time,
        "module_count": len(modules),
        "selected_module_count": len(selected),
        "module_status_counts": counts,
        "target_stable": stable,
        "region_snapshot_count": region_snapshots,
        "region_total_counts": region_totals,
        "modules": module_results,
    }


async def live_scan(executable: Path, sha256: str, process_name: str, pid: int | None,
                    requested_modules: list[str], all_modules: bool, phases: set[str],
                    workers: int) -> tuple[dict, Budget]:
    config = ScanConfig()
    budget = Budget(config)
    resolved = trusted_executable(executable, sha256)
    require_sdk()
    state = {"client": None}
    result = {"schema_version": 1, "skill": "hook-detect", "status": "failed",
              "coverage_semantics": "region-first-eat-semantic-iat"}
    try:
        # One tiny blocking open for the devnull sink keeps server stderr out of logs.
        with open(os.devnull, "w") as error_log:  # noqa: ASYNC230
            logging.disable(logging.CRITICAL)
            with anyio.fail_after(config.total_seconds):
                params = StdioServerParameters(command=str(resolved), args=[],
                                               cwd=str(resolved.parent))
                async with stdio_client(params, errlog=error_log) as (read, write):  # noqa: SIM117
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(
                            seconds=config.rpc_seconds)) as session:
                        client = SystemInformerClient(session, config, budget, memory_allowed=True)
                        state["client"] = client
                        catalogue = await client.handshake()
                        scanned = await run_verified_scan(client, process_name, pid,
                                                          requested_modules, all_modules,
                                                          phases, workers)
                        result.update(status="passed", catalogue_tools=catalogue, **scanned)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001
        exception = unwrap(exc)
        if isinstance(exception, KeyboardInterrupt):
            reason = "cancelled"
        elif isinstance(exception, (PhUtilsError, BaselineError, InlineGap)):
            reason = str(exception)
        elif isinstance(exception, TimeoutError):
            reason = "transport_timeout"
        elif isinstance(exception, McpError) and exception.error.message == "Connection closed":
            reason = "transport_closed"
        else:
            reason = "runtime_error"
        result.update(reason=reason)
        if not isinstance(exception, (PhUtilsError, BaselineError, InlineGap, KeyboardInterrupt)):
            result["error_type"] = type(exception).__name__
    client = state.get("client")
    result.update(phase=client.phase if client else "preflight",
                  used_tools=client.used_tools if client else [])
    return result, budget


async def verify_transport(executable: Path, sha256: str) -> tuple[dict, Budget]:
    config = TransportConfig()
    budget = Budget(config)
    resolved = trusted_executable(executable, sha256)
    require_sdk()
    state = {"client": None}
    result = {"schema_version": 1, "skill": "hook-detect", "status": "failed",
              "scope": "self_metadata_only"}
    try:
        # One tiny blocking open for the devnull sink keeps server stderr out of logs.
        with open(os.devnull, "w") as error_log:  # noqa: ASYNC230
            logging.disable(logging.CRITICAL)
            with anyio.fail_after(config.total_seconds):
                params = StdioServerParameters(command=str(resolved), args=[],
                                               cwd=str(resolved.parent))
                async with stdio_client(params, errlog=error_log) as (read, write):  # noqa: SIM117
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(
                            seconds=config.rpc_seconds)) as session:
                        client = SystemInformerClient(session, config, budget, memory_allowed=False)
                        state["client"] = client
                        catalogue = await client.handshake()
                        info = await client.system_info()
                        await anyio.sleep(1.5)
                        process = ProcessRecord(os.getpid(), 0, "self", "")
                        first_record = await client.call("get_process", {"pid": process.pid})
                        from ph_utils.mcp import fresh, process_identity
                        fresh(first_record, config)
                        identity = process_identity(first_record, process.pid)
                        process = ProcessRecord(process.pid, identity[1], "self", "")
                        first = await client.modules(process)
                        second = await client.modules(process)
                        require(first[0] in second, "self_module_identity_changed")
                        final = await client.call("get_process", {"pid": process.pid})
                        fresh(final, config)
                        require(process_identity(final, process.pid) == identity,
                                "self_process_identity_changed")
                        result.update(status="passed", catalogue_tools=catalogue,
                                      structured_content=True,
                                      system_informer_version=info.get("system_informer_version"),
                                      system_informer_elevated=info.get("system_informer_elevated"),
                                      ksi_level=info.get("ksi_level"),
                                      sampled_modules=min(len(second), 16),
                                      module_identity_basis="provider_metadata_only")
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001
        exception = unwrap(exc)
        result["reason"] = ("cancelled" if isinstance(exception, KeyboardInterrupt)
                            else str(exception) if isinstance(exception, PhUtilsError)
                            else "runtime_error")
        if not isinstance(exception, (PhUtilsError, KeyboardInterrupt)):
            result["error_type"] = type(exception).__name__
    client = state.get("client")
    result.update(phase=client.phase if client else "preflight",
                  used_tools=client.used_tools if client else [])
    return result, budget


def compact_summary(result: dict, output: Path) -> dict:
    inline_findings = []
    for module in result.get("modules", []):
        for patch in module.get("inline", {}).get("patches", []):
            inline_findings.append({"module": module["module"], **patch})
    return {
        "status": result["status"], "reason": result.get("reason"),
        "pid": result.get("pid"), "target_stable": result.get("target_stable"),
        "module_status_counts": result.get("module_status_counts"),
        "inline_findings": inline_findings,
        "module_phase_status": [
            {"module": item["module"], "status": item["status"],
             "inline": item.get("inline", {}).get("status"),
             "eat": item.get("eat", {}).get("status"),
             "iat": item.get("iat", {}).get("status")}
            for item in result.get("modules", [])
        ],
        "budget": result.get("budget"), "output": str(output),
    }
