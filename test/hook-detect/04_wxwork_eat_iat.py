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

"""Read-only WXWork EAT and semantic-IAT table validation experiment."""

import asyncio
import importlib.metadata
import importlib.util
import json
import logging
import os
import struct
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import anyio
import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from capstone import CS_MODE_32

from scan_evidence import MAX_FILE_BYTES, ScanGap, load_baseline


ROOT = Path(__file__).resolve().parents[2]
TARGET_MODULES = ("KernelBase.dll", "kernel32.dll")
EXPORT_DESCRIPTOR = struct.Struct("<IIHHIIIIIII")
POINTER_32 = struct.Struct("<I")


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


def cstr(data, offset):
    end = data.find(b"\0", offset)
    if end < 0:
        raise ScanGap("unterminated_string")
    return data[offset:end].decode("utf-8", errors="replace")


async def read_rva(scanner, pid, sequence, base, rva, size):
    if not 0 < size <= 4 * 1024 * 1024:
        raise ScanGap("invalid_table_read_size")
    chunks = []
    for offset in range(rva, rva + size, scanner.config.max_read_bytes):
        length = min(scanner.config.max_read_bytes, rva + size - offset)
        chunks.append(await scanner.read(pid, sequence, base + offset, length))
    return b"".join(chunks)


def blob_slice(blob, blob_rva, rva, size):
    offset = rva - blob_rva
    if offset < 0 or offset + size > len(blob):
        raise ScanGap("table_outside_export_blob")
    return blob[offset:offset + size]


def blob_cstr(blob, blob_rva, rva, limit=512):
    offset = rva - blob_rva
    if offset < 0 or offset >= len(blob):
        raise ScanGap("string_outside_export_blob")
    end = blob.find(b"\0", offset, min(len(blob), offset + limit))
    if end < 0:
        raise ScanGap("unterminated_or_truncated_string")
    return blob[offset:end].decode("utf-8", errors="replace")


async def parse_remote_export(scanner, pid, sequence, row, baseline):
    directory_rva, directory_size = baseline.export_directory
    if not directory_rva or not directory_size:
        return {"status": "absent"}
    blob = await read_rva(scanner, pid, sequence, row.base, directory_rva,
                          min(directory_size, 2 * 1024 * 1024))
    descriptor = EXPORT_DESCRIPTOR.unpack_from(blob, 0)
    (flags, timestamp, major, minor, name_rva, ordinal_base, function_count,
     name_count, functions_rva, names_rva, ordinals_rva) = descriptor
    if function_count > 65535 or name_count > function_count:
        raise ScanGap("invalid_export_counts")

    functions_raw = blob_slice(blob, directory_rva, functions_rva, 4 * function_count)
    names_raw = blob_slice(blob, directory_rva, names_rva, 4 * name_count)
    ordinals_raw = blob_slice(blob, directory_rva, ordinals_rva, 2 * name_count)
    slots = list(struct.unpack(f"<{function_count}I", functions_raw))
    name_rvas = list(struct.unpack(f"<{name_count}I", names_raw))
    indexes = list(struct.unpack(f"<{name_count}H", ordinals_raw))
    names = {}
    for index, name_pointer in zip(indexes, name_rvas):
        if index >= function_count:
            raise ScanGap("invalid_export_name_index")
        value = blob_cstr(blob, directory_rva, name_pointer)
        names.setdefault(value.casefold(), []).append(index)
    return {
        "status": "present",
        "blob_rva": directory_rva,
        "descriptor": {
            "flags": flags, "timestamp": timestamp, "version": [major, minor],
            "name_rva": name_rva, "ordinal_base": ordinal_base,
            "function_count": function_count, "name_count": name_count,
            "functions_rva": functions_rva, "names_rva": names_rva,
            "ordinals_rva": ordinals_rva,
        },
        "slots": slots,
        "names": names,
        "blob": blob,
    }


def disk_export_semantics(baseline):
    descriptor_raw = None
    descriptor_rva, directory_size = baseline.export_directory
    for section in baseline.sections:
        if section.start <= descriptor_rva < section.end:
            offset = section.offset + (descriptor_rva - section.start)
            descriptor_raw = baseline.data[offset:offset + EXPORT_DESCRIPTOR.size]
            break
    if descriptor_raw is None:
        raise ScanGap("disk_export_descriptor_unbacked")
    descriptor = EXPORT_DESCRIPTOR.unpack_from(descriptor_raw)
    slots = [None] * descriptor[6]
    names = {}
    for entry in next(iter([baseline.exports_by_ordinal.values()]), []):
        pass
    all_entries = [entry for entries in baseline.exports_by_ordinal.values() for entry in entries]
    for entry in all_entries:
        index = entry.ordinal - descriptor[5]
        if 0 <= index < len(slots):
            slots[index] = entry
        if entry.name:
            names.setdefault(entry.name.casefold(), []).append(index)
    return {"descriptor": descriptor, "slots": slots, "names": names,
            "all_entries": all_entries}


def disk_cstr_by_rva(baseline, rva, limit=512):
    for section in baseline.sections:
        if section.start <= rva < section.end:
            offset = section.offset + (rva - section.start)
            end = baseline.data.find(b"\0", offset, min(len(baseline.data), offset + limit))
            if end < 0:
                raise ScanGap("unterminated_or_truncated_disk_string")
            return baseline.data[offset:end].decode("utf-8", errors="replace")
    raise ScanGap("disk_string_outside_raw_backing")


def compare_exports(row, baseline, remote):
    if remote["status"] == "absent":
        return {"status": "absent", "findings": []}
    disk = disk_export_semantics(baseline)
    disk_descriptor, remote_descriptor = disk["descriptor"], remote["descriptor"]
    field_names = ("flags", "timestamp", "major", "minor", "name_rva",
                   "ordinal_base", "function_count", "name_count",
                   "functions_rva", "names_rva", "ordinals_rva")
    findings = []
    for name, left, right in zip(field_names, disk_descriptor, remote_descriptor):
        if name in ("major", "minor"):
            right_value = remote_descriptor["version"][0 if name == "major" else 1]
        else:
            right_value = remote_descriptor[name]
        if left != right_value:
            findings.append({"field": name, "disk": left, "memory": right_value})

    disk_slots, memory_slots = disk["slots"], remote["slots"]
    for index, (expected, actual) in enumerate(zip(disk_slots, memory_slots)):
        if expected is None:
            findings.append({"slot_index": index, "status": "memory_slot_without_disk_entry",
                             "memory_rva": actual})
            continue
        expected_rva = expected.address
        if expected_rva != actual:
            finding = {"slot_index": index, "export": expected.name,
                       "ordinal": expected.ordinal, "disk_rva": expected_rva,
                       "memory_rva": actual, "status": "eat_slot_mismatch"}
            findings.append(finding)
            continue
        if expected.forwarded:
            disk_forwarder = disk_cstr_by_rva(baseline, expected_rva)
            memory_forwarder = blob_cstr(remote["blob"], remote["blob_rva"], actual)
            if disk_forwarder != memory_forwarder:
                findings.append({
                    "slot_index": index, "export": expected.name,
                    "ordinal": expected.ordinal, "status": "forwarder_string_mismatch",
                    "disk": disk_forwarder, "memory": memory_forwarder,
                })

    disk_names = {name: values[0] for name, values in disk["names"].items() if len(values) == 1}
    memory_names = {name: values[0] for name, values in remote["names"].items() if len(values) == 1}
    for name in sorted(set(disk_names) - set(memory_names)):
        findings.append({"name": name, "status": "memory_name_missing",
                         "disk_index": disk_names[name]})
    for name in sorted(set(memory_names) - set(disk_names)):
        findings.append({"name": name, "status": "memory_name_extra",
                         "memory_index": memory_names[name]})
    for name in sorted(set(disk_names) & set(memory_names)):
        if disk_names[name] != memory_names[name]:
            findings.append({"name": name, "status": "name_index_mismatch",
                             "disk_index": disk_names[name], "memory_index": memory_names[name]})
    return {
        "status": "equal" if not findings else "modified",
        "function_count": len(memory_slots),
        "named_count": len(remote["names"]),
        "forwarder_strings_compared": sum(1 for entry in disk["slots"]
                                          if entry is not None and entry.forwarded),
        "findings": findings,
    }


class DependencyResolver:
    def __init__(self, rows, target_kind):
        self.rows = {}
        for row in rows:
            if row.kind == target_kind and Path(row.path).is_file() and Path(row.path).stat().st_size <= MAX_FILE_BYTES:
                self.rows.setdefault(Path(row.path).name.casefold(), []).append(row)
        self.cache = {}

    async def baseline(self, row):
        if row.key not in self.cache:
            self.cache[row.key] = await asyncio.to_thread(load_baseline, Path(row.path), row.size, row.base)
        return self.cache[row.key]

    def row(self, library):
        matches = self.rows.get(Path(library).name.casefold(), [])
        return matches[0] if len(matches) == 1 else None

    async def unique_export_candidates(self, name):
        candidates = []
        for matches in self.rows.values():
            for row in matches:
                baseline = await self.baseline(row)
                entries = baseline.exports.get(name, [])
                if len(entries) == 1 and not entries[0].forwarded:
                    candidates.append((row.base + entries[0].address, row))
        return candidates

    async def resolve(self, library, name, ordinal, by_ordinal, chain=()):
        row = self.row(library)
        if row is None:
            if name and not by_ordinal:
                candidates = await self.unique_export_candidates(name)
                if len(candidates) == 1:
                    return candidates[0][0], candidates[0][1], "resolved_unique_export"
            return None, None, "unresolved_library_or_apiset"
        key = (row.key, name, ordinal, by_ordinal)
        if key in chain:
            return None, None, "forwarder_cycle"
        baseline = await self.baseline(row)
        entries = (baseline.exports_by_ordinal.get(ordinal, [])
                   if by_ordinal else baseline.exports.get(name, []))
        if len(entries) != 1:
            return None, row, "missing_or_ambiguous_export"
        entry = entries[0]
        if not entry.forwarded:
            return row.base + entry.address, row, "resolved"
        next_name = entry.forwarder_function
        next_ordinal, next_by_ordinal = 0, False
        if next_name.startswith("#"):
            try:
                next_ordinal, next_by_ordinal = int(next_name[1:], 10), True
            except ValueError:
                return None, row, "invalid_forwarder_ordinal"
        return await self.resolve(entry.forwarder_library + ".dll", next_name, next_ordinal,
                                  next_by_ordinal, chain + (key,))


async def read_iat_slots(scanner, pid, sequence, row, baseline):
    entries = sorted({entry[4] for entry in baseline.import_entries if entry[4]})
    if not entries:
        return {}, []
    ranges = []
    start = previous = entries[0]
    width = 4 if baseline.mode == CS_MODE_32 else 8
    for rva in entries[1:]:
        if rva - previous <= 4096:
            previous = rva
            continue
        ranges.append((start, previous + width - start))
        start = previous = rva
    ranges.append((start, previous + width - start))
    actual = {}
    for start, size in ranges:
        data = await read_rva(scanner, pid, sequence, row.base, start, size)
        for offset in range(0, len(data), width):
            value = int.from_bytes(data[offset:offset + width], "little")
            actual[start + offset] = value
    return actual, [{"rva": start, "size": size} for start, size in ranges]


async def validate_iat(scanner, pid, sequence, row, baseline, resolver):
    actual, ranges = await read_iat_slots(scanner, pid, sequence, row, baseline)
    width = 4 if baseline.mode == CS_MODE_32 else 8
    results = []
    counts = {}
    for library, name, ordinal, by_ordinal, iat_rva, delayed, disk_iat_value in baseline.import_entries:
        raw = actual.get(iat_rva)
        if raw is None:
            status = "slot_not_read"
        else:
            expected, expected_row, reason = await resolver.resolve(library, name, ordinal, by_ordinal)
            unresolved_delay = (disk_iat_value - baseline.preferred_base + row.base
                                if disk_iat_value >= baseline.preferred_base else disk_iat_value)
            if delayed and raw == unresolved_delay:
                status = "unresolved_delay_import"
            elif reason == "resolved":
                status = "equal" if raw == expected else "iat_pointer_mismatch"
            elif delayed and raw == 0:
                status = "unresolved_delay_import"
            else:
                status = reason
        counts[status] = counts.get(status, 0) + 1
        if status != "equal":
            results.append({
                "library": library, "name": name, "ordinal": ordinal,
                "by_ordinal": by_ordinal, "iat_rva": iat_rva,
                "delayed": delayed, "status": status, "actual": raw,
            })
    read_addresses = len(actual)
    entry_count = len(baseline.import_entries)
    return {"status": "equal" if all(value == 0 for key, value in counts.items()
                                     if key != "equal") else "modified_or_unknown",
            "slot_count": read_addresses, "entry_count": entry_count,
            "covered_filler_addresses": read_addresses - entry_count,
            "counts": counts, "ranges": ranges,
            "non_equal": results}


async def scan_module(scanner, pid, sequence, row, resolver):
    result = {"module": row.name, "status": "gap"}
    try:
        baseline = await resolver.baseline(row)
        header = await scanner.read(pid, sequence, row.base,
                                     min(scanner.config.page_size, row.size))
        baseline.check_headers(header)
        remote_export = await parse_remote_export(scanner, pid, sequence, row, baseline)
        eat = compare_exports(row, baseline, remote_export)
        iat = await validate_iat(scanner, pid, sequence, row, baseline, resolver)
        result.update(status="completed", eat=eat, iat=iat)
    except (ScanGap, probe.ProbeError, OSError, ValueError, struct.error) as exc:
        result.update(reason=str(exc) if isinstance(exc, ScanGap) else "mcp_or_local_gap",
                      reason_code=str(exc) if isinstance(exc, (ScanGap, probe.ProbeError))
                      else type(exc).__name__)
    return result


async def live_scan(simcp, sha256, process_name, pid, workers):
    config = probe.Config()
    budget = probe.Budget(config=config, started=time.monotonic())
    executable = probe.trusted_executable(simcp, sha256)
    probe.require(importlib.metadata.version("mcp") == probe.SDK_VERSION,
                  "unexpected_sdk_version")
    state = {"scanner": None}
    result = {"schema_version": 1, "research_only": True, "status": "failed"}
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
                        await scanner.handshake()
                        pid, sequence = await scanner.find_process(process_name, pid)
                        modules = await scanner.modules(pid, sequence)
                        targets = [row for row in modules
                                   if row.name.casefold() in {name.casefold() for name in TARGET_MODULES}]
                        probe.require(len(targets) == len(TARGET_MODULES), "target_modules_not_found")
                        resolver = DependencyResolver(modules, targets[0].kind)
                        limit = asyncio.Semaphore(workers)
                        async def one(row):
                            async with limit:
                                return await scan_module(scanner, pid, sequence, row, resolver)
                        module_results = await asyncio.gather(*(one(row) for row in targets))
                        final = await scanner.call("get_process", {"pid": pid})
                        probe.require(probe.identity(final, pid) == (pid, sequence),
                                      "process_identity_changed_after_scan")
                        final_modules = await scanner.modules(pid, sequence)
                        stable = {row.key for row in targets} <= {row.key for row in final_modules}
                        result.update(status="passed", pid=pid,
                                      process_sequence_number=sequence,
                                      module_count=len(modules), target_stable=stable,
                                      modules=module_results)
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
        ".codex-tracking/research/hook-detect-wxwork-eat-iat-2026-11-19.json"
    ),
) -> None:
    """Run bounded read-only EAT and semantic-IAT validation."""
    destination = output if output.is_absolute() else ROOT / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    result, code = asyncio.run(live_scan(simcp, sha256, process_name, pid, workers))
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    summary = {
        "status": result["status"], "reason": result.get("reason"),
        "pid": result.get("pid"), "target_stable": result.get("target_stable"),
        "modules": [
            {"module": item["module"], "status": item["status"],
             "eat": {key: item.get("eat", {}).get(key)
                     for key in ("status", "function_count", "named_count", "forwarder_strings_compared")},
             "eat_findings": item.get("eat", {}).get("findings", [])[:20],
             "iat": {key: item.get("iat", {}).get(key)
                     for key in ("status", "entry_count", "slot_count", "covered_filler_addresses", "counts")},
             "iat_non_equal": item.get("iat", {}).get("non_equal", [])[:20]}
            for item in result.get("modules", [])
        ],
        "budget": result.get("budget"), "output": str(destination),
    }
    print(json.dumps(summary, indent=2))
    raise typer.Exit(code)


if __name__ == "__main__":
    app()
