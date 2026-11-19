import asyncio
from dataclasses import dataclass
from pathlib import Path

import lief
from pe.baseline import MAX_FILE_BYTES, Baseline, load_baseline
from ph_utils.mcp import SystemInformerClient
from ph_utils.models import ModuleRecord, ProcessRecord


@dataclass(frozen=True)
class ExportCandidate:
    address: int
    module_identity: tuple
    module_name: str


class DependencyResolver:
    def __init__(self, modules: list[ModuleRecord], target_kind: str):
        self.rows: dict[str, list[ModuleRecord]] = {}
        for row in modules:
            if row.kind != target_kind:
                continue
            path = Path(row.path)
            if path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
                self.rows.setdefault(path.name.casefold(), []).append(row)
        self.cache: dict[tuple, Baseline] = {}
        self.export_index: dict[str, list[ExportCandidate]] | None = None

    async def baseline(self, row: ModuleRecord) -> Baseline:
        if row.identity not in self.cache:
            self.cache[row.identity] = await asyncio.to_thread(
                load_baseline, Path(row.path), row.size, row.base)
        return self.cache[row.identity]

    def row(self, library: str) -> ModuleRecord | None:
        matches = self.rows.get(Path(library).name.casefold(), [])
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _direct_exports(row: ModuleRecord) -> dict[str, list[ExportCandidate]]:
        try:
            path = Path(row.path)
            data = path.read_bytes()
            parser = lief.PE.ParserConfig()
            parser.parse_imports = False
            parser.parse_exports = True
            parser.parse_reloc = False
            parser.parse_signature = False
            parser.parse_rsrc = False
            parser.parse_exceptions = False
            image = lief.PE.parse(data, parser)
        except (OSError, ValueError):
            return {}
        if image is None or image.optional_header.sizeof_image != row.size:
            return {}
        result: dict[str, list[ExportCandidate]] = {}
        exports = image.get_export()
        if not exports:
            return {}
        for entry in exports.entries:
            if entry.name and not entry.is_forwarded:
                result.setdefault(entry.name.casefold(), []).append(ExportCandidate(
                    row.base + entry.function_rva, row.identity, row.name,
                ))
        return result

    async def build_export_index(self, workers: int = 4) -> dict[str, list[ExportCandidate]]:
        if self.export_index is not None:
            return self.export_index
        rows = [row for matches in self.rows.values() for row in matches]
        semaphore = asyncio.Semaphore(workers)
        async def build(row: ModuleRecord):
            async with semaphore:
                return await asyncio.to_thread(self._direct_exports, row)
        results = await asyncio.gather(*(build(row) for row in rows))
        index: dict[str, list[ExportCandidate]] = {}
        for result in results:
            for name, candidates in result.items():
                index.setdefault(name, []).extend(candidates)
        self.export_index = index
        return index

    async def resolve(self, library: str, name: str, ordinal: int,
                      by_ordinal: bool, chain: tuple = ()) -> tuple[int | None, ModuleRecord | None, str]:
        row = self.row(library)
        if row is None:
            if name and not by_ordinal and self.export_index is not None:
                candidates = self.export_index.get(name.casefold(), [])
                if len(candidates) == 1:
                    candidate = candidates[0]
                    owner = self.row(candidate.module_name)
                    if owner is not None and owner.identity == candidate.module_identity:
                        return candidate.address, owner, "resolved_unique_export"
            return None, None, "unresolved_library_or_apiset"
        key = (row.identity, name, ordinal, by_ordinal)
        if key in chain:
            return None, row, "forwarder_cycle"
        baseline = await self.baseline(row)
        entries = (baseline.exports_by_ordinal.get(ordinal, [])
                   if by_ordinal else baseline.exports.get(name, []))
        if len(entries) != 1:
            return None, row, "missing_or_ambiguous_export"
        entry = entries[0]
        if not entry.forwarded:
            return row.base + entry.address, row, "resolved"
        next_name = entry.forwarder_function or ""
        next_ordinal, next_by_ordinal = 0, False
        if next_name.startswith("#"):
            try:
                next_ordinal, next_by_ordinal = int(next_name[1:], 10), True
            except ValueError:
                return None, row, "invalid_forwarder_ordinal"
        return await self.resolve((entry.forwarder_library or "") + ".dll", next_name,
                                  next_ordinal, next_by_ordinal, chain + (key,))


async def read_iat_slots(client: SystemInformerClient, process: ProcessRecord,
                         module: ModuleRecord, baseline: Baseline) -> tuple[dict[int, int], list[dict]]:
    entries = sorted({entry.iat_rva for entry in baseline.import_entries if entry.iat_rva})
    if not entries:
        return {}, []
    ranges: list[tuple[int, int]] = []
    start = previous = entries[0]
    width = baseline.pointer_width
    for rva in entries[1:]:
        if rva - previous <= 4096:
            previous = rva
            continue
        ranges.append((start, previous + width - start))
        start = previous = rva
    ranges.append((start, previous + width - start))

    actual: dict[int, int] = {}
    range_report: list[dict] = []
    from detect.eat import read_rva
    for start_rva, size in ranges:
        data = await read_rva(client, process, module, start_rva, size)
        for offset in range(0, len(data), width):
            actual[start_rva + offset] = int.from_bytes(data[offset:offset + width], "little")
        range_report.append({"rva": start_rva, "size": size})
    return actual, range_report


def _iat_status(counts: dict[str, int]) -> str:
    if counts.get("iat_pointer_mismatch", 0) or counts.get("slot_not_read", 0):
        return "modified_or_gap"
    if counts.get("equal", 0) == sum(counts.values()):
        return "equal"
    return "partial_unknown"


async def scan_iat(client: SystemInformerClient, process: ProcessRecord,
                   module: ModuleRecord, baseline: Baseline,
                   resolver: DependencyResolver) -> dict:
    actual, ranges = await read_iat_slots(client, process, module, baseline)
    counts: dict[str, int] = {}
    non_equal: list[dict] = []
    for entry in baseline.import_entries:
        raw = actual.get(entry.iat_rva)
        if raw is None:
            status = "slot_not_read"
        else:
            expected, _owner, reason = await resolver.resolve(
                entry.library, entry.name, entry.ordinal, entry.by_ordinal)
            unresolved_delay = None
            if entry.delayed:
                unresolved_delay = (entry.disk_iat_value - baseline.preferred_base + module.base
                                    if entry.disk_iat_value >= baseline.preferred_base
                                    else entry.disk_iat_value)
            if entry.delayed and raw == unresolved_delay or entry.delayed and raw == 0:
                status = "unresolved_delay_import"
            elif reason == "resolved":
                status = "equal" if raw == expected else "iat_pointer_mismatch"
            else:
                status = reason
        counts[status] = counts.get(status, 0) + 1
        if status != "equal":
            non_equal.append({
                "library": entry.library, "name": entry.name,
                "ordinal": entry.ordinal, "by_ordinal": entry.by_ordinal,
                "iat_rva": entry.iat_rva, "delayed": entry.delayed,
                "status": status, "actual": raw,
            })
    read_addresses = len(actual)
    entry_count = len(baseline.import_entries)
    return {
        "status": _iat_status(counts),
        "entry_count": entry_count,
        "slot_count": read_addresses,
        "covered_filler_addresses": read_addresses - entry_count,
        "counts": counts,
        "ranges": ranges,
        "non_equal": non_equal,
    }
