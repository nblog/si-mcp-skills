from dataclasses import dataclass

from pe.baseline import Baseline, Section
from ph_utils.errors import PhUtilsError
from ph_utils.mcp import SystemInformerClient
from ph_utils.models import MemoryRegion, ModuleRecord, ProcessRecord


@dataclass(frozen=True)
class Interval:
    start: int
    end: int


def executable_intersections(regions: list[MemoryRegion], start: int, end: int) -> list[Interval]:
    result: list[Interval] = []
    for region in regions:
        low, high = max(start, region.start), min(end, region.end)
        if low >= high:
            continue
        if result and result[-1].end == low:
            result[-1] = Interval(result[-1].start, high)
        else:
            result.append(Interval(low, high))
    return result


def runtime_exec_without_disk_exec(regions: list[MemoryRegion], module: ModuleRecord,
                                   executable_sections: list[Section]) -> list[Interval]:
    backed = [(module.base + section.start, module.base + section.end)
              for section in executable_sections]
    uncovered: list[Interval] = []
    for interval in executable_intersections(regions, module.base, module.base + module.size):
        cursor = interval.start
        for start, end in backed:
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


async def read_region(client: SystemInformerClient, process: ProcessRecord,
                      module: ModuleRecord, baseline: Baseline, section: Section,
                      interval: Interval) -> tuple[bytes, bytes]:
    expected = bytearray()
    live = bytearray()
    for address in range(interval.start, interval.end, client.config.max_read_bytes):
        size = min(client.config.max_read_bytes, interval.end - address)
        rva = address - module.base
        expected.extend(baseline.expected(section, rva, size))
        live.extend(await client.read_memory(process, address, size))
    if len(expected) != len(live):
        raise PhUtilsError("incomplete_region_read")
    return bytes(expected), bytes(live)
