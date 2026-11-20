import struct

from pe.baseline import Baseline
from ph_utils.errors import PhUtilsError
from ph_utils.mcp import SystemInformerClient
from ph_utils.models import ModuleRecord, ProcessRecord

EXPORT_DESCRIPTOR = struct.Struct("<IIHHIIIIIII")


async def read_rva(client: SystemInformerClient, process: ProcessRecord,
                   module: ModuleRecord, rva: int, size: int) -> bytes:
    if not 0 < size <= client.config.max_table_bytes:
        raise PhUtilsError("invalid_table_read_size")
    chunks = []
    for offset in range(rva, rva + size, client.config.max_read_bytes):
        length = min(client.config.max_read_bytes, rva + size - offset)
        chunks.append(await client.read_memory(process, module.base + offset, length))
    return b"".join(chunks)


def _blob_slice(blob: bytes, blob_rva: int, rva: int, size: int) -> bytes:
    offset = rva - blob_rva
    if offset < 0 or offset + size > len(blob):
        raise PhUtilsError("table_outside_export_blob")
    return blob[offset:offset + size]


def _blob_cstr(blob: bytes, blob_rva: int, rva: int, limit: int) -> str:
    offset = rva - blob_rva
    if offset < 0 or offset >= len(blob):
        raise PhUtilsError("string_outside_export_blob")
    end = blob.find(b"\0", offset, min(len(blob), offset + limit))
    if end < 0:
        raise PhUtilsError("unterminated_or_truncated_string")
    return blob[offset:end].decode("utf-8", errors="replace")


async def parse_remote_export(client: SystemInformerClient, process: ProcessRecord,
                              module: ModuleRecord, baseline: Baseline) -> dict:
    directory_rva, directory_size = baseline.export_directory
    if not directory_rva or not directory_size:
        return {"status": "absent"}
    if directory_size > client.config.max_table_bytes:
        raise PhUtilsError("export_directory_budget")
    blob = await read_rva(client, process, module, directory_rva, directory_size)
    descriptor = EXPORT_DESCRIPTOR.unpack_from(blob, 0)
    (_flags, _timestamp, _major, _minor, _name_rva, ordinal_base, function_count,
     name_count, functions_rva, names_rva, ordinals_rva) = descriptor
    if function_count > client.config.max_export_entries or name_count > function_count:
        raise PhUtilsError("invalid_export_counts")
    functions = _blob_slice(blob, directory_rva, functions_rva, 4 * function_count)
    names = _blob_slice(blob, directory_rva, names_rva, 4 * name_count)
    ordinals = _blob_slice(blob, directory_rva, ordinals_rva, 2 * name_count)
    slots = list(struct.unpack(f"<{function_count}I", functions))
    name_rvas = list(struct.unpack(f"<{name_count}I", names))
    indexes = list(struct.unpack(f"<{name_count}H", ordinals))
    names_by_index: dict[str, list[int]] = {}
    for index, name_rva in zip(indexes, name_rvas):
        if index >= function_count:
            raise PhUtilsError("invalid_export_name_index")
        value = _blob_cstr(blob, directory_rva, name_rva, client.config.max_string_bytes)
        names_by_index.setdefault(value.casefold(), []).append(index)
    return {
        "status": "present",
        "blob": blob,
        "blob_rva": directory_rva,
        "descriptor": {
            "flags": descriptor[0], "timestamp": descriptor[1],
            "version": [descriptor[2], descriptor[3]], "name_rva": descriptor[4],
            "ordinal_base": ordinal_base, "function_count": function_count,
            "name_count": name_count, "functions_rva": functions_rva,
            "names_rva": names_rva, "ordinals_rva": ordinals_rva,
        },
        "slots": slots,
        "names": names_by_index,
    }


def _disk_cstr(baseline: Baseline, rva: int, limit: int) -> str:
    section = baseline.section_for_rva(rva)
    if section is None:
        raise PhUtilsError("disk_string_outside_raw_backing")
    available = min(limit, section.end - rva)
    raw = baseline.raw_bytes(rva, available)
    end = raw.find(b"\0")
    if end < 0:
        raise PhUtilsError("unterminated_or_truncated_disk_string")
    return raw[:end].decode("utf-8", errors="replace")


def disk_export_semantics(baseline: Baseline) -> dict:
    directory_rva, _size = baseline.export_directory
    descriptor_raw = baseline.raw_bytes(directory_rva, EXPORT_DESCRIPTOR.size)
    descriptor = EXPORT_DESCRIPTOR.unpack_from(descriptor_raw)
    slots: list[object] = [None] * descriptor[6]
    names: dict[str, list[int]] = {}
    for entry in baseline.export_entries:
        index = entry.ordinal - descriptor[5]
        if 0 <= index < len(slots):
            slots[index] = entry
        if entry.name:
            names.setdefault(entry.name.casefold(), []).append(index)
    return {"descriptor": descriptor, "slots": slots, "names": names}


def compare_exports(baseline: Baseline, remote: dict, string_limit: int) -> dict:
    if remote["status"] == "absent":
        return {"status": "absent", "findings": []}
    disk = disk_export_semantics(baseline)
    fields = ("flags", "timestamp", "major", "minor", "name_rva", "ordinal_base",
              "function_count", "name_count", "functions_rva", "names_rva", "ordinals_rva")
    findings: list[dict] = []
    for field, disk_value in zip(fields, disk["descriptor"]):
        if field in ("major", "minor"):
            memory_value = remote["descriptor"]["version"][0 if field == "major" else 1]
        else:
            memory_value = remote["descriptor"][field]
        if disk_value != memory_value:
            findings.append({"field": field, "disk": disk_value, "memory": memory_value})

    for index, (expected, actual) in enumerate(zip(disk["slots"], remote["slots"])):
        if expected is None:
            findings.append({"slot_index": index, "status": "memory_slot_without_disk_entry",
                             "memory_rva": actual})
            continue
        if expected.address != actual:
            findings.append({"slot_index": index, "export": expected.name,
                             "ordinal": expected.ordinal, "disk_rva": expected.address,
                             "memory_rva": actual, "status": "eat_slot_mismatch"})
            continue
        if expected.forwarded:
            disk_forwarder = _disk_cstr(baseline, expected.address, string_limit)
            memory_forwarder = _blob_cstr(remote["blob"], remote["blob_rva"], actual, string_limit)
            if disk_forwarder != memory_forwarder:
                findings.append({"slot_index": index, "export": expected.name,
                                 "ordinal": expected.ordinal,
                                 "status": "forwarder_string_mismatch",
                                 "disk": disk_forwarder, "memory": memory_forwarder})

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
        "function_count": len(remote["slots"]),
        "named_count": len(remote["names"]),
        "forwarder_strings_compared": sum(entry is not None and entry.forwarded
                                         for entry in disk["slots"]),
        "findings": findings,
    }


async def scan_eat(client: SystemInformerClient, process: ProcessRecord,
                   module: ModuleRecord, baseline: Baseline) -> dict:
    remote = await parse_remote_export(client, process, module, baseline)
    return compare_exports(baseline, remote, client.config.max_string_bytes)
