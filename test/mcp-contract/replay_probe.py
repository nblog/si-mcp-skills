# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["lief==1.0.0", "capstone==5.0.9"]
# ///

"""Offline feasibility probe for one PE export window; not a hook detector."""

import argparse
import json
import re
import sys
from pathlib import Path

import capstone
import lief


MCP_MAX_READ_BYTES = 65_535
MAX_INPUT_CHARS = 2 * MCP_MAX_READ_BYTES + 4096
MAX_PE_BYTES = 64 * 1024 * 1024
PREVIEW_BYTES = 32
MODES = {
    lief.PE.Header.MACHINE_TYPES.I386: (capstone.CS_MODE_32, 32),
    lief.PE.Header.MACHINE_TYPES.AMD64: (capstone.CS_MODE_64, 64),
}


def load_pe(path):
    with path.open("rb") as source:
        raw = source.read(MAX_PE_BYTES + 1)
    if len(raw) > MAX_PE_BYTES:
        raise ValueError("PE exceeds the offline probe's 64 MiB file limit")
    image = lief.PE.parse(raw)
    if image is None or image.header.machine not in MODES:
        raise ValueError("expected a parseable x86 or x64 PE file")
    return image, raw


def export_window(image, raw, name, size):
    exports = image.get_export()
    matches = [entry for entry in exports.entries if entry.name == name] if exports else []
    if len(matches) != 1 or matches[0].is_forwarded:
        raise ValueError("expected exactly one direct export of the requested name")

    rva = matches[0].address
    sections = [
        section for section in image.sections
        if section.virtual_address <= rva < section.virtual_address + section.virtual_size
    ]
    if len(sections) != 1:
        raise ValueError("export RVA does not map uniquely to a section")
    section = sections[0]
    delta = rva - section.virtual_address
    backed_size = min(section.virtual_size, section.sizeof_raw_data)
    file_offset = section.pointerto_raw_data + delta
    if (
        not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        or section.pointerto_raw_data == 0
        or delta + size > backed_size
        or rva + size > image.optional_header.sizeof_image
        or file_offset + size > len(raw)
        or file_offset != image.rva_to_offset(rva)
    ):
        raise ValueError("requested window is not fully backed by executable file bytes")
    return rva, file_offset, raw[file_offset:file_offset + size]


def read_mcp_reply(address, size, pid, sequence):
    reply = sys.stdin.read(MAX_INPUT_CHARS + 1)
    if len(reply) > MAX_INPUT_CHARS:
        raise ValueError("MCP record exceeds the input limit")
    record = json.loads(reply)
    if not isinstance(record, dict):
        raise ValueError("expected one unwrapped System Informer MCP result object")
    if (
        record.get("pid") != pid
        or record.get("process_sequence_number") != sequence
        or record.get("size") != size
        or int(str(record.get("address")), 0) != address
    ):
        raise ValueError("MCP result does not match requested PID, sequence, VA and size")
    payload = record.get("hex")
    if not isinstance(payload, str) or len(payload) != 2 * size or not re.fullmatch(r"[0-9a-fA-F]+", payload):
        raise ValueError("invalid, partial or truncated MCP hex payload")
    return bytes.fromhex(payload)


def describe(disassembler, data, address):
    instructions = [
        {"va": hex(insn.address), "size": insn.size, "mnemonic": insn.mnemonic, "operands": insn.op_str}
        for insn in disassembler.disasm(data[:PREVIEW_BYTES], address)
    ]
    return {"decoded_bytes": sum(insn["size"] for insn in instructions), "instructions": instructions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path)
    parser.add_argument("export")
    parser.add_argument("--base", type=lambda value: int(value, 0))
    parser.add_argument("--size", type=int, default=5, help="window size; this replay accepts 1..65535 bytes")
    parser.add_argument("--mcp-stdin", action="store_true", help="compare with a synthetic result on stdin")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--sequence", type=int)
    args = parser.parse_args()
    if not 1 <= args.size <= MCP_MAX_READ_BYTES:
        parser.error("--size must be 1..65535 bytes")
    if args.mcp_stdin and (args.base is None or not args.pid or not args.sequence):
        parser.error("--mcp-stdin requires --base, --pid and --sequence")

    try:
        image, raw = load_pe(args.pe)
        mode, bits = MODES[image.header.machine]
        rva, file_offset, disk = export_window(image, raw, args.export, args.size)
        base = image.optional_header.imagebase if args.base is None else args.base
        address = base + rva
        if base < 0 or address + args.size > 1 << bits:
            raise ValueError("VA window exceeds PE address width")
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, mode)
        result = {
            "architecture": image.header.machine.name,
            "export": args.export,
            "rva": hex(rva),
            "va": hex(address),
            "file_offset": hex(file_offset),
            "size": args.size,
            "disk": describe(disassembler, disk, address),
            "comparison": "not_run",
        }
        if args.mcp_stdin:
            live = read_mcp_reply(address, args.size, args.pid, args.sequence)
            result["memory"] = describe(disassembler, live, address)
            result["comparison"] = "raw_equal" if disk == live else "raw_different"
    except (OSError, ValueError, RuntimeError, capstone.CsError) as exc:
        parser.exit(2, f"probe: {exc}\n")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
