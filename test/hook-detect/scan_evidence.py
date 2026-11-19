"""Read-only PE comparison primitives used by the WXWork research probe."""

from bisect import bisect_left
from struct import unpack_from
from dataclasses import dataclass
from pathlib import Path

import lief
from capstone import CS_ARCH_X86, CS_GRP_RET, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86_const import X86_INS_JMP, X86_OP_IMM, X86_OP_MEM


MAX_FILE_BYTES = 64 * 1024 * 1024
PAGE_SIZE = 4096
PATCH_BLOCK_SIZE = 512
MAX_READ_BYTES = 65535
EXECUTE = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
MODES = {lief.PE.Header.MACHINE_TYPES.I386: CS_MODE_32,
         lief.PE.Header.MACHINE_TYPES.AMD64: CS_MODE_64}


class ScanGap(ValueError):
    """A comparison that cannot safely be made."""


@dataclass(frozen=True)
class Section:
    start: int
    end: int
    offset: int
    executable: bool


@dataclass(frozen=True)
class ExportSymbol:
    name: str | None
    address: int
    ordinal: int
    forwarded: bool
    forwarder_library: str | None = None
    forwarder_function: str | None = None


class Baseline:
    def __init__(self, data, image, module_size, module_base):
        self.data = data
        self.mode = MODES.get(image.header.machine)
        header_size = image.optional_header.sizeof_headers
        if self.mode is None or image.optional_header.sizeof_image != module_size:
            raise ScanGap("architecture_or_image_size_mismatch")
        if not 0 < header_size <= PAGE_SIZE or header_size > len(data):
            raise ScanGap("invalid_or_oversize_headers")
        self.headers = data[:header_size]
        self.preferred_base = image.optional_header.imagebase
        self.module_base = module_base
        self.imagebase_width = 4 if self.mode == CS_MODE_32 else 8
        pe_offset = unpack_from("<I", self.headers, 0x3C)[0]
        self.imagebase_offset = pe_offset + 24 + (28 if self.mode == CS_MODE_32 else 24)
        if self.imagebase_offset + self.imagebase_width > header_size:
            raise ScanGap("invalid_imagebase_field")
        self.sections = []
        for section in image.sections:
            start, offset = section.virtual_address, section.pointerto_raw_data
            size = min(section.virtual_size, section.sizeof_raw_data)
            if size and offset >= header_size:
                if start < header_size or start + size > module_size or offset + size > len(data):
                    raise ScanGap("invalid_section_range")
                self.sections.append(Section(start, start + size, offset, section.has_characteristic(EXECUTE)))
        self.sections.sort(key=lambda sec: sec.start)
        if any(a.end > b.start for a, b in zip(self.sections, self.sections[1:])):
            raise ScanGap("ambiguous_section_ranges")
        self.exports = {}
        if exports := image.get_export():
            for entry in exports.entries:
                if entry.name:
                    self.exports.setdefault(entry.name, []).append(self.export_symbol(entry))
        self.exports_by_ordinal = {}
        if exports := image.get_export():
            for entry in exports.entries:
                if entry.ordinal >= 0:
                    self.exports_by_ordinal.setdefault(entry.ordinal, []).append(self.export_symbol(entry))
        export_directory = image.data_directory(lief.PE.DataDirectory.TYPES.EXPORT_TABLE)
        self.export_directory = (export_directory.rva, export_directory.size)
        self.import_entries = []
        for imported in list(image.imports):
            for entry in imported.entries:
                self.import_entries.append((imported.name, entry.name, entry.ordinal,
                                            entry.is_ordinal, entry.iat_address, False,
                                            entry.iat_value))
        for imported in list(image.delay_imports):
            width = 4 if self.mode == CS_MODE_32 else 8
            for index, entry in enumerate(imported.entries):
                self.import_entries.append((imported.name, entry.name, entry.ordinal,
                                            entry.is_ordinal, imported.iat + index * width, True,
                                            entry.iat_value))
        self.relocations = {}
        self.unknown_pages = set()
        self.delta = module_base - image.optional_header.imagebase
        if not self.delta:
            self.reloc_starts = []
            return
        width = 4 if self.mode == CS_MODE_32 else 8
        supported = "HIGHLOW" if width == 4 else "DIR64"
        for block in image.relocations:
            for entry in block.entries:
                if entry.type.name == supported and entry.address not in self.relocations:
                    self.relocations[entry.address] = width
                elif entry.type.name != "ABS":
                    self.unknown_pages.add(block.virtual_address)
        if not self.relocations and not self.unknown_pages:
            raise ScanGap("relocated_without_relocation_evidence")
        self.reloc_starts = sorted(self.relocations)

    @staticmethod
    def export_symbol(entry):
        library = function = None
        if entry.is_forwarded:
            library = entry.forward_information.library
            function = entry.forward_information.function
        return ExportSymbol(entry.name, entry.function_rva, entry.ordinal,
                            entry.is_forwarded, library, function)

    def check_headers(self, header):
        mapped = header[:len(self.headers)]
        if len(mapped) != len(self.headers):
            raise ScanGap("incomplete_mapping_headers")
        start = self.imagebase_offset
        end = start + self.imagebase_width
        live_base = int.from_bytes(mapped[start:end], "little")
        if live_base not in (self.preferred_base, self.module_base):
            raise ScanGap("mapped_imagebase_mismatch")
        spans = diff_runs(self.headers, mapped[:start] + self.headers[start:end] + mapped[end:])
        if spans:
            summary = ",".join(f"{lo:#x}-{hi:#x}" for lo, hi in spans[:4])
            raise ScanGap("mapped_headers_differ_from_disk:" + summary)

    def export_window(self, name, size):
        matching = self.exports.get(name, ())
        if len(matching) != 1:
            raise ScanGap("missing_or_ambiguous_export")
        rva, forwarded = matching[0]
        if forwarded:
            raise ScanGap("export_forwarder")
        for section in self.sections:
            if section.executable and section.start <= rva and rva + size <= section.end:
                return section, rva
        raise ScanGap("export_not_in_disk_code")

    def expected(self, section, rva, size):
        end = rva + size
        if not section.start <= rva < end <= section.end:
            raise ScanGap("range_outside_disk_backing")
        if any(page in self.unknown_pages for page in range(rva & -PAGE_SIZE, end, PAGE_SIZE)):
            raise ScanGap("unsupported_relocation")
        offset = section.offset + rva - section.start
        expected = bytearray(self.data[offset:offset + size])
        i = bisect_left(self.reloc_starts, rva - 7)
        while i < len(self.reloc_starts) and (where := self.reloc_starts[i]) < end:
            i += 1
            width = self.relocations[where]
            if where + width <= rva:
                continue
            if where < section.start or where + width > section.end:
                raise ScanGap("relocation_outside_disk_backing")
            word_at = section.offset + where - section.start
            old = int.from_bytes(self.data[word_at:word_at + width], "little")
            rebased = ((old + self.delta) % (1 << (8 * width))).to_bytes(width, "little")
            lo, hi = max(rva, where), min(end, where + width)
            expected[lo - rva:hi - rva] = rebased[lo - where:hi - where]
        return bytes(expected)


def load_baseline(path: Path, module_size, module_base):
    with path.open("rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ScanGap("disk_file_budget")
    config = lief.PE.ParserConfig()
    config.parse_imports = True
    config.parse_signature = False
    config.parse_rsrc = False
    config.parse_exceptions = False
    config.parse_reloc = True
    config.parse_exports = True
    image = lief.PE.parse(data, config)
    if image is None:
        raise ScanGap("unparseable_disk_pe")
    return Baseline(data, image, module_size, module_base)


def diff_runs(expected, live):
    if len(expected) != len(live):
        raise ScanGap("incomplete_compare")
    runs = []
    start = None
    for offset, (a, b) in enumerate(zip(expected, live)):
        if a != b:
            if start is None:
                start = offset
        elif start is not None:
            runs.append((start, offset))
            start = None
    if start is not None:
        runs.append((start, len(live)))
    return runs


def window_result(expected, live, mode, address):
    """Only export entry (offset zero) has a trusted instruction boundary here."""
    runs = diff_runs(expected, live)
    result = {"status": "patch" if runs else "equal", "patch_runs": len(runs),
              "changed_bytes": sum(hi - lo for lo, hi in runs)}
    if not runs:
        return result
    engine = Cs(CS_ARCH_X86, mode)
    engine.detail = True
    first_disk = next(engine.disasm(expected, address, count=1), None)
    first_live = next(engine.disasm(live, address, count=1), None)
    if first_disk is None or first_live is None:
        return result
    disk_ops = list(engine.disasm(expected, address, count=5))
    live_ops = list(engine.disasm(live, address, count=5))
    result.update(disk_mnemonics=[i.mnemonic for i in disk_ops[:3]],
                  live_mnemonics=[i.mnemonic for i in live_ops[:3]])
    if (first_live.id == X86_INS_JMP and first_disk.bytes != first_live.bytes
            and any(lo < first_live.size and hi - lo < PATCH_BLOCK_SIZE for lo, hi in runs)
            and all(hi - lo < PATCH_BLOCK_SIZE for lo, hi in runs if lo < first_live.size)):
        kind = {X86_OP_IMM: "direct", X86_OP_MEM: "memory_indirect"}.get(first_live.operands[0].type, "register_indirect")
        detail = {
            "status": "inline_candidate",
            "jump_kind": kind,
            "disk_entry_jump": first_disk.id == X86_INS_JMP,
        }
        if first_live.operands[0].type == X86_OP_IMM:
            # Capstone reports an absolute destination for PC-relative X86 JMP.
            detail["branch_target"] = first_live.operands[0].imm
        elif first_live.operands[0].type == X86_OP_MEM:
            detail["memory_operand"] = first_live.operands[0].mem.disp
        result.update(**detail)
    else:
        disk_returns = {i.address - address for i in disk_ops if i.group(CS_GRP_RET)}
        for instruction in live_ops:
            offset = instruction.address - address
            if (instruction.group(CS_GRP_RET) and offset not in disk_returns
                    and any(lo < offset + instruction.size and hi > offset for lo, hi in runs)):
                result.update(status="entry_return_patch", return_offset=offset)
                break
            if instruction.mnemonic not in {"nop", "endbr32", "endbr64", "mov", "xor", "and", "sub", "lea"}:
                break
    return result


def classify_region_patch(expected, live, mode, address):
    """Classify one contiguous run found by whole-region diff.

    A jump decoded at the first changed byte establishes a new instruction
    boundary for that patch. A changed operand inside an older instruction does
    not, and therefore remains a patch rather than inline-hook evidence.
    """
    runs = diff_runs(expected, live)
    if len(runs) != 1:
        raise ScanGap("expected_one_contiguous_patch")
    start, end = runs[0]
    result = {
        "status": "patch",
        "offset": start,
        "size": end - start,
        "boundary": "patch_start",
    }
    if end - start >= PATCH_BLOCK_SIZE:
        return result

    engine = Cs(CS_ARCH_X86, mode)
    engine.detail = True
    first_live = next(engine.disasm(live[start:end], address + start, count=1), None)
    first_disk = next(engine.disasm(expected[start:end], address + start, count=1), None)
    if first_live is None:
        return result

    result["live_mnemonic"] = first_live.mnemonic
    if first_disk is not None:
        result["disk_mnemonic"] = first_disk.mnemonic
    if first_live.id == X86_INS_JMP and first_live.size <= end - start:
        result.update(status="inline_candidate", jump_kind={
            X86_OP_IMM: "direct", X86_OP_MEM: "memory_indirect"
        }.get(first_live.operands[0].type, "register_indirect"))
        if first_live.operands[0].type == X86_OP_IMM:
            result["branch_target"] = first_live.operands[0].imm
        elif first_live.operands[0].type == X86_OP_MEM:
            result["memory_operand"] = first_live.operands[0].mem.disp
        return result

    nearby = list(engine.disasm(live[start:end], address + start, count=8))
    disk_engine = Cs(CS_ARCH_X86, mode)
    disk_engine.detail = True
    disk_returns = {
        instruction.address - (address + start)
        for instruction in disk_engine.disasm(expected[start:end], address + start, count=8)
        if instruction.group(CS_GRP_RET)
    }
    for instruction in nearby:
        offset = instruction.address - (address + start)
        if instruction.group(CS_GRP_RET) and offset not in disk_returns:
            result.update(status="entry_return_patch", return_offset=offset)
            break
    return result
