import hashlib
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path
from struct import unpack_from

import lief
from capstone import CS_MODE_32, CS_MODE_64

MAX_FILE_BYTES = 64 * 1024 * 1024
PAGE_SIZE = 4096
EXECUTE = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
MODES = {
    lief.PE.Header.MACHINE_TYPES.I386: CS_MODE_32,
    lief.PE.Header.MACHINE_TYPES.AMD64: CS_MODE_64,
}


class BaselineError(ValueError):
    """The disk PE cannot safely establish a comparable baseline."""


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


@dataclass(frozen=True)
class ImportEntry:
    library: str
    name: str
    ordinal: int
    by_ordinal: bool
    iat_rva: int
    delayed: bool
    disk_iat_value: int


class Baseline:
    def __init__(self, data: bytes, image: lief.PE.Binary, module_size: int,
                 module_base: int, file_sha256: str):
        self.data = data
        self.file_sha256 = file_sha256
        self.mode = MODES.get(image.header.machine)
        header_size = image.optional_header.sizeof_headers
        if self.mode is None or image.optional_header.sizeof_image != module_size:
            raise BaselineError("architecture_or_image_size_mismatch")
        if not 0 < header_size <= PAGE_SIZE or header_size > len(data):
            raise BaselineError("invalid_or_oversize_headers")
        self.headers = data[:header_size]
        self.preferred_base = image.optional_header.imagebase
        self.module_base = module_base
        self.module_size = module_size
        self.pointer_width = 4 if self.mode == CS_MODE_32 else 8
        pe_offset = unpack_from("<I", self.headers, 0x3C)[0]
        self.imagebase_offset = pe_offset + 24 + (28 if self.mode == CS_MODE_32 else 24)
        if self.imagebase_offset + self.pointer_width > header_size:
            raise BaselineError("invalid_imagebase_field")
        self._load_sections(image)
        self._load_exports(image)
        self._load_imports(image)
        self._load_relocations(image)

    def _load_sections(self, image: lief.PE.Binary) -> None:
        self.sections: list[Section] = []
        for section in image.sections:
            start, offset = section.virtual_address, section.pointerto_raw_data
            size = min(section.virtual_size, section.sizeof_raw_data)
            if size and offset >= len(self.headers):
                if start < len(self.headers) or start + size > self.module_size or offset + size > len(self.data):
                    raise BaselineError("invalid_section_range")
                self.sections.append(Section(start, start + size, offset,
                                              section.has_characteristic(EXECUTE)))
        self.sections.sort(key=lambda section: section.start)
        if any(left.end > right.start for left, right in zip(self.sections, self.sections[1:])):
            raise BaselineError("ambiguous_section_ranges")

    @staticmethod
    def _export_symbol(entry: lief.PE.ExportEntry) -> ExportSymbol:
        forwarder_library = forwarder_function = None
        if entry.is_forwarded:
            forwarder_library = entry.forward_information.library
            forwarder_function = entry.forward_information.function
        return ExportSymbol(entry.name, entry.function_rva, entry.ordinal,
                            entry.is_forwarded, forwarder_library, forwarder_function)

    def _load_exports(self, image: lief.PE.Binary) -> None:
        self.exports: dict[str, list[ExportSymbol]] = {}
        self.exports_by_ordinal: dict[int, list[ExportSymbol]] = {}
        exports = image.get_export()
        self.export_entries: list[ExportSymbol] = []
        if exports:
            for native in exports.entries:
                entry = self._export_symbol(native)
                self.export_entries.append(entry)
                if entry.name:
                    self.exports.setdefault(entry.name, []).append(entry)
                if entry.ordinal >= 0:
                    self.exports_by_ordinal.setdefault(entry.ordinal, []).append(entry)
        directory = image.data_directory(lief.PE.DataDirectory.TYPES.EXPORT_TABLE)
        self.export_directory = (directory.rva, directory.size)

    def _load_imports(self, image: lief.PE.Binary) -> None:
        self.import_entries: list[ImportEntry] = []
        for imported in list(image.imports):
            for entry in imported.entries:
                self.import_entries.append(ImportEntry(
                    imported.name, entry.name or "", entry.ordinal, entry.is_ordinal,
                    entry.iat_address, False, entry.iat_value,
                ))
        for imported in list(image.delay_imports):
            for index, entry in enumerate(imported.entries):
                self.import_entries.append(ImportEntry(
                    imported.name, entry.name or "", entry.ordinal, entry.is_ordinal,
                    imported.iat + index * self.pointer_width, True, entry.iat_value,
                ))

    def _load_relocations(self, image: lief.PE.Binary) -> None:
        self.relocations: dict[int, int] = {}
        self.unknown_pages: set[int] = set()
        self.delta = self.module_base - self.preferred_base
        self.relocation_starts: list[int] = []
        if not self.delta:
            return
        supported = "HIGHLOW" if self.pointer_width == 4 else "DIR64"
        for block in image.relocations:
            for entry in block.entries:
                if entry.type.name == supported and entry.address not in self.relocations:
                    self.relocations[entry.address] = self.pointer_width
                elif entry.type.name != "ABS":
                    self.unknown_pages.add(block.virtual_address)
        if not self.relocations and not self.unknown_pages:
            raise BaselineError("relocated_without_relocation_evidence")
        self.relocation_starts = sorted(self.relocations)

    def check_headers(self, memory_headers: bytes) -> None:
        mapped = memory_headers[:len(self.headers)]
        if len(mapped) != len(self.headers):
            raise BaselineError("incomplete_mapping_headers")
        start, end = self.imagebase_offset, self.imagebase_offset + self.pointer_width
        live_base = int.from_bytes(mapped[start:end], "little")
        if live_base not in (self.preferred_base, self.module_base):
            raise BaselineError("mapped_imagebase_mismatch")
        normalized = mapped[:start] + self.headers[start:end] + mapped[end:]
        if normalized != self.headers:
            raise BaselineError("mapped_headers_differ_from_disk")

    def section_for_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.start <= rva < section.end:
                return section
        return None

    def raw_bytes(self, rva: int, size: int) -> bytes:
        section = self.section_for_rva(rva)
        if section is None or rva + size > section.end:
            raise BaselineError("rva_outside_raw_backing")
        offset = section.offset + (rva - section.start)
        return self.data[offset:offset + size]

    def expected(self, section: Section, rva: int, size: int) -> bytes:
        end = rva + size
        if not section.start <= rva < end <= section.end:
            raise BaselineError("range_outside_disk_backing")
        if any(page in self.unknown_pages for page in range(rva & -PAGE_SIZE, end, PAGE_SIZE)):
            raise BaselineError("unsupported_relocation")
        offset = section.offset + (rva - section.start)
        expected = bytearray(self.data[offset:offset + size])
        index = bisect_left(self.relocation_starts, rva - 7)
        while index < len(self.relocation_starts) and (where := self.relocation_starts[index]) < end:
            index += 1
            width = self.relocations[where]
            if where + width <= rva:
                continue
            if where < section.start or where + width > section.end:
                raise BaselineError("relocation_outside_disk_backing")
            disk_offset = section.offset + (where - section.start)
            old = int.from_bytes(self.data[disk_offset:disk_offset + width], "little")
            rebased = ((old + self.delta) % (1 << (8 * width))).to_bytes(width, "little")
            low, high = max(rva, where), min(end, where + width)
            expected[low - rva:high - rva] = rebased[low - where:high - where]
        return bytes(expected)


def load_baseline(path: Path, module_size: int, module_base: int) -> Baseline:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BaselineError("disk_file_unreadable") from exc
    if not 0 < len(data) <= MAX_FILE_BYTES:
        raise BaselineError("disk_file_budget")
    parser = lief.PE.ParserConfig()
    parser.parse_imports = True
    parser.parse_exports = True
    parser.parse_reloc = True
    parser.parse_signature = False
    parser.parse_rsrc = False
    parser.parse_exceptions = False
    image = lief.PE.parse(data, parser)
    if image is None:
        raise BaselineError("unparseable_disk_pe")
    return Baseline(data, image, module_size, module_base,
                    hashlib.sha256(data).hexdigest())
