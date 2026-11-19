# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["lief==1.0.0"]
# ///

"""Check LIEF against synthetic PE file and mapped layouts; never load either."""

import struct
import unittest

import lief


RAW_OFFSET = 0x200
SECTION_RVA = 0x1000
EXPORT_RVA = SECTION_RVA + 0x80
SECTION_DATA = b"fixture-layout"


def fixture(bits: int) -> tuple[bytes, bytes, int]:
    """Return a tiny PE, an RVA-indexed copy, and its image base."""
    file = bytearray(0x400)
    file[:2] = b"MZ"
    struct.pack_into("<I", file, 0x3C, 0x80)
    file[0x80:0x84] = b"PE\0\0"
    machine, magic, optional_size, image_base = (
        (0x14C, 0x10B, 0xE0, 0x400000)
        if bits == 32 else (0x8664, 0x20B, 0xF0, 0x180000000)
    )
    struct.pack_into("<HHIIIHH", file, 0x84, machine, 1, 0, 0, 0, optional_size, 0x2002)
    optional = 0x98
    struct.pack_into("<H", file, optional, magic)
    struct.pack_into("<I" if bits == 32 else "<Q", file, optional + (28 if bits == 32 else 24), image_base)
    struct.pack_into("<II", file, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", file, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", file, optional + 68, 3)
    struct.pack_into("<III", file, optional + optional_size - 132, 16, EXPORT_RVA, 0x70)
    struct.pack_into(
        "<8sIIIIIIHHI", file, optional + optional_size,
        b".text", 0x150, SECTION_RVA, 0x200, RAW_OFFSET, 0, 0, 0, 0, 0x60000020,
    )
    file[RAW_OFFSET:RAW_OFFSET + len(SECTION_DATA)] = SECTION_DATA
    export = RAW_OFFSET + EXPORT_RVA - SECTION_RVA
    struct.pack_into(
        "<IIHHIIIIIII", file, export, 0, 0, 0, 0, EXPORT_RVA + 0x40, 1, 1, 1,
        EXPORT_RVA + 0x28, EXPORT_RVA + 0x2C, EXPORT_RVA + 0x30,
    )
    struct.pack_into("<IIH", file, export + 0x28, SECTION_RVA, EXPORT_RVA + 0x50, 0)
    file[export + 0x40:export + 0x4C] = b"fixture.dll\0"
    file[export + 0x50:export + 0x56] = b"entry\0"
    mapped = bytearray(0x2000)
    mapped[:RAW_OFFSET] = file[:RAW_OFFSET]
    mapped[SECTION_RVA:SECTION_RVA + 0x150] = file[RAW_OFFSET:RAW_OFFSET + 0x150]
    return bytes(file), bytes(mapped), image_base


class LayoutTests(unittest.TestCase):
    def test_file_and_mapped_parsers_read_the_same_section_and_export(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                file, mapped, base = fixture(bits)
                for binary in (lief.PE.parse(file), lief.PE.parse_from_dump(mapped, base)):
                    self.assertIsNotNone(binary)
                    section = binary.get_section(".text")
                    self.assertEqual(section.virtual_address, SECTION_RVA)
                    self.assertEqual(section.pointerto_raw_data, RAW_OFFSET)
                    self.assertEqual(bytes(section.content[:len(SECTION_DATA)]), SECTION_DATA)
                    self.assertEqual([(e.name, e.address) for e in binary.get_export().entries],
                                     [("entry", SECTION_RVA)])

    def test_file_parser_uses_wrong_offsets_on_mapped_input(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                _, mapped, _ = fixture(bits)
                parsed = lief.PE.parse(mapped)
                self.assertIsNotNone(parsed)
                self.assertNotEqual(bytes(parsed.get_section(".text").content[:len(SECTION_DATA)]), SECTION_DATA)
                exports = parsed.get_export()
                self.assertFalse(exports and any(e.name == "entry" for e in exports.entries))

    def test_first_page_declares_table_but_does_not_contain_it(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                _, mapped, base = fixture(bits)
                config = lief.PE.ParserConfig()
                config.parse_exports = False
                binary = lief.PE.parse_from_dump(mapped[:4096], base, config)
                self.assertIsNotNone(binary)
                directory = binary.data_directory(lief.PE.DataDirectory.TYPES.EXPORT_TABLE)
                self.assertEqual((directory.rva, directory.size), (EXPORT_RVA, 0x70))
                self.assertEqual(len(binary.get_section(".text").content), 0)
                self.assertIsNone(binary.get_export())


if __name__ == "__main__":
    lief.logging.disable()  # Deliberately incorrect/truncated input in two tests.
    unittest.main()
