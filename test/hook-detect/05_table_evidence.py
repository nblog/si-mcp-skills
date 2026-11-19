# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["mcp==1.30.0", "lief==1.0.0", "capstone==5.0.9", "typer==0.20.0", "pydantic==2.12.5"]
# ///

"""Offline EAT comparison and semantic IAT resolution checks."""

import struct
import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_evidence import ExportSymbol, Section, Baseline


def load_table_probe():
    path = Path(__file__).with_name("04_wxwork_eat_iat.py")
    spec = importlib.util.spec_from_file_location("wxwork_table_probe", path)
    loader = spec.loader if spec is not None else None
    if spec is None or loader is None:
        raise RuntimeError("table probe module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


table_probe = load_table_probe()


EXPORT_DESCRIPTOR = struct.Struct("<IIHHIIIIIII")


def export_fixture():
    baseline = Baseline.__new__(Baseline)
    baseline.export_directory = (0x1000, 0x1000)
    baseline.data = bytearray(0x3000)
    baseline.sections = [Section(0x1000, 0x3000, 0, False)]
    descriptor = (0, 0, 0, 0, 0x1200, 1, 3, 3,
                  0x1100, 0x1140, 0x1148)
    EXPORT_DESCRIPTOR.pack_into(baseline.data, 0, *descriptor)
    struct.pack_into("<III", baseline.data, 0x100, 0x2000, 0x2004, 0x1210)
    struct.pack_into("<III", baseline.data, 0x140, 0x200, 0x204, 0x220)
    struct.pack_into("<HHH", baseline.data, 0x148, 0, 1, 2)
    baseline.data[0x200:0x204] = b"one\0"
    baseline.data[0x204:0x208] = b"two\0"
    baseline.data[0x210:0x21b] = b"host.real\0"
    baseline.data[0x220:0x22a] = b"forwarded\0"
    baseline.exports_by_ordinal = {
        1: [ExportSymbol("one", 0x2000, 1, False)],
        2: [ExportSymbol("two", 0x2004, 2, False)],
        3: [ExportSymbol("forwarded", 0x1210, 3, True, "host", "real")],
    }
    remote = {
        "status": "present",
        "descriptor": {
            "flags": 0, "timestamp": 0, "version": [0, 0], "name_rva": 0x1200,
            "ordinal_base": 1, "function_count": 3, "name_count": 3,
            "functions_rva": 0x1100, "names_rva": 0x1140, "ordinals_rva": 0x1148,
        },
        "slots": [0x2000, 0x2004, 0x1210],
        "names": {"one": [0], "two": [1], "forwarded": [2]},
        "blob_rva": 0x1000,
        "blob": bytes(baseline.data),
    }
    return baseline, remote


class TableTests(unittest.IsolatedAsyncioTestCase):
    def test_equal_and_modified_eat(self):
        baseline, remote = export_fixture()
        self.assertEqual(table_probe.compare_exports(None, baseline, remote)["status"], "equal")
        remote["slots"][1] = 0x2bad
        result = table_probe.compare_exports(None, baseline, remote)
        self.assertEqual(result["status"], "modified")
        self.assertEqual(result["findings"][0]["export"], "two")
        self.assertEqual(result["findings"][0]["memory_rva"], 0x2bad)

    def test_eat_forwarder_string_mismatch(self):
        baseline, remote = export_fixture()
        remote["blob"] = bytearray(remote["blob"])
        remote["blob"][0x210:0x21b] = b"host.other\0"
        result = table_probe.compare_exports(None, baseline, remote)
        self.assertEqual(result["forwarder_strings_compared"], 1)
        self.assertEqual(result["status"], "modified")
        self.assertEqual(result["findings"][0]["status"], "forwarder_string_mismatch")

    async def test_iat_direct_and_forwarded_expected_addresses(self):
        resolver = table_probe.DependencyResolver.__new__(table_probe.DependencyResolver)
        resolver.rows = {}
        resolver.cache = {}
        def add(name, base, symbol):
            row = table_probe.probe.ModuleRow(name, f"C:/fixture/{name}", "wow64_module",
                                              base, 0x10000, None)
            dependency = Baseline.__new__(Baseline)
            dependency.preferred_base = 0x10000000
            dependency.exports = {symbol.name: [symbol]}
            dependency.exports_by_ordinal = {symbol.ordinal: [symbol]}
            resolver.rows[name.casefold()] = [row]
            resolver.cache[row.key] = dependency
            return row
        direct = add("dep.dll", 0x20000000, ExportSymbol("Target", 0x1234, 1, False))
        forwarded = ExportSymbol("Forwarded", 0x1000, 2, True, "host", "Real")
        add("forward.dll", 0x30000000, forwarded)
        host = add("host.dll", 0x40000000, ExportSymbol("Real", 0x2345, 3, False))

        async def fixed_baseline(row):
            return resolver.cache[row.key]
        resolver.baseline = fixed_baseline
        self.assertEqual(await resolver.resolve("dep.dll", "Target", 0, False),
                         (0x20001234, direct, "resolved"))
        expected = await resolver.resolve("forward.dll", "Forwarded", 0, False)
        self.assertEqual((expected[0], expected[1]), (0x40002345, host))


if __name__ == "__main__":
    unittest.main()
