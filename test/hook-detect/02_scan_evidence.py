# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["lief==1.0.0", "capstone==5.0.9"]
# ///

"""Offline checks for export-entry patch and jump classification."""

import unittest

from capstone import CS_MODE_32

from scan_evidence import (PATCH_BLOCK_SIZE, Baseline, ScanGap, Section, classify_region_patch,
                           diff_runs, window_result)


MODE = CS_MODE_32
ADDRESS = 0x10000000
DIRECT_TARGET = ADDRESS + 5


class ScanEvidenceTests(unittest.TestCase):
    def test_equal_window_has_no_finding(self):
        data = bytes.fromhex("8bff558bec")
        self.assertEqual(window_result(data, data, MODE, ADDRESS)["status"], "equal")

    def test_direct_jump_patch_reports_absolute_target(self):
        disk = bytes.fromhex("8bff558bec")
        live = bytes.fromhex("e900000000")
        result = window_result(disk, live, MODE, ADDRESS)
        self.assertEqual(result["status"], "inline_candidate")
        self.assertEqual(result["jump_kind"], "direct")
        self.assertEqual(result["branch_target"], DIRECT_TARGET)
        self.assertLess(result["changed_bytes"], PATCH_BLOCK_SIZE)

    def test_return_patch_is_not_reported_as_redirect(self):
        disk = bytes.fromhex("8bff558bec5dc20400")
        live = bytes.fromhex("33c0c20400cccccccc")
        result = window_result(disk, live, MODE, ADDRESS)
        self.assertEqual(result["status"], "entry_return_patch")
        self.assertEqual(result["return_offset"], 2)
        self.assertNotIn("branch_target", result)

    def test_jump_at_second_instruction_stays_patch(self):
        disk = bytes.fromhex("8bff558bec909090")
        live = bytes.fromhex("8bffe90000000090")
        self.assertEqual(window_result(disk, live, MODE, ADDRESS)["status"], "patch")

    def test_relocation_spanning_two_accepted_reads(self):
        baseline = Baseline.__new__(Baseline)
        baseline.data = bytes.fromhex("ff2588120810cccc")
        baseline.relocations = {0x1002: 4}
        baseline.reloc_starts = [0x1002]
        baseline.unknown_pages = set()
        baseline.delta = 0x1000000
        section = Section(0x1000, 0x1008, 0, True)
        actual = baseline.expected(section, 0x1000, 4) + baseline.expected(section, 0x1004, 4)
        self.assertEqual(actual, bytes.fromhex("ff2588120811cccc"))
        self.assertEqual(window_result(actual, actual, MODE, ADDRESS + 0x1000)["status"], "equal")

    def test_short_compare_is_rejected(self):
        self.assertEqual(diff_runs(b"123456", b"023006"), [(0, 1), (3, 5)])
        with self.assertRaisesRegex(ScanGap, "incomplete_compare"):
            diff_runs(b"123456", b"02300")

    def test_region_diff_finds_hook_after_unchanged_prologue(self):
        disk = bytes.fromhex("8bff558bec909090909090")
        live = bytes.fromhex("8bff558bec90e900000000")
        got = classify_region_patch(disk, live, MODE, 0x10000000)
        self.assertEqual(got["offset"], 6)
        self.assertEqual(got["status"], "inline_candidate")
        self.assertEqual(got["jump_kind"], "direct")
        self.assertEqual(got["branch_target"], 0x1000000b)

    def test_operand_change_inside_existing_instruction_is_not_inline(self):
        disk = bytes.fromhex("ff2510124010909090")
        live = bytes.fromhex("ff2520124010909090")
        got = classify_region_patch(disk, live, MODE, 0x10000000)
        self.assertEqual((got["status"], got["offset"], got["size"]), ("patch", 2, 1))


if __name__ == "__main__":
    unittest.main()
