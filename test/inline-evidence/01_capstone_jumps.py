# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["capstone==5.0.9"]
# ///

"""Verify what Capstone sees in synthetic x86/x64 byte windows."""

import unittest

from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86_const import X86_INS_JMP


class JumpEvidenceTests(unittest.TestCase):
    def test_direct_and_indirect_jumps_at_known_instruction_boundary(self):
        for mode in (CS_MODE_32, CS_MODE_64):
            for data in ("e9 00 00 00 00", "eb 00", "ff 25 00 00 00 00", "ff 24 24"):
                with self.subTest(mode=mode, data=data):
                    engine = Cs(CS_ARCH_X86, mode)
                    engine.detail = True
                    instruction = next(engine.disasm(bytes.fromhex(data), 0x1000))
                    self.assertEqual(instruction.id, X86_INS_JMP)
                    self.assertTrue(instruction.group(CS_GRP_JUMP))

    def test_opcode_bytes_inside_immediate_do_not_make_a_jump(self):
        engine = Cs(CS_ARCH_X86, CS_MODE_64)
        engine.detail = True
        instructions = list(engine.disasm(bytes.fromhex("b8 e9 eb ff 25 90"), 0x1000))
        self.assertEqual([i.size for i in instructions], [5, 1])
        self.assertFalse(any(i.group(CS_GRP_JUMP) for i in instructions))

    def test_truncated_relative_and_indirect_jumps_do_not_decode(self):
        engine = Cs(CS_ARCH_X86, CS_MODE_64)
        for data in ("e9 00", "eb", "ff 25", "ff 24"):
            with self.subTest(data=data):
                self.assertEqual(list(engine.disasm(bytes.fromhex(data), 0x1000)), [])


if __name__ == "__main__":
    unittest.main()
