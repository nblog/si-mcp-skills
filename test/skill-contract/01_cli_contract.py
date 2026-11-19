# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = ["mcp==1.30.0", "lief==1.0.0", "capstone==5.0.9", "typer==0.20.0", "pydantic==2.12.5"]
# ///

"""Contract checks for the hook-detect Typer entry point."""

import subprocess
import sys
import unittest
from pathlib import Path

from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "hook-detect"
ENTRY = SKILL / "scripts" / "hook_detect.py"
LIBRARY = SKILL / "scripts" / "lib"


class SkillContractTests(unittest.TestCase):
    def test_skill_metadata_and_routing_boundary(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^name: hook-detect$")
        self.assertIn("Read-only System Informer MCP scanner", text)
        self.assertIn("Do not use for process mutation", text)
        self.assertIn("references/output.md", text)

    def test_cli_commands_and_explicit_target_options(self):
        completed = subprocess.run(
            [sys.executable, str(ENTRY), "--help"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        for command in ("module", "process", "verify-transport"):
            self.assertIn(command, completed.stdout)
        module_help = subprocess.run(
            [sys.executable, str(ENTRY), "module", "--help"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout
        for option in ("--simcp", "--sha256", "--pid", "--module", "--phase", "--workers"):
            self.assertIn(option, module_help)
        self.assertIn("NAME@BASE", module_help)

    def test_entry_declares_pinned_dependencies_and_hard_read_limit(self):
        text = ENTRY.read_text(encoding="utf-8")
        for dependency in ("mcp==1.30.0", "lief==1.0.0", "capstone==5.0.9",
                           "typer==0.20.0", "pydantic==2.12.5"):
            self.assertIn(dependency, text)
        config = (SKILL / "scripts" / "lib" / "config.py").read_text(encoding="utf-8")
        self.assertIn("max_read_bytes: Literal[65535] = Field(", config)
        self.assertIn("max_memory_bytes: Literal[64 * 1024 * 1024, 0] = Field(", config)
        self.assertIn('model_config = ConfigDict(strict=True, extra="forbid")', config)

    def test_every_configuration_field_has_a_description(self):
        sys.path.insert(0, str(LIBRARY))
        try:
            from config import ScanConfig, TransportConfig
        finally:
            sys.path.remove(str(LIBRARY))

        for model in (ScanConfig, TransportConfig):
            with self.subTest(model=model.__name__):
                self.assertTrue(issubclass(model, BaseModel))
                missing = [name for name, field in model.model_fields.items()
                           if not field.description]
                self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
