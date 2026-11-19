# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mcp>=1.30.0",
#   "lief>=1.0.0",
#   "capstone>=5.0.9",
#   "pydantic>=2.12.5",
#   "typer>=0.20.0",
# ]
# ///

"""Read-only System Informer MCP hook-detect scanner."""

import asyncio
import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

LIBRARY = Path(__file__).resolve().parent / "lib"
sys.path.insert(0, str(LIBRARY))

from scan import compact_summary, live_scan, verify_transport


class Phase(str, Enum):
    inline = "inline"
    eat = "eat"
    iat = "iat"


app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Run bounded, read-only PE hook detection through System Informer MCP.")


def _write_report(path: Path, result: dict, budget) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    result["budget"] = budget.summary()
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def _validate_selection(all_modules: bool, modules: list[str] | None) -> None:
    if all_modules and modules:
        raise typer.BadParameter("Use either --all-modules or repeated --module, not both.")
    if not all_modules and not modules:
        raise typer.BadParameter("At least one --module is required unless --all-modules is set.")


@app.command()
def module(
    simcp: Annotated[Path, typer.Option(exists=True, dir_okay=False, resolve_path=True,
                                        help="Reviewed absolute simcp.exe path.")],
    sha256: Annotated[str, typer.Option(help="SHA-256 reviewed for simcp.exe.")],
    pid: Annotated[int, typer.Option(min=1, help="Target process PID.")],
    module_name: Annotated[list[str], typer.Option(
        "--module", min=1,
        help="Exact module name, or NAME@BASE hexadecimal address for duplicate names.")],
    process_name: Annotated[str, typer.Option(help="Exact process name used with the explicit PID.")],
    phase: Annotated[list[Phase] | None, typer.Option()] = None,
    workers: Annotated[int, typer.Option(min=1, max=8)] = 4,
    output: Annotated[Path, typer.Option(dir_okay=False, writable=True)] = Path("hook-detect-report.json"),
) -> None:
    """Scan explicitly selected modules in one process."""
    selected_phases = phase or list(Phase)
    result, budget = asyncio.run(live_scan(
        simcp, sha256, process_name, pid, module_name, False,
        {item.value for item in selected_phases}, workers,
    ))
    _write_report(output, result, budget)
    print(json.dumps(compact_summary(result, output.resolve()), indent=2, ensure_ascii=False))
    raise typer.Exit(0 if result["status"] == "passed" else 2)


@app.command(name="process")
def process(
    simcp: Annotated[Path, typer.Option(exists=True, dir_okay=False, resolve_path=True,
                                        help="Reviewed absolute simcp.exe path.")],
    sha256: Annotated[str, typer.Option(help="SHA-256 reviewed for simcp.exe.")],
    pid: Annotated[int, typer.Option(min=1, help="Target process PID.")],
    process_name: Annotated[str, typer.Option(help="Exact process name used with the explicit PID.")],
    all_modules: Annotated[bool, typer.Option("--all-modules/--selected-modules")] = False,
    module_name: Annotated[list[str] | None, typer.Option(
        "--module", help="Exact module name, or NAME@BASE hexadecimal address.")] = None,
    phase: Annotated[list[Phase] | None, typer.Option()] = None,
    workers: Annotated[int, typer.Option(min=1, max=8)] = 4,
    output: Annotated[Path, typer.Option(dir_okay=False, writable=True)] = Path("hook-detect-report.json"),
) -> None:
    """Scan selected or all modules in one explicitly identified process."""
    selected_phases = phase or list(Phase)
    _validate_selection(all_modules, module_name)
    result, budget = asyncio.run(live_scan(
        simcp, sha256, process_name, pid, module_name or [], all_modules,
        {item.value for item in selected_phases}, workers,
    ))
    _write_report(output, result, budget)
    print(json.dumps(compact_summary(result, output.resolve()), indent=2, ensure_ascii=False))
    raise typer.Exit(0 if result["status"] == "passed" else 2)


@app.command(name="verify-transport")
def verify_transport_command(
    simcp: Annotated[Path, typer.Option(exists=True, dir_okay=False, resolve_path=True,
                                        help="Reviewed absolute simcp.exe path.")],
    sha256: Annotated[str, typer.Option(help="SHA-256 reviewed for simcp.exe.")],
    output: Annotated[Path, typer.Option(dir_okay=False, writable=True)] = Path("hook-detect-transport.json"),
) -> None:
    """Verify SDK, structured responses, and self module metadata without memory reads."""
    result, budget = asyncio.run(verify_transport(simcp, sha256))
    _write_report(output, result, budget)
    print(json.dumps({
        "status": result["status"], "reason": result.get("reason"),
        "system_informer_version": result.get("system_informer_version"),
        "structured_content": result.get("structured_content"),
        "sampled_modules": result.get("sampled_modules"),
        "budget": result.get("budget"), "output": str(output.resolve()),
    }, indent=2))
    raise typer.Exit(0 if result["status"] == "passed" else 2)


if __name__ == "__main__":
    app()
