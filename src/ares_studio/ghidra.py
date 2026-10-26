"""Optional Ghidra headless integration; user must explicitly enable and configure it."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .core import Analysis

DEFAULT_TIMEOUT = 180
MAX_OUTPUT_BYTES = 2 * 1024 * 1024


class GhidraError(RuntimeError):
    pass


def locate_headless(ghidra_dir: str | Path) -> Path:
    base = Path(ghidra_dir).expanduser().resolve()
    script = base / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not script.is_file():
        raise GhidraError("Ghidra's support/analyzeHeadless was not found; select Ghidra root folder")
    return script


def export_functions(analysis: Analysis, ghidra_dir: str | Path, timeout: int = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """Run Ghidra only after user approval, with a disposable temp project."""
    if timeout < 15 or timeout > 600:
        raise GhidraError("Timeout must be between 15 and 600 seconds")
    binary = Path(analysis.path).resolve(strict=True)
    script = locate_headless(ghidra_dir)
    scripts_dir = Path(__file__).resolve().parent / "resources"
    # When packaged, a copy is placed in _MEIPASS/scripts/ghidra.
    if not scripts_dir.is_dir():
        import sys
        scripts_dir = Path(getattr(sys, "_MEIPASS", "")) / "scripts" / "ghidra"
    if not (scripts_dir / "ExportFunctions.py").is_file():
        raise GhidraError("Required ExportFunctions.py integration script is missing")
    with tempfile.TemporaryDirectory(prefix="ares-ghidra-") as root:
        base = Path(root)
        target = base / "functions.json"
        args = [str(script), str(base), "ARES_Temp", "-import", str(binary),
                "-scriptPath", str(scripts_dir), "-postScript", "ExportFunctions.py", str(target),
                "-analysisTimeoutPerFile", str(min(timeout - 5, 540)), "-deleteProject"]
        try:
            completed = subprocess.run(args, shell=False, capture_output=True, text=True,
                                       timeout=timeout, check=False, errors="replace")
        except subprocess.TimeoutExpired as exc:
            raise GhidraError(f"Ghidra analysis timed out after {timeout}s") from exc
        except OSError as exc:
            raise GhidraError(f"Could not launch Ghidra: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout)[-1500:]
            raise GhidraError(f"Ghidra exited with status {completed.returncode}: {detail}")
        if not target.is_file() or target.stat().st_size > MAX_OUTPUT_BYTES:
            raise GhidraError("Ghidra did not create a valid bounded function export")
        try:
            content = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise GhidraError("Could not parse Ghidra function export") from exc
        if not isinstance(content, list):
            raise GhidraError("Unexpected Ghidra output")
        return [item for item in content[:80] if isinstance(item, dict)]
