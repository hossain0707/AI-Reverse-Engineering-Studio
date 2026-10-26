"""Deterministic offline reports; no binary bytes or secrets are uploaded."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .core import Analysis


def make_markdown(a: Analysis, ai: str = "", functions: list[dict] | None = None) -> str:
    lines = [f"# ARES Analysis Report — {a.name}", "", "## Binary metadata", "",
             f"- **SHA-256:** `{a.sha256}`", f"- **Type:** {a.file_type}",
             f"- **Architecture:** {a.architecture}", f"- **Size:** {a.size:,} bytes",
             f"- **Sample entropy:** {a.entropy:.3f} / 8", "",
             "## Sections", "", "| Name | File offset | Size | Executable |",
             "| --- | ---: | ---: | :---: |"]
    for s in a.sections:
        lines.append(f"| {s.name.replace('|','/')} | 0x{s.offset:X} | {s.size:,} | {'Yes' if s.executable else 'No'} |")
    lines.extend(["", "## Observations (not verdicts)", ""])
    lines.extend(f"- {i}" for i in (a.indicators or ["No heuristic indicators"]))
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {w}" for w in a.warnings)
    lines.extend(["- Static metadata is not proof of malicious behavior.",
                  "- Optional AI interpretations require independent validation."])
    if functions:
        lines.extend(["", "## Ghidra function listing", ""])
        lines.extend(f"- `{f.get('address','')}` — `{f.get('name','')}`" for f in functions[:80])
    if ai:
        lines.extend(["", "## Local AI interpretation (unverified)", "", ai[:30000]])
    lines.append("")
    return "\n".join(lines)


def write_report(path: str | Path, analysis: Analysis, ai: str = "", functions: list[dict] | None = None) -> None:
    output = Path(path)
    if output.suffix.lower() == ".json":
        doc = {"schema": "ares.report/v1", "generated_utc": datetime.now(timezone.utc).isoformat(),
               "analysis": analysis.as_dict(), "ai_interpretation": ai, "ghidra_functions": functions or []}
        output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        output.write_text(make_markdown(analysis, ai, functions), encoding="utf-8")
