"""Headless CLI for repeatable, scriptable static analysis."""

from __future__ import annotations

import argparse
import json
import sys

from .core import analyze
from .reporting import make_markdown, write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ares-cli", description="ARES static binary inspector")
    parser.add_argument("binary", help="Path to binary/sample (not executed)")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--out", help="Save report (.json or .md)")
    args = parser.parse_args(argv)
    try:
        result = analyze(args.binary)
        if args.out:
            if not args.out.lower().endswith((".json", ".md")):
                parser.error("Output must have .json or .md extension")
            write_report(args.out, result)
            print(f"Saved {args.out}")
        else:
            print(json.dumps(result.as_dict(), indent=2) if args.format == "json" else make_markdown(result))
        return 0
    except (OSError, ValueError) as exc:
        print(f"ARES error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
