"""Command-line interface.

    python analyzer.py samples/sample-1.eml
    python analyzer.py samples/*.eml --summary
    python analyzer.py samples/sample-2.eml --json > report.json
"""

from __future__ import annotations

import argparse
import sys

from .analysis import analyze_file
from .report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Triage .eml files for phishing indicators.",
    )
    parser.add_argument("files", nargs="+", help="one or more .eml files")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="output machine-readable JSON")
    output.add_argument("--summary", action="store_true", help="one line per file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    exit_code = 0

    for path in args.files:
        try:
            result = analyze_file(path)
        except OSError as e:  # missing file, permission denied...
            print(f"error: {path}: {e.strerror}", file=sys.stderr)
            exit_code = 1
            continue

        if args.json:
            print(to_json(result))
        elif args.summary:
            print(f"{result.score:>3}/100  {result.verdict:<16} {path}  |  {result.headers.subject[:60]}")
        else:
            print(to_text(result))
    return exit_code
