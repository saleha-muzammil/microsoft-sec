#!/usr/bin/env python
"""Validate every generated OSCAL document. Exit non-zero on any failure."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scuba_oscal.validation import validate_file  # noqa: E402


def main(directory: str = "data/oscal_out") -> int:
    files = sorted(Path(directory).glob("*.json"))
    if not files:
        print(f"No OSCAL documents found in {directory}")
        return 1

    failures = 0
    for path in files:
        report = validate_file(path)
        print(report)
        if not report.ok:
            failures += 1
            for err in report.errors:
                print(f"       {err}")

    print(f"\n{len(files) - failures}/{len(files)} documents valid")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
