#!/usr/bin/env python
"""Validate every generated OSCAL document. Exit non-zero on any failure."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scuba_oscal.validation import cli_available, summarise, validate_directory  # noqa: E402


def main(directory: str = "data/oscal_out") -> int:
    if not sorted(Path(directory).glob("*.json")):
        print(f"No OSCAL documents found in {directory}")
        print("Run `python scripts/generate.py` first.")
        return 1

    # Say up front which tier is actually running. Reporting schema-only
    # results under a heading that implies NIST Metaschema validation is
    # exactly the overstatement this script exists to avoid.
    if not cli_available():
        print(
            "WARNING: oscal-cli is not installed, so only JSON Schema validation runs.\n"
            "         Run ./scripts/install_tools.sh for full NIST Metaschema validation.\n"
        )

    reports = validate_directory(directory)
    for report in reports:
        print(report)
        if not report.ok:
            for err in report.errors:
                print(f"       {err}")

    counts = summarise(reports)
    print(f"\n{counts['documents'] - counts['failed']}/{counts['documents']} documents valid")
    print(f"  JSON Schema : {counts['schema_valid']}/{counts['documents']}")
    if cli_available():
        print(
            f"  oscal-cli   : {counts['cli_valid']}/{counts['documents']}"
            f"  ({counts['cli_not_applicable']} unsupported by oscal-cli 3.2.0)"
        )
    else:
        print("  oscal-cli   : not run (not installed)")
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
