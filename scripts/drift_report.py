#!/usr/bin/env python
"""Show posture drift between two ScubaGear runs, naive vs version-aware."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scuba_oscal.drift import compare, false_signal_count  # noqa: E402
from scuba_oscal.parsers.mappings import MappingIndex  # noqa: E402
from scuba_oscal.parsers.scubagear import parse_run  # noqa: E402

DEFAULT_BEFORE = "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"
DEFAULT_AFTER = "data/scubagear_samples/ScubaResults_followup_30d.json"


def main(before_path: str = DEFAULT_BEFORE, after_path: str = DEFAULT_AFTER) -> int:
    before = parse_run(ROOT / before_path)
    after = parse_run(ROOT / after_path)
    index = MappingIndex(
        ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv",
        ROOT / "data/mappings/scuba-baseline-policy-migrations.csv",
    )

    naive = compare(before, after, index.migrations, version_aware=False)
    aware = compare(before, after, index.migrations, version_aware=True)

    print(naive.summary(), end="\n\n")
    print(aware.summary(), end="\n\n")

    false_signals = false_signal_count(naive, aware)
    total = false_signals["total_false_events"]
    if total:
        print(
            f"Matching on identifier alone manufactures {total} false events "
            f"({false_signals.get('added', 0)} phantom new findings, "
            f"{false_signals.get('removed', 0)} phantom resolved findings) "
            f"from {len(aware.renumbered)} policies CISA renumbered."
        )
        print()

    print("Actual changes:")
    for delta in aware.deltas:
        if delta.kind.is_material:
            print(f"  [{delta.kind.value:<11}] {delta.description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
