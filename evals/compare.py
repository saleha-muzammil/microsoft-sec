#!/usr/bin/env python
"""Head-to-head: grounded architecture vs. the obvious implementation.

Pass rate alone understates the difference, because a substring grader cannot
tell a *correct* answer from a *lucky* one. What actually separates the two
arms is **fabrication**: asserting a specific, checkable identifier that was
never in the model's context and that it therefore could not have known.

This detects that mechanically. For each answer we extract every NIST 800-53
control ID and MITRE ATT&CK technique ID asserted, and check whether it
appeared in the context the model was given. Anything asserted but absent was
produced from model memory, not from evidence -- regardless of whether it
happens to be right.

That distinction is the entire argument of this project. A compliance artifact
is not improved by a guess that turns out correct; it is a document someone
will act on, and "unverifiable but often right" is not a standard an auditor
can accept.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "evals"))

# No trailing \b: a word boundary cannot follow ")", which silently truncated
# "AC-2(12)" to "AC-2" and lost exactly the enhancement-level precision that
# distinguishes a correct mapping from a wrong one (CM-7 vs IA-2(1)).
NIST_ID = re.compile(r"\b[A-Z]{2}-\d+(?:\(\d+\))*[a-z]?")
ATTACK_ID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

GROUNDED = ROOT / "evals/results.json"
BASELINE = ROOT / "evals/baseline_results.json"
REPORT = ROOT / "evals/comparison.json"


def asserted_identifiers(text: str) -> set[str]:
    return set(NIST_ID.findall(text)) | set(ATTACK_ID.findall(text))


def analyse(cases: list[dict], context: str, label: str) -> dict:
    """Count identifiers asserted that were not available to the model."""
    available = asserted_identifiers(context)
    unsupported: list[tuple[str, list[str]]] = []
    total_unsupported = 0

    for case in cases:
        claimed = asserted_identifiers(case.get("answer", ""))
        missing = sorted(claimed - available)
        if missing:
            unsupported.append((case["id"], missing))
            total_unsupported += len(missing)

    return {
        "arm": label,
        "cases": len(cases),
        "passed": sum(c["passed"] for c in cases),
        "pass_rate": round(100 * sum(c["passed"] for c in cases) / len(cases), 1),
        "answers_with_unsupported_identifiers": len(unsupported),
        "unsupported_identifier_count": total_unsupported,
        "detail": [{"case": cid, "asserted_but_absent": ids} for cid, ids in unsupported],
    }


def main() -> int:
    if not (GROUNDED.exists() and BASELINE.exists()):
        print("Run evals/run_eval.py and evals/run_baseline.py first.")
        return 1

    grounded = json.loads(GROUNDED.read_text())
    baseline = json.loads(BASELINE.read_text())

    from run_baseline import compact_assessment

    raw_context = compact_assessment()

    # The grounded arm's "context" is everything its tools can reach: the
    # validated OSCAL documents. An identifier appearing there is evidenced.
    oscal_context = "\n".join(
        p.read_text() for p in sorted((ROOT / "data/oscal_out").glob("*.json"))
    )

    ungrounded = analyse(baseline["cases"], raw_context, "ungrounded (raw JSON, no tools)")
    tooled = analyse(grounded["cases"], oscal_context, "grounded (tools over validated OSCAL)")

    print("=" * 72)
    print(f"  {'':<42}{'GROUNDED':>13}{'UNGROUNDED':>15}")
    print("-" * 72)
    print(f"  {'Pass rate':<42}{tooled['pass_rate']:>12}%{ungrounded['pass_rate']:>14}%")
    print(f"  {'Answers asserting unsupported facts':<42}"
          f"{tooled['answers_with_unsupported_identifiers']:>13}"
          f"{ungrounded['answers_with_unsupported_identifiers']:>15}")
    print(f"  {'Total unsupported identifiers':<42}"
          f"{tooled['unsupported_identifier_count']:>13}"
          f"{ungrounded['unsupported_identifier_count']:>15}")
    print("=" * 72)

    if ungrounded["detail"]:
        print("\n  Identifiers the ungrounded model asserted but was never given:")
        for row in ungrounded["detail"]:
            print(f"    {row['case']:<28} {', '.join(row['asserted_but_absent'])}")

    REPORT.write_text(json.dumps({"grounded": tooled, "ungrounded": ungrounded}, indent=2))
    print(f"\n  written to {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
