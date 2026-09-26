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

**What this measure does and does not show.** "Available" is evaluated against
the whole corpus each arm could reach: the raw ScubaGear dump for the
ungrounded arm, the full OSCAL document set for the grounded one. That is the
right comparison for the question being asked -- *could this identifier have
come from evidence at all?* -- and the answer for the ungrounded arm is a flat
no, because the ScubaGear file contains no NIST or ATT&CK identifiers
whatsoever.

It is deliberately **not** a per-answer citation check. The catalog carries
every NIST and ATT&CK identifier in scope, so a grounded answer scores as
supported if the identifier exists anywhere in the artifacts, even if that
particular conversation's tool calls did not return it. Tightening this to
per-conversation tool output would be strictly better and needs the eval
harness to record tool traffic, which it does not yet do. So read the grounded
arm's zero as *no identifier was invented from outside the evidence base*, not
as *every identifier was individually cited*.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "evals"))

# One detector, two uses: the identifier extraction lives in
# scuba_oscal.grounding, where the app runs it on every live answer. Importing
# it here means the number in the published comparison and the badge on screen
# come from the same tested code, not two implementations that could drift.
from scuba_oscal.grounding import asserted_identifiers  # noqa: E402

GROUNDED = ROOT / "evals/results.json"
BASELINE = ROOT / "evals/baseline_results.json"
REPORT = ROOT / "evals/comparison.json"


def analyse(
    cases: list[dict],
    context: str,
    label: str,
    questions: dict[str, str] | None = None,
) -> dict:
    """Count identifiers asserted that were not available to the model.

    *questions* (case id -> question text) exempts identifiers the question
    itself supplied: repeating one back — usually to deny it exists — is
    quotation, not fabrication. Applied to both arms, so neither is penalised
    for correctly refusing the trap question. The exemption never *hides* a
    fabrication elsewhere in an answer; it only stops the trap's own bait
    from counting against the arm that refused it.
    """
    available = asserted_identifiers(context)
    unsupported: list[tuple[str, list[str]]] = []
    total_unsupported = 0

    for case in cases:
        claimed = asserted_identifiers(case.get("answer", ""))
        asked = asserted_identifiers((questions or {}).get(case["id"], ""))
        missing = sorted(claimed - available - asked)
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
    # validated OSCAL documents plus the shipped crosswalk data — the same
    # corpus definition the live app audits against. An identifier appearing
    # there is evidenced.
    oscal_context = "\n".join(
        [p.read_text() for p in sorted((ROOT / "data/oscal_out").glob("*.json"))]
        + [p.read_text() for p in sorted((ROOT / "data/mappings").glob("*.csv"))]
    )

    golden = json.loads((ROOT / "evals/golden_set.json").read_text())
    questions = {c["id"]: c.get("question", "") for c in golden["cases"]}

    ungrounded = analyse(
        baseline["cases"], raw_context, "ungrounded (raw JSON, no tools)", questions
    )
    tooled = analyse(
        grounded["cases"], oscal_context, "grounded (tools over validated OSCAL)", questions
    )

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
