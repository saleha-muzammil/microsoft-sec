#!/usr/bin/env python
"""Evaluate the Foundry agents against a golden question set.

Three metrics, all checkable rather than subjective:

* **Accuracy** - the answer contains the value the OSCAL artifacts actually hold.
* **Citation rate** - answers making policy-specific claims cite a SCuBA policy ID.
* **Hallucination resistance** - the model refuses to invent a control that does
  not exist, and does not reproduce a known-wrong third-party mapping.

Ground truth is derived from the generated artifacts, so the set cannot drift
away from the data it is meant to describe.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scuba_oscal.agents.orchestrator import ComplianceAssistant, FoundryConfig  # noqa: E402

POLICY_ID = re.compile(r"MS\.[A-Z0-9]+\.\d+\.\d+v\d+")
GOLDEN = ROOT / "evals/golden_set.json"
RESULTS = ROOT / "evals/results.json"


def score(case: dict, answer: str) -> dict:
    lowered = answer.lower()
    missing = [t for t in case.get("must_contain", []) if t.lower() not in lowered]
    forbidden = [t for t in case.get("must_not_contain", []) if t.lower() in lowered]
    cited = bool(POLICY_ID.search(answer))
    citation_ok = cited if case.get("must_cite_policy") else True

    return {
        "id": case["id"],
        "specialist": case["specialist"],
        "accurate": not missing and not forbidden,
        "missing_terms": missing,
        "forbidden_terms_present": forbidden,
        "cited_policy_id": cited,
        "citation_ok": citation_ok,
        "passed": not missing and not forbidden and citation_ok,
    }


async def main() -> int:
    cases = json.loads(GOLDEN.read_text())["cases"]
    config = FoundryConfig.from_env(ROOT / ".env")

    results = []
    started = time.time()

    async with ComplianceAssistant(ROOT / "data/oscal_out", config, audience="auditor") as bot:
        for index, case in enumerate(cases, 1):
            t0 = time.time()
            try:
                answer = await bot.ask(case["question"], case["specialist"])
            except Exception as exc:
                answer = f"ERROR: {exc}"
            outcome = score(case, answer)
            outcome["latency_s"] = round(time.time() - t0, 1)
            outcome["answer"] = answer[:600]
            results.append(outcome)
            mark = "PASS" if outcome["passed"] else "FAIL"
            print(f"  [{index:>2}/{len(cases)}] {mark}  {case['id']:<26} {outcome['latency_s']:>5.1f}s")
            if not outcome["passed"]:
                if outcome["missing_terms"]:
                    print(f"          missing: {outcome['missing_terms']}")
                if outcome["forbidden_terms_present"]:
                    print(f"          forbidden present: {outcome['forbidden_terms_present']}")
                if not outcome["citation_ok"]:
                    print("          no policy ID cited")

    total = len(results)
    passed = sum(r["passed"] for r in results)
    accurate = sum(r["accurate"] for r in results)
    cite_cases = [r for r in results if r["citation_ok"] is not None]
    cited = sum(r["cited_policy_id"] for r in results)
    latency = sum(r["latency_s"] for r in results) / total

    summary = {
        "total_cases": total,
        "passed": passed,
        "pass_rate": round(100 * passed / total, 1),
        "accuracy_rate": round(100 * accurate / total, 1),
        "citation_rate": round(100 * cited / len(cite_cases), 1),
        "mean_latency_s": round(latency, 1),
        "total_runtime_s": round(time.time() - started, 1),
    }

    print("\n" + "=" * 58)
    print(f"  Pass rate       {summary['pass_rate']}%   ({passed}/{total})")
    print(f"  Accuracy        {summary['accuracy_rate']}%")
    print(f"  Citation rate   {summary['citation_rate']}%")
    print(f"  Mean latency    {summary['mean_latency_s']}s")
    print("=" * 58)

    RESULTS.write_text(json.dumps({"summary": summary, "cases": results}, indent=2))
    print(f"\nwritten to {RESULTS.relative_to(ROOT)}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
