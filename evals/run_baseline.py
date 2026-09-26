#!/usr/bin/env python
"""Ungrounded baseline: the same questions, the same scorer, no tools.

Our central claim is that putting the model behind a wall of pure functions
over validated artifacts produces answers you can trust. That claim is only
meaningful if the obvious alternative measurably does worse -- otherwise the
architecture is ceremony.

So this runs the identical 15 golden questions against the same model with the
raw ScubaGear assessment dumped into its context and **no tools at all**. That
is what a straightforward implementation looks like, and it is the fair
comparison: same model, same questions, same grading, same data. The only
variable is the architecture.

The result is informative because of what ScubaGear output does *not* contain.
It has policy IDs, requirements and pass/fail. It has **no NIST 800-53
mappings, no MITRE ATT&CK techniques, no CISA rationale and no remediation
guidance** -- all of which our pipeline supplies by integrating CISA's
baselines and crosswalk. An ungrounded model asked for those either declines,
or invents them. Both outcomes are worth measuring, and the second is the one
that matters.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scuba_oscal.parsers.scubagear import parse_run  # noqa: E402

# The Foundry SDK is imported inside main() rather than here on purpose:
# compare.py imports compact_assessment() from this module to rebuild the
# ungrounded arm's context, and that analysis is entirely offline. Importing
# the SDK at module scope made the offline comparison impossible to re-run
# without Azure credentials installed.

sys.path.insert(0, str(ROOT / "evals"))
from run_eval import GOLDEN, score  # noqa: E402

SAMPLE = ROOT / "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"
RESULTS = ROOT / "evals/baseline_results.json"

INSTRUCTIONS = """You are a Microsoft 365 security compliance assistant.

Below is the complete ScubaGear assessment output for the tenant you are being
asked about. Answer the user's questions using it.

{data}
"""


def compact_assessment() -> str:
    """The assessment as a naive implementation would paste it into a prompt."""
    run = parse_run(SAMPLE)
    return json.dumps(
        {
            "tenant": run.tenant_display_name,
            "tool_version": run.tool_version,
            "assessed_at": run.timestamp.isoformat(),
            "policies": [
                {
                    "id": p.policy_id,
                    "requirement": p.requirement,
                    "result": p.result.value,
                    "criticality": p.criticality.value,
                    "product": p.product,
                    "details": p.details[:220],
                }
                for p in run.policies
            ],
        },
        indent=1,
    )


async def main() -> int:
    from agent_framework import Agent
    from agent_framework.foundry import FoundryChatClient
    from azure.identity.aio import AzureCliCredential

    from scuba_oscal.agents.orchestrator import FoundryConfig

    cases = json.loads(GOLDEN.read_text())["cases"]
    config = FoundryConfig.from_env(ROOT / ".env")
    data = compact_assessment()
    print(f"  context: {len(data):,} chars of raw ScubaGear output, no tools\n")

    results = []
    started = time.time()

    async with AzureCliCredential() as credential:
        client = FoundryChatClient(
            project_endpoint=config.endpoint, model=config.model, credential=credential
        )
        agent = Agent(client=client, name="Ungrounded", instructions=INSTRUCTIONS.format(data=data))

        for index, case in enumerate(cases, 1):
            t0 = time.time()
            try:
                answer = (await agent.run(case["question"])).text
            except Exception as exc:
                answer = f"ERROR: {exc}"
            outcome = score(case, answer)
            outcome["latency_s"] = round(time.time() - t0, 1)
            outcome["answer"] = answer[:900]
            results.append(outcome)
            mark = "PASS" if outcome["passed"] else "FAIL"
            print(f"  [{index:>2}/{len(cases)}] {mark}  {case['id']:<26} {outcome['latency_s']:>5.1f}s")

    total = len(results)
    passed = sum(r["passed"] for r in results)
    summary = {
        "arm": "ungrounded (raw ScubaGear JSON in context, no tools)",
        "total_cases": total,
        "passed": passed,
        "pass_rate": round(100 * passed / total, 1),
        "total_runtime_s": round(time.time() - started, 1),
    }

    print("\n" + "=" * 58)
    print(f"  UNGROUNDED pass rate   {summary['pass_rate']}%   ({passed}/{total})")
    print("=" * 58)
    print("\n  Failures:")
    for r in results:
        if not r["passed"]:
            why = []
            if r["missing_terms"]:
                why.append(f"missing {r['missing_terms']}")
            if r["forbidden_terms_present"]:
                why.append(f"asserted {r['forbidden_terms_present']}")
            if not r["citation_ok"]:
                why.append("no citation")
            print(f"    {r['id']:<28} {'; '.join(why)}")

    RESULTS.write_text(json.dumps({"summary": summary, "cases": results}, indent=2))
    print(f"\n  written to {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
