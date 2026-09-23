"""Threat coverage: which attacks are still open, not just which boxes are unticked.

A POA&M answers "what is non-compliant". It does not answer the question a
security team actually asks: **what can still happen to us?**

CISA maps most SCuBA policies to MITRE ATT&CK techniques, which makes the
control set a bipartite graph: techniques on one side, policies that mitigate
them on the other. Once results are attached, a technique's *depth* is simply
how many of its mapped policies currently pass.

    depth 0  every mapped policy is failing -- nothing is stopping it
    depth 1  one policy stands between you and it
    depth 2+ defence in depth actually holds

This reframes prioritisation. Compliance severity ranks by SHALL vs SHOULD.
Threat coverage ranks by *how many techniques a fix fully closes*, and the two
orderings genuinely differ: a failing SHOULD that is the only remaining
mitigation for a technique matters more than a failing SHALL with two surviving
backstops.

This is coverage arithmetic over CISA's published mappings. It is **not** a
claim about real-world exploitability: "no remaining mapped mitigation" means
exactly that, and nothing more.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .models import Result, ScubaRun
from .parsers.baselines import BaselineCatalog


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: str
    name: str
    url: str
    mitigating: tuple[str, ...]      # policies CISA maps to this technique
    passing: tuple[str, ...]         # of those, the ones currently passing
    failing: tuple[str, ...]         # of those, the ones currently not

    @property
    def depth(self) -> int:
        """Surviving mitigations. Zero means nothing mapped is stopping it."""
        return len(self.passing)

    @property
    def is_uncovered(self) -> bool:
        return self.depth == 0

    @property
    def is_degraded(self) -> bool:
        return self.depth > 0 and bool(self.failing)

    @property
    def status(self) -> str:
        if self.is_uncovered:
            return "uncovered"
        return "degraded" if self.failing else "covered"


@dataclass
class CoverageReport:
    techniques: dict[str, TechniqueCoverage] = field(default_factory=dict)

    def of(self, *statuses: str) -> list[TechniqueCoverage]:
        out = [t for t in self.techniques.values() if t.status in statuses]
        # Most exposed first: fewest survivors, then most failing policies.
        return sorted(out, key=lambda t: (t.depth, -len(t.failing), t.technique_id))

    @property
    def uncovered(self) -> list[TechniqueCoverage]:
        return self.of("uncovered")

    @property
    def degraded(self) -> list[TechniqueCoverage]:
        return self.of("degraded")

    def counts(self) -> dict[str, int]:
        out = {"uncovered": 0, "degraded": 0, "covered": 0}
        for technique in self.techniques.values():
            out[technique.status] += 1
        return out

    def techniques_closed_by(self, policy_id: str) -> list[str]:
        """Techniques that would reach depth >= 1 if this one policy were fixed.

        This is the ranking signal compliance severity cannot express: the value
        of a fix measured in attacks it actually stops.
        """
        closed = []
        for technique in self.techniques.values():
            if technique.is_uncovered and policy_id in technique.failing:
                closed.append(technique.technique_id)
        return sorted(closed)

    def remediation_ranking(self, limit: int = 10) -> list[tuple[str, list[str]]]:
        """Failing policies ordered by how many uncovered techniques each closes."""
        impact: dict[str, list[str]] = defaultdict(list)
        for technique in self.uncovered:
            for policy_id in technique.failing:
                impact[policy_id].append(technique.technique_id)
        ranked = sorted(impact.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        return [(policy, sorted(techniques)) for policy, techniques in ranked[:limit]]


def build_coverage(run: ScubaRun, baselines: BaselineCatalog) -> CoverageReport:
    """Join assessment results onto CISA's ATT&CK mappings."""
    assessed = {p.policy_id: p for p in run.policies}
    techniques: dict[str, dict] = {}

    for policy in baselines.policies:
        result = assessed.get(policy.policy_id)
        if result is None:
            continue  # not assessed in this run
        # N/A is neither a mitigation nor a gap, so it does not count either way.
        if result.result is Result.NOT_APPLICABLE:
            continue

        for technique in policy.mitre:
            if not technique.technique_id:
                continue
            entry = techniques.setdefault(
                technique.technique_id,
                {"name": technique.name, "url": technique.url, "pass": [], "fail": []},
            )
            bucket = "pass" if result.result is Result.PASS else "fail"
            entry[bucket].append(policy.policy_id)

    report = CoverageReport()
    for tid, entry in techniques.items():
        report.techniques[tid] = TechniqueCoverage(
            technique_id=tid,
            name=entry["name"],
            url=entry["url"],
            mitigating=tuple(sorted(entry["pass"] + entry["fail"])),
            passing=tuple(sorted(entry["pass"])),
            failing=tuple(sorted(entry["fail"])),
        )
    return report
