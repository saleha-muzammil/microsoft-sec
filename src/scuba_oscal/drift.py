"""Posture drift between two ScubaGear runs, surviving baseline version changes.

The problem every other drift tool gets wrong
---------------------------------------------
SCuBA policy identifiers are **versioned**, and CISA revises them. When a policy
is amended, its identifier changes: ``MS.EXO.2.2v2`` becomes ``MS.EXO.2.2v3``.

A drift tool that matches runs by identifier therefore reports a single amended
policy as **two** spurious events -- one control that "disappeared" and an
unrelated one that "appeared". If the old result was Fail and the new one Pass,
the naive output claims a finding was *resolved* and a *brand-new* finding
opened, when in reality the same requirement was simply renumbered.

That is not a cosmetic bug. It corrupts exactly the numbers a compliance report
is built on: how many findings opened, how many closed, and whether posture
improved.

CISA publishes the fix themselves, in ``scuba-baseline-policy-migrations.csv``.
We consume it, so identifiers are reconciled *before* results are compared.

``compare(..., version_aware=False)`` reproduces the naive behaviour, so the
difference can be demonstrated rather than merely asserted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .models import PolicyResult, Result, ScubaRun


class DriftKind(str, Enum):
    REGRESSION = "regression"          # was satisfied, now is not
    IMPROVEMENT = "improvement"        # was not satisfied, now is
    UNCHANGED = "unchanged"
    ADDED = "added"                    # newly assessed policy
    REMOVED = "removed"                # no longer assessed
    RENUMBERED = "renumbered"          # same requirement, new identifier

    @property
    def is_material(self) -> bool:
        """Whether this change should appear in a posture report."""
        return self in (DriftKind.REGRESSION, DriftKind.IMPROVEMENT,
                        DriftKind.ADDED, DriftKind.REMOVED)


@dataclass(frozen=True)
class PolicyDelta:
    policy_id: str
    kind: DriftKind
    before: Result | None = None
    after: Result | None = None
    previous_id: str | None = None     # set when the identifier changed
    requirement: str = ""

    @property
    def description(self) -> str:
        if self.kind is DriftKind.RENUMBERED:
            return f"{self.previous_id} renumbered to {self.policy_id}; result unchanged"
        if self.kind is DriftKind.ADDED:
            return f"{self.policy_id} newly assessed: {self.after.value}"
        if self.kind is DriftKind.REMOVED:
            return f"{self.policy_id} no longer assessed (was {self.before.value})"
        arrow = f"{self.before.value} -> {self.after.value}"
        if self.previous_id:
            return f"{self.previous_id} -> {self.policy_id}: {arrow}"
        return f"{self.policy_id}: {arrow}"


@dataclass
class DriftReport:
    before_run: str
    after_run: str
    version_aware: bool
    deltas: list[PolicyDelta] = field(default_factory=list)

    def of(self, *kinds: DriftKind) -> list[PolicyDelta]:
        return [d for d in self.deltas if d.kind in kinds]

    @property
    def regressions(self) -> list[PolicyDelta]:
        return self.of(DriftKind.REGRESSION)

    @property
    def improvements(self) -> list[PolicyDelta]:
        return self.of(DriftKind.IMPROVEMENT)

    @property
    def renumbered(self) -> list[PolicyDelta]:
        return self.of(DriftKind.RENUMBERED)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for delta in self.deltas:
            out[delta.kind.value] = out.get(delta.kind.value, 0) + 1
        return out

    def summary(self) -> str:
        counts = self.counts()
        mode = "version-aware" if self.version_aware else "naive (identifier match)"
        lines = [
            f"Posture drift ({mode})",
            f"  regressions : {counts.get('regression', 0)}",
            f"  improvements: {counts.get('improvement', 0)}",
            f"  added       : {counts.get('added', 0)}",
            f"  removed     : {counts.get('removed', 0)}",
            f"  renumbered  : {counts.get('renumbered', 0)}",
            f"  unchanged   : {counts.get('unchanged', 0)}",
        ]
        return "\n".join(lines)


def _satisfied(result: Result) -> bool:
    return result is Result.PASS


def compare(
    before: ScubaRun,
    after: ScubaRun,
    migrations: dict[str, str] | None = None,
    version_aware: bool = True,
) -> DriftReport:
    """Compare two runs.

    :param migrations: CISA's ``Old ID -> New ID`` table. Required for
        ``version_aware``; without it the comparison silently degrades to naive.
    :param version_aware: when False, match purely on identifier, reproducing
        the behaviour of tools that ignore baseline versioning.
    """
    migrations = migrations or {}
    report = DriftReport(
        before_run=before.run_id, after_run=after.run_id, version_aware=version_aware
    )

    def canonical(policy_id: str) -> str:
        """Follow the migration chain to the current identifier."""
        if not version_aware:
            return policy_id
        seen: set[str] = set()
        current = policy_id
        while current in migrations and current not in seen:
            seen.add(current)
            current = migrations[current]
        return current

    before_map: dict[str, PolicyResult] = {canonical(p.policy_id): p for p in before.policies}
    after_map: dict[str, PolicyResult] = {canonical(p.policy_id): p for p in after.policies}

    for key in sorted(before_map.keys() | after_map.keys()):
        old = before_map.get(key)
        new = after_map.get(key)

        if old is None and new is not None:
            report.deltas.append(
                PolicyDelta(
                    policy_id=new.policy_id, kind=DriftKind.ADDED,
                    after=new.result, requirement=new.requirement,
                )
            )
            continue
        if new is None and old is not None:
            report.deltas.append(
                PolicyDelta(
                    policy_id=old.policy_id, kind=DriftKind.REMOVED,
                    before=old.result, requirement=old.requirement,
                )
            )
            continue

        assert old is not None and new is not None
        # Only report a renumbering when the identifier genuinely changed.
        previous_id = old.policy_id if old.policy_id != new.policy_id else None

        if old.result == new.result:
            kind = DriftKind.RENUMBERED if previous_id else DriftKind.UNCHANGED
        elif _satisfied(old.result) and not _satisfied(new.result):
            kind = DriftKind.REGRESSION
        elif not _satisfied(old.result) and _satisfied(new.result):
            kind = DriftKind.IMPROVEMENT
        else:
            # e.g. Fail -> Warning: still unsatisfied, but the detail changed.
            kind = DriftKind.UNCHANGED

        report.deltas.append(
            PolicyDelta(
                policy_id=new.policy_id, kind=kind,
                before=old.result, after=new.result,
                previous_id=previous_id, requirement=new.requirement,
            )
        )

    return report


def false_signal_count(naive: DriftReport, aware: DriftReport) -> dict[str, int]:
    """Quantify what the naive comparison gets wrong.

    Returns the number of material events the naive run reports that the
    version-aware run does not - i.e. the phantom findings a renumbering
    manufactures.
    """
    aware_material = {(d.policy_id, d.kind) for d in aware.deltas if d.kind.is_material}
    naive_material = [d for d in naive.deltas if d.kind.is_material]
    phantom = [d for d in naive_material if (d.policy_id, d.kind) not in aware_material]
    out: dict[str, int] = {}
    for delta in phantom:
        out[delta.kind.value] = out.get(delta.kind.value, 0) + 1
    out["total_false_events"] = len(phantom)
    return out
