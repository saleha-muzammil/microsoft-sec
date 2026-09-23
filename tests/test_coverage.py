"""Tests for MITRE ATT&CK threat coverage.

The claim this module makes is that compliance severity and threat exposure are
different orderings. That is only worth saying if it is true on real data, so
these tests pin both the mechanics and the disagreement itself.
"""

from __future__ import annotations

import dataclasses

import pytest

from scuba_oscal.coverage import build_coverage
from scuba_oscal.models import Result
from scuba_oscal.transformers.poam import severity


@pytest.fixture(scope="module")
def coverage(run, baselines):
    return build_coverage(run, baselines)


def test_every_technique_is_classified(coverage):
    counts = coverage.counts()
    assert sum(counts.values()) == len(coverage.techniques)
    assert set(counts) == {"uncovered", "degraded", "covered"}


def test_depth_is_the_number_of_passing_mitigations(coverage):
    for technique in coverage.techniques.values():
        assert technique.depth == len(technique.passing)
        assert set(technique.passing) | set(technique.failing) == set(technique.mitigating)
        assert not (set(technique.passing) & set(technique.failing))


def test_uncovered_means_no_surviving_mitigation(coverage):
    assert coverage.uncovered, "expected at least one uncovered technique on this data"
    for technique in coverage.uncovered:
        assert technique.depth == 0
        assert technique.passing == ()
        assert technique.failing, "uncovered requires mapped policies that are failing"


def test_covered_techniques_have_no_failures(coverage):
    for technique in coverage.of("covered"):
        assert technique.failing == ()
        assert technique.depth > 0


def test_na_policies_count_neither_way(run, baselines):
    """N/A is evidence of neither mitigation nor gap."""
    na = [p for p in run.policies if p.result is Result.NOT_APPLICABLE]
    assert na, "sample should contain N/A policies"
    coverage = build_coverage(run, baselines)
    na_ids = {p.policy_id for p in na}
    for technique in coverage.techniques.values():
        assert not (na_ids & set(technique.mitigating))


def test_fixing_a_policy_closes_exactly_its_uncovered_techniques(coverage):
    for policy_id, techniques in coverage.remediation_ranking(limit=50):
        closed = coverage.techniques_closed_by(policy_id)
        assert closed == sorted(techniques)
        for tid in closed:
            assert coverage.techniques[tid].is_uncovered


def test_ranking_is_ordered_by_techniques_closed(coverage):
    ranked = coverage.remediation_ranking(limit=20)
    counts = [len(techniques) for _, techniques in ranked]
    assert counts == sorted(counts, reverse=True)


def test_threat_ranking_disagrees_with_compliance_severity(coverage, run):
    """The substantive claim: the two orderings genuinely differ.

    On this data, low-severity SHOULD policies are the only remaining mitigation
    for techniques nothing else covers, while most high-severity failures close
    no uncovered technique because other controls still hold.
    """
    by_id = {p.policy_id: p for p in run.policies}

    low_but_high_impact = [
        policy_id
        for policy_id, techniques in coverage.remediation_ranking(limit=20)
        if policy_id in by_id
        and severity(by_id[policy_id]) != "high"
        and len(techniques) >= 2
    ]
    assert low_but_high_impact, (
        "expected at least one low-severity policy that is the last mitigation "
        "for multiple techniques"
    )

    high_failures = [p for p in run.failures() if severity(p) == "high"]
    closing_nothing = [
        p for p in high_failures if not coverage.techniques_closed_by(p.policy_id)
    ]
    assert closing_nothing, "expected some high-severity failures with surviving coverage"


def test_a_fully_passing_run_has_no_uncovered_techniques(run, baselines):
    passing = dataclasses.replace(
        run,
        policies=[
            dataclasses.replace(p, result=Result.PASS)
            for p in run.policies
            if p.result is not Result.NOT_APPLICABLE
        ],
    )
    coverage = build_coverage(passing, baselines)
    assert coverage.uncovered == []
    assert coverage.degraded == []
