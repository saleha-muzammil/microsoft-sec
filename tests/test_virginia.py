"""Tests for the Virginia SEC530 composition.

The value of this join rests on two things being true: that the identifiers
really are shared (so no fuzzy matching is involved), and that withdrawal is
respected (so we never imply a Commonwealth duty that Virginia has removed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scuba_oscal.parsers.mappings import MappingIndex
from scuba_oscal.virginia import (
    Ownership,
    _classify,
    _normalise,
    map_to_virginia,
    parse_sec530,
)

ROOT = Path(__file__).resolve().parents[1]
WORKBOOK = ROOT / "data/virginia/SEC530_Control_Summaries.xlsx"

pytestmark = pytest.mark.skipif(not WORKBOOK.exists(), reason="SEC530 workbook not present")


@pytest.fixture(scope="module")
def sec530():
    return parse_sec530(WORKBOOK)


@pytest.fixture(scope="module")
def index():
    return MappingIndex(
        ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv",
        ROOT / "data/mappings/scuba-baseline-policy-migrations.csv",
    )


def test_workbook_parses_all_control_families(sec530):
    assert len(sec530) > 1000
    families = {cid.split("-")[0] for cid in sec530}
    assert {"ac", "ia", "sc", "si", "au"} <= families


def test_ownership_values_are_classified(sec530):
    seen = {c.ownership for c in sec530.values()}
    assert Ownership.ORGANIZATION in seen
    assert Ownership.SYSTEM in seen
    assert Ownership.WITHDRAWN in seen


@pytest.mark.parametrize(
    "raw,expected",
    [("O", Ownership.ORGANIZATION), ("S", Ownership.SYSTEM), ("O/S", Ownership.BOTH)],
)
def test_classify_known_codes(raw, expected):
    assert _classify(raw)[0] is expected


def test_withdrawal_reason_is_captured():
    ownership, note = _classify("W: not applicable to COV")
    assert ownership is Ownership.WITHDRAWN
    assert note == "not applicable to COV"


@pytest.mark.parametrize(
    "raw,expected",
    [("AC-2", "ac-2"), ("AC-2(12)", "ac-2.12"), ("SC-7(10)", "sc-7.10"), ("IA-5", "ia-5")],
)
def test_normalisation_matches_the_crosswalk_convention(raw, expected):
    assert _normalise(raw) == expected


def test_every_crosswalk_control_exists_in_sec530(sec530, index, run):
    """The join must be exact. A miss would mean silent under-reporting."""
    ours = {
        cid
        for policy in run.policies
        for cid in index.resolve(policy.policy_id).nist_controls
    }
    missing = sorted(cid for cid in ours if cid not in sec530)
    assert not missing, f"NIST controls absent from SEC530: {missing}"


def test_failures_map_to_virginia_obligations(index, sec530, run):
    obligations = map_to_virginia([p.policy_id for p in run.failures()], index, sec530)
    assert obligations
    assert any(o.is_state_obligation for o in obligations)


def test_controls_are_not_listed_twice(index, sec530, run):
    """CISA cites IA-5c and IA-5g, which normalise to the same control."""
    for obligation in map_to_virginia([p.policy_id for p in run.failures()], index, sec530):
        ids = [c.published_id for c in obligation.sec530]
        assert len(ids) == len(set(ids))


def test_withdrawn_controls_do_not_create_a_state_obligation(index, sec530, run):
    """Where Virginia withdrew the control, there is no Commonwealth duty."""
    obligations = map_to_virginia([p.policy_id for p in run.failures()], index, sec530)
    federal_only = [o for o in obligations if o.sec530 and not o.in_scope]
    assert federal_only, "expected at least one federal-only finding on this data"
    for obligation in federal_only:
        assert not obligation.is_state_obligation
        assert obligation.withdrawn
        assert all(c.is_withdrawn for c in obligation.withdrawn)


def test_owners_are_reported_for_in_scope_controls(index, sec530, run):
    obligations = map_to_virginia([p.policy_id for p in run.failures()], index, sec530)
    for obligation in obligations:
        if obligation.is_state_obligation:
            assert obligation.owners
            assert all(o != Ownership.WITHDRAWN.label for o in obligation.owners)


def test_unmapped_policy_yields_no_virginia_obligation(index, sec530):
    (obligation,) = map_to_virginia(["MS.FAKE.9.9v9"], index, sec530)
    assert obligation.sec530 == ()
    assert not obligation.is_state_obligation
