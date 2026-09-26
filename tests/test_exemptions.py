"""Tests for the exemption ledger.

The claim is that a compliance percentage can be raised by editing a config
file, and that nothing enforces the optional expiry date. These tests pin both,
plus the arithmetic that quantifies the gap.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from scuba_oscal.exemptions import (
    Exemption,
    build_ledger,
    parse_config,
    parse_config_dict,
    to_oscal_risks,
)
from scuba_oscal.models import Result

CONFIG = Path(__file__).resolve().parents[1] / "data/scubagear_samples/scuba_config_example.yaml"
TODAY = date(2026, 9, 23)


@pytest.fixture(scope="module")
def exemptions():
    return parse_config(CONFIG)


@pytest.fixture(scope="module")
def ledger(run, exemptions):
    return build_ledger(run, exemptions)


def test_parses_both_omissions_and_annotations(exemptions):
    kinds = {e.kind for e in exemptions}
    assert kinds == {"omission", "annotation"}


def test_parses_cisas_documented_field_names():
    doc = {
        "OmitPolicy": {
            "MS.EXO.4.3v1": {
                "Rationale": "Only applies to federal agencies",
                "Expiration": "2025-12-31",
            }
        }
    }
    (parsed,) = parse_config_dict(doc)
    assert parsed.policy_id == "MS.EXO.4.3v1"
    assert parsed.expiration == date(2025, 12, 31)
    assert parsed.has_rationale


def test_missing_expiration_means_it_never_lapses():
    (parsed,) = parse_config_dict({"OmitPolicy": {"MS.X.1.1v1": {"Rationale": "because"}}})
    assert parsed.expiration is None
    assert not parsed.is_expired(TODAY)


def test_unparseable_date_does_not_crash():
    (parsed,) = parse_config_dict(
        {"OmitPolicy": {"MS.X.1.1v1": {"Rationale": "r", "Expiration": "not-a-date"}}}
    )
    assert parsed.expiration is None


def test_expired_exemptions_are_detected(exemptions):
    expired = [e for e in exemptions if e.is_expired(TODAY)]
    assert {e.policy_id for e in expired} == {"MS.EXO.4.3v1", "MS.AAD.3.1v1"}


def test_an_expired_exemption_is_open_not_approved():
    """A lapsed deviation is not an approved one, whatever the report shows."""
    lapsed = Exemption("MS.X.1.1v1", "reason", date(2025, 1, 1))
    assert lapsed.status(TODAY) == "open"

    current = Exemption("MS.X.1.2v1", "reason", date(2027, 1, 1))
    assert current.status(TODAY) == "deviation-approved"


def test_exemption_without_rationale_is_only_requested():
    assert Exemption("MS.X.1.1v1", "", None).status(TODAY) == "deviation-requested"


def test_exemptions_inflate_the_reported_rate(ledger):
    assert ledger.reported_total < ledger.assessed_total
    assert ledger.reported_rate > ledger.true_rate
    assert ledger.inflation > 0


def test_inflation_is_the_difference_between_the_two_rates(ledger):
    assert ledger.inflation == pytest.approx(ledger.reported_rate - ledger.true_rate)


def test_only_omissions_change_the_denominator(run, exemptions):
    """Annotations add context; they do not remove a policy from the report."""
    omissions = [e for e in exemptions if e.kind == "omission"]
    assert build_ledger(run, exemptions).reported_total == build_ledger(run, omissions).reported_total


def test_no_exemptions_means_no_gap(run):
    ledger = build_ledger(run, [])
    assert ledger.reported_total == ledger.assessed_total
    assert ledger.inflation == pytest.approx(0.0)


def test_na_policies_are_excluded_from_both_denominators(run, exemptions):
    ledger = build_ledger(run, exemptions)
    na = sum(1 for p in run.policies if p.result is Result.NOT_APPLICABLE)
    assert ledger.assessed_total == len(run.policies) - na


def test_mandatory_suppressions_are_called_out(ledger):
    assert ledger.suppressed_mandatory
    assert set(ledger.suppressed_mandatory) <= set(ledger.suppressed)


def test_exemptions_render_as_oscal_risks_with_deviation_status(ledger, run):
    risks = to_oscal_risks(ledger, run.run_id, TODAY)
    assert len(risks) == len(ledger.exemptions)
    statuses = {r["status"] for r in risks}
    assert statuses <= {"open", "deviation-requested", "deviation-approved"}
    assert "open" in statuses, "expired exemptions must fall back to open"


def test_expired_risks_say_so_in_their_statement(ledger, run):
    risks = to_oscal_risks(ledger, run.run_id, TODAY)
    expired = [r for r in risks if r["status"] == "open"]
    assert expired
    for risk in expired:
        assert "expired" in risk["statement"].lower()
        assert any(p["name"] == "expired" for p in risk["props"])


def test_true_rate_scores_omitted_policies_on_their_real_result(ledger, run):
    """The comparable rate uses each policy's actual result, not an assumption.

    An earlier version scored every omitted policy as unmet, which on this data
    is wrong twice over: two of the four omissions were *passing*. That inflated
    the reported distortion roughly fourfold and, worse, put a second
    contradictory "real" compliance rate on the same page as the headline.
    """
    assessed = [p for p in run.policies if p.result is not Result.NOT_APPLICABLE]
    passing = sum(1 for p in assessed if p.result is Result.PASS)

    assert ledger.assessed_total == len(assessed)
    assert ledger.assessed_pass == passing
    assert ledger.true_rate == pytest.approx(100 * passing / len(assessed))


def test_true_rate_matches_the_headline_posture_figure(ledger):
    """Same tenant, same denominator, same scoring -- so the same number."""
    assert round(ledger.true_rate, 1) == 68.7
    assert round(ledger.reported_rate, 1) == 69.6
    assert round(ledger.inflation, 1) == 0.9


def test_worst_case_is_reported_separately_from_the_true_rate(ledger):
    """Assuming every exemption hides a failure is a bound, not a finding."""
    assert round(ledger.worst_case_rate, 1) == 66.3
    assert ledger.worst_case_rate < ledger.true_rate


def test_omitting_a_passing_policy_is_identified(ledger):
    """Naming these is what keeps the headline number honest."""
    assert ledger.suppressed_passing == ["MS.EXO.4.3v1", "MS.SHAREPOINT.1.1v1"]
    assert set(ledger.suppressed_passing) <= set(ledger.suppressed)


def test_omitting_only_failures_would_inflate_the_rate(run):
    """Sanity-check the mechanism itself on a clean case.

    Omit two genuinely failing policies and the reported rate must rise while
    the true rate does not move at all -- that is the distortion, isolated.
    """
    failing = [p for p in run.policies if p.result is Result.FAIL][:2]
    omissions = [
        Exemption(policy_id=p.policy_id, rationale="test", expiration=None)
        for p in failing
    ]
    baseline = build_ledger(run, [])
    gamed = build_ledger(run, omissions)

    assert gamed.reported_rate > baseline.reported_rate
    assert gamed.true_rate == pytest.approx(baseline.true_rate)
    assert gamed.inflation > 0
    assert gamed.suppressed_passing == []


def test_exemptions_are_emitted_into_the_poam(run, exemptions):
    """The governance claim only holds if the deviation reaches a document.

    `to_oscal_risks` was implemented and tested but wired to nothing, so no
    generated artifact contained a single exemption -- while the module
    asserted it produced "the governance artifact the YAML config is not".
    """
    from scuba_oscal.transformers.poam import build_poam

    poam = build_poam(run, exemptions=exemptions)["plan-of-action-and-milestones"]
    emitted = [
        r for r in poam["risks"]
        if any(p["name"] == "exemption-kind" for p in r.get("props", []))
    ]
    assert len(emitted) == len(exemptions)

    # poam-items are untouched: a deviation is not a commitment to remediate.
    assert len(poam["poam-items"]) == len(run.failures())

    props = {p["name"]: p["value"] for p in poam["metadata"]["props"]}
    assert props["exemptions"] == str(len(exemptions))
    assert props["expired-exemptions"] == "2"
    assert props["exemptions-suppressing-mandatory"] == "4"


def test_emitted_exemption_risks_use_oscal_risk_status(run, exemptions):
    from scuba_oscal.transformers.poam import build_poam

    poam = build_poam(run, exemptions=exemptions)["plan-of-action-and-milestones"]
    emitted = [
        r for r in poam["risks"]
        if any(p["name"] == "exemption-kind" for p in r.get("props", []))
    ]
    allowed = {"open", "investigating", "remediating",
               "deviation-requested", "deviation-approved", "closed"}
    assert {r["status"] for r in emitted} <= allowed

    by_id = {
        next(p["value"] for p in r["props"] if p["name"] == "scuba-policy-id"): r
        for r in emitted
    }
    # An expired exemption has lapsed: it is open again, whatever the report says.
    assert by_id["MS.EXO.4.3v1"]["status"] == "open"
    assert by_id["MS.AAD.3.1v1"]["status"] == "open"
    # In force, with a rationale on record.
    assert by_id["MS.AAD.5.2v1"]["status"] == "deviation-approved"


def test_poam_without_exemptions_is_unchanged(run):
    """Omitting the config must not alter the document at all."""
    from scuba_oscal.transformers.poam import build_poam

    bare = build_poam(run)["plan-of-action-and-milestones"]
    assert len(bare["risks"]) == len(run.failures())
    assert not [p for p in bare["metadata"]["props"] if p["name"] == "exemptions"]


def test_entry_for_an_unassessed_policy_is_reported_as_such(ledger):
    """MS.TEAMS.2.1v1 is in the config but not in the run.

    Describing it as "excluded from the reported compliance figure" would be
    false -- it excluded nothing, because it was never assessed.
    """
    # Config order is preserved, so compare as a set.
    assert {e.policy_id for e in ledger.stale} == {"MS.TEAMS.2.1v1", "MS.EXO.2.2v2"}

    risks = to_oscal_risks(ledger, "run-1")
    by_id = {
        next(p["value"] for p in r["props"] if p["name"] == "scuba-policy-id"): r
        for r in risks
    }
    stale = by_id["MS.TEAMS.2.1v1"]
    assert "was not assessed in this run" in stale["description"]
    assert next(p["value"] for p in stale["props"] if p["name"] == "policy-assessed") == "false"

    live = by_id["MS.AAD.5.2v1"]
    assert "excluded from the reported compliance figure" in live["description"]
    assert next(p["value"] for p in live["props"] if p["name"] == "policy-assessed") == "true"


def test_annotation_is_not_described_as_an_exclusion(run):
    """Only an omission removes a policy from the figure; an annotation does not."""
    from scuba_oscal.exemptions import Exemption

    target = next(p for p in run.policies if p.result is Result.FAIL)
    note = Exemption(
        policy_id=target.policy_id, rationale="risk accepted",
        expiration=None, kind="annotation",
    )
    risk = to_oscal_risks(build_ledger(run, [note]), "run-1")[0]
    assert "remains in the reported compliance figure" in risk["description"]
    assert "excluded from" not in risk["description"]
