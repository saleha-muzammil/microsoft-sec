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


# ----------------------------------------------------------------- parsing

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


# ---------------------------------------------------------------- lapsing

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


# -------------------------------------------------------------- arithmetic

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


# ------------------------------------------------------------------- OSCAL

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
