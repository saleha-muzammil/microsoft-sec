"""Tests for the economic impact model.

The point of these is to protect the distinction the model exists to make:
measurements must come from artifacts, assumptions must be explicit, and a
change to an assumption must visibly move the answer. A model whose output
does not respond to its inputs is a headline number wearing a disguise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scuba_oscal.impact import (
    VA_INSTITUTIONS,
    Assumptions,
    commonwealth_scale,
    effort_per_assessment,
    measure,
    run_cost,
)

OSCAL_DIR = Path(__file__).resolve().parents[1] / "data/oscal_out"


@pytest.fixture(scope="module")
def measured():
    return measure(OSCAL_DIR)


def test_measurements_come_from_the_artifacts(measured, run):
    """Every measured value must be traceable to a generated document."""
    assert measured.policies_assessed == len(run.policies)
    assert measured.poam_items == len(run.failures())
    assert measured.oscal_documents == len(list(OSCAL_DIR.glob("*.json")))
    assert measured.findings < measured.observations, "N/A policies yield no finding"


def test_band_is_ordered_and_non_degenerate(measured):
    band = effort_per_assessment(measured)
    assert band.low_hours < band.mid_hours < band.high_hours
    assert band.low_cost < band.mid_cost < band.high_cost


def test_assumptions_actually_drive_the_answer(measured):
    """If doubling the effort assumption does not move the result, the model
    is decorative."""
    base = effort_per_assessment(measured, Assumptions(minutes_per_poam_item=10))
    doubled = effort_per_assessment(measured, Assumptions(minutes_per_poam_item=20))
    assert doubled.mid_hours > base.mid_hours


def test_wage_only_affects_cost_not_hours(measured):
    """Hours are a function of work; only the valuation depends on wage."""
    cheap = effort_per_assessment(measured, Assumptions(hourly_wage=30))
    dear = effort_per_assessment(measured, Assumptions(hourly_wage=120))
    assert cheap.mid_hours == dear.mid_hours
    assert cheap.mid_cost < dear.mid_cost


def test_breakdown_accounts_for_the_whole_estimate(measured):
    band = effort_per_assessment(measured)
    assert sum(h for _, h in band.breakdown) == pytest.approx(band.mid_hours, rel=1e-6)


def test_running_cost_is_reported_and_small(measured):
    costs = run_cost()
    band = effort_per_assessment(measured)
    assert costs["total_monthly"] > 0, "operating cost must not be claimed as free"
    assert costs["total_monthly"] < band.mid_cost, (
        "the claim is that running it costs far less than the work it replaces"
    )


def test_commonwealth_scale_uses_published_counts(measured):
    band = effort_per_assessment(measured)
    scale = commonwealth_scale(band)
    assert scale["institutions"] == sum(VA_INSTITUTIONS.values())
    assert scale["mid_hours"] == pytest.approx(
        band.mid_hours * scale["institutions"] * scale["cycles_per_year"]
    )


def test_zero_findings_produces_no_poam_effort(measured):
    """Sanity: the model must not credit savings for work that wasn't needed."""
    import dataclasses

    none = dataclasses.replace(measured, poam_items=0, phantom_findings_avoided=0)
    assert effort_per_assessment(none).mid_hours < effort_per_assessment(measured).mid_hours
