"""Drift tests: the version-aware comparison must not manufacture findings.

The scenario is real, not contrived. Between the two runs CISA renumbered
MS.DEFENDER.* to MS.SECURITYSUITE.*, using the migration table CISA publishes.
A drift tool that matches on identifier reports each renumbered policy twice --
once as vanished, once as new -- corrupting the "findings opened / closed"
counts a compliance report is built from.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scuba_oscal.drift import DriftKind, compare, false_signal_count
from scuba_oscal.parsers.mappings import MigrationKind
from scuba_oscal.parsers.scubagear import parse_run

ROOT = Path(__file__).resolve().parents[1]
BEFORE = ROOT / "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"
AFTER = ROOT / "data/scubagear_samples/ScubaResults_followup_30d.json"


@pytest.fixture(scope="module")
def runs():
    if not AFTER.exists():
        subprocess.run([sys.executable, str(ROOT / "scripts/make_followup_run.py")], check=True)
    return parse_run(BEFORE), parse_run(AFTER)


@pytest.fixture(scope="module")
def migrations(index):
    return index.migrations


def test_version_aware_reports_only_real_changes(runs, migrations):
    before, after = runs
    report = compare(before, after, migrations, version_aware=True)
    assert len(report.improvements) == 3
    assert len(report.regressions) == 1
    # A renumbering is not a material change.
    assert report.of(DriftKind.ADDED) == []
    assert report.of(DriftKind.REMOVED) == []


def test_naive_comparison_manufactures_false_findings(runs, migrations):
    """Pin the defect we are correcting, so the claim stays honest."""
    before, after = runs
    naive = compare(before, after, migrations, version_aware=False)
    aware = compare(before, after, migrations, version_aware=True)

    assert len(naive.of(DriftKind.ADDED)) == 13
    assert len(naive.of(DriftKind.REMOVED)) == 13

    false_signals = false_signal_count(naive, aware)
    assert false_signals["total_false_events"] == 26

    # The real changes survive in both; only the phantoms differ.
    assert len(naive.improvements) == len(aware.improvements) == 3
    assert len(naive.regressions) == len(aware.regressions) == 1


def test_renumbered_policies_keep_their_result(runs, migrations):
    before, after = runs
    report = compare(before, after, migrations, version_aware=True)
    assert len(report.renumbered) == 13
    for delta in report.renumbered:
        assert delta.previous_id and delta.previous_id != delta.policy_id
        assert delta.before == delta.after


def test_specific_remediation_is_detected(runs, migrations):
    """The top-priority failure our risk agent flags, once fixed."""
    before, after = runs
    report = compare(before, after, migrations, version_aware=True)
    improved = {d.policy_id for d in report.improvements}
    assert "MS.AAD.3.1v1" in improved


def test_regression_is_detected(runs, migrations):
    before, after = runs
    report = compare(before, after, migrations, version_aware=True)
    assert [d.policy_id for d in report.regressions] == ["MS.EXO.6.1v1"]


def test_comparing_a_run_to_itself_shows_no_drift(runs, migrations):
    before, _ = runs
    report = compare(before, before, migrations, version_aware=True)
    assert not [d for d in report.deltas if d.kind.is_material]


def test_split_migrations_are_not_used_as_renames(index):
    """A policy split into several has no single successor; inventing one
    would silently equate two different requirements."""
    split = [
        r for r in index.migration_records.values() if r.kind is MigrationKind.SPLIT
    ]
    assert split, "expected CISA's table to contain split migrations"
    for record in split:
        assert record.successor is None
        assert record.old_id not in index.migrations


def test_retired_policies_are_not_used_as_renames(index):
    retired = [
        r for r in index.migration_records.values() if r.kind is MigrationKind.RETIRED
    ]
    assert retired
    for record in retired:
        assert record.new_ids == ()
        assert record.old_id not in index.migrations


def test_migration_table_classification(index):
    assert index.migration_stats() == {"renamed": 45, "retired": 5, "split": 5}
