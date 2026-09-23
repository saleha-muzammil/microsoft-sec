"""Tests for the agent tool layer.

These run without Azure: the tools are pure functions over generated OSCAL, and
that is precisely the property that makes agent answers verifiable. If these
pass, any factual claim an agent makes is traceable to a validated document.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OSCAL_DIR = ROOT / "data/oscal_out"


@pytest.fixture(scope="module", autouse=True)
def generated():
    """Ensure artifacts exist before the tools are exercised."""
    if not (OSCAL_DIR / "scuba-m365-catalog.json").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts/generate.py")], check=True)


@pytest.fixture(scope="module")
def tools():
    from scuba_oscal.agents.tools import ComplianceTools
    return ComplianceTools(OSCAL_DIR)


def test_posture_summary_matches_the_assessment(tools, run):
    data = json.loads(tools.get_posture_summary())
    assert data["total_policies_assessed"] == len(run.policies)
    assert data["results"] == run.counts()


def test_failures_are_traceable_to_poam_items(tools):
    data = json.loads(tools.list_failures(severity="high", limit=100))
    assert data["count"] == 14
    for item in data["failures"]:
        assert item["policy_id"].startswith("MS.")
        assert item["severity"] == "high"
        assert item["poam_item_uuid"], "every failure must cite its POA&M item"
        assert item["deadline"], "every failure must carry a remediation deadline"


def test_control_details_include_cisa_rationale_and_mitre(tools):
    data = json.loads(tools.get_control_details("MS.AAD.1.1v1"))
    assert data["policy_id"] == "MS.AAD.1.1v1"
    assert data["mandatory"] is True
    assert "legacy authentication" in data["rationale"].lower()
    assert "T1110" in data["mitre_attack"]
    assert data["assessed_result"] == "Pass"


def test_unknown_policy_returns_an_error_not_a_guess(tools):
    """The tool must not invent a control; hallucination starts here if it does."""
    data = json.loads(tools.get_control_details("MS.FAKE.9.9v9"))
    assert "error" in data


def test_nist_mapping_always_reports_provenance(tools):
    data = json.loads(tools.get_nist_mapping("MS.AAD.1.1v1"))
    assert data["nist_controls"] == ["cm-7"]
    assert data["provenance"] == "cisa-authoritative"
    assert data["confidence"] == {"category": "authoritative"}


def test_unmapped_policy_is_reported_as_unmapped(tools):
    data = json.loads(tools.get_nist_mapping("MS.DEFENDER.1.1v1"))
    assert data["provenance"] == "unmapped"
    assert data["nist_controls"] == []


def test_search_finds_mfa_policies(tools):
    data = json.loads(tools.search_controls("multifactor authentication phishing"))
    assert data["matches"], "expected MFA-related policies"
    assert any(m["policy_id"].startswith("MS.AAD") for m in data["matches"])


def test_product_filter(tools):
    data = json.loads(tools.list_failures(product="AAD", limit=100))
    assert data["count"] > 0
    assert all(f["product"] == "AAD" for f in data["failures"])
