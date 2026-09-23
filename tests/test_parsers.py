"""Parser tests, written against CISA's real published sample report.

Each test below pins a ScubaGear quirk that broke a naive implementation, so a
future refactor cannot silently reintroduce it.
"""

from __future__ import annotations

from conftest import SAMPLE_RUN

from scuba_oscal.models import Criticality, Result
from scuba_oscal.parsers.scubagear import clean_requirement, load_json


def test_sample_report_parses(run):
    assert len(run.policies) == 92
    assert run.tool_version == "1.8.0"
    assert run.report_uuid


def test_result_counts_match_scubagear_summary(run):
    assert run.counts() == {"Pass": 57, "Fail": 14, "Warning": 12, "N/A": 9}


def test_utf8_bom_is_handled():
    """ScubaGear writes UTF-8 with a BOM; plain utf-8 decoding raises."""
    assert SAMPLE_RUN.read_bytes()[:3] == b"\xef\xbb\xbf"
    assert load_json(SAMPLE_RUN)["MetaData"]["ToolVersion"] == "1.8.0"


def test_control_id_field_has_a_space(run):
    """The field is 'Control ID', not 'PolicyId' (which lives in TestResults)."""
    raw = load_json(SAMPLE_RUN)
    control = raw["Results"]["AAD"][0]["Controls"][0]
    assert "Control ID" in control
    assert "PolicyId" not in control


def test_html_badges_are_stripped_from_requirements(run):
    """ScubaGear appends a <div class='policy-indicators'> block to Requirement."""
    raw = load_json(SAMPLE_RUN)["Results"]["AAD"][0]["Controls"][0]["Requirement"]
    assert "<div" in raw, "sample no longer contains the HTML we guard against"
    assert clean_requirement(raw) == "Legacy authentication SHALL be blocked."
    assert all("<" not in p.requirement for p in run.policies)


def test_criticality_parsing_is_case_insensitive():
    """Docs say '-implemented'; the Rego emits '-Implemented'."""
    assert Criticality.parse("Shall/Not-Implemented") is Criticality.SHALL_NOT_IMPL
    assert Criticality.parse("shall/not-implemented") is Criticality.SHALL_NOT_IMPL


def test_not_implemented_policies_are_not_automated():
    """A policy ScubaGear cannot test must not be reported as machine-verified."""
    assert Criticality.SHALL.is_automated
    assert not Criticality.SHALL_NOT_IMPL.is_automated
    assert not Criticality.SHOULD_3P.is_automated


def test_result_to_oscal_state():
    assert Result.PASS.oscal_state == "satisfied"
    assert Result.FAIL.oscal_state == "not-satisfied"
    assert Result.WARNING.oscal_state == "not-satisfied"


def test_actionable_failures_exclude_untestable_policies(run):
    """Failures we cannot evidence must not become POA&M items."""
    for policy in run.failures():
        assert policy.result.is_failure
        assert policy.criticality.is_automated
    assert len(run.failures()) == 26


def test_baselines_parse(baselines):
    assert len(baselines.policies) == 127
    assert "aad" in baselines.products
    policy = baselines.by_id("MS.AAD.1.1v1")
    assert policy.is_mandatory
    assert policy.rationale
    assert any(t.technique_id == "T1110" for t in policy.mitre)
