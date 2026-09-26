"""Transformer tests: the generated OSCAL must be valid and internally honest."""

from __future__ import annotations

import re

import pytest

from scuba_oscal.ids import control_uuid, det_uuid
from scuba_oscal.transformers.assessment_results import build_assessment_results
from scuba_oscal.transformers.catalog import build_catalog, control_count
from scuba_oscal.transformers.poam import build_poam, severity, summarise
from scuba_oscal.validation import validate_schema

#: OSCAL's uuid datatype: the version nibble is [45], so UUIDv5 is legal.
OSCAL_UUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}"
    r"-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
)


def test_uuid5_satisfies_oscal_uuid_datatype():
    assert OSCAL_UUID.match(control_uuid("MS.AAD.1.1v1"))


def test_uuids_are_deterministic():
    assert det_uuid("a", "b") == det_uuid("a", "b")
    assert det_uuid("a", "b") != det_uuid("ab",)


def test_uuid_parts_cannot_collide():
    """Joining must not let different inputs produce the same identity."""
    assert det_uuid("control", "MS.AAD.1.1v1") != det_uuid("control.MS", "AAD.1.1v1")


def test_catalog_is_schema_valid(baselines):
    catalog = build_catalog(baselines)
    assert validate_schema(catalog) == []
    assert control_count(catalog) == 127


def test_catalog_regeneration_is_byte_stable(baselines):
    """Identical input must produce an identical document, or drift is noise.

    ``last-modified`` is compared too, and deliberately so: an earlier version
    of this test popped that field before comparing, which made it pass while
    every regenerated document in fact differed. The whole value of the
    deterministic UUIDs is a meaningful git diff, and one wall-clock timestamp
    per document is enough to destroy it.
    """
    import json
    from datetime import UTC, datetime

    stamp = datetime(2026, 5, 4, 17, 15, 48, tzinfo=UTC)
    first = build_catalog(baselines, last_modified=stamp)
    second = build_catalog(baselines, last_modified=stamp)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["catalog"]["metadata"]["last-modified"] == "2026-05-04T17:15:48.000Z"


def test_assessment_results_is_schema_valid(run):
    doc = build_assessment_results(run)
    assert validate_schema(doc) == []


def test_na_policies_produce_observations_but_no_findings(run):
    """N/A is evidence of neither compliance nor deficiency."""
    doc = build_assessment_results(run)["assessment-results"]["results"][0]
    assert len(doc["observations"]) == 92
    assert len(doc["findings"]) == 83        # 92 minus the 9 N/A policies


def test_untestable_policies_are_recorded_as_examine_not_test(run):
    """Reporting a human-assessed policy as a machine TEST would misstate evidence."""
    doc = build_assessment_results(run)["assessment-results"]["results"][0]
    by_id = {
        next(p["value"] for p in o["props"] if p["name"] == "scuba-policy-id"): o
        for o in doc["observations"]
    }
    for policy in run.policies:
        expected = "TEST" if policy.criticality.is_automated else "EXAMINE"
        assert by_id[policy.policy_id]["methods"] == [expected]


def test_poam_is_schema_valid(run):
    poam = build_poam(run)
    assert validate_schema(poam) == []


def test_poam_severity_model(run):
    from scuba_oscal.models import Criticality, PolicyResult, Result

    def make(result, criticality):
        return PolicyResult(
            policy_id="MS.X.1.1v1", requirement="r", result=result,
            criticality=criticality, details="", product="x",
            group_number="1", group_name="g",
        )

    assert severity(make(Result.FAIL, Criticality.SHALL)) == "high"
    assert severity(make(Result.FAIL, Criticality.SHOULD)) == "moderate"
    assert severity(make(Result.WARNING, Criticality.SHALL)) == "moderate"
    assert severity(make(Result.WARNING, Criticality.SHOULD)) == "low"


def test_poam_counts_match_run(run):
    poam = build_poam(run)
    assert sum(summarise(poam).values()) == len(run.failures()) == 26


def test_compliant_tenant_produces_no_poam(run):
    """OSCAL requires >=1 poam-item, so an empty POA&M is not a valid document."""
    import dataclasses

    clean = dataclasses.replace(run, policies=[p for p in run.policies if not p.result.is_failure])
    assert clean.failures() == []
    assert build_poam(clean) is None


def test_ai_remediation_is_provenance_tagged(run):
    """Machine-written prose must be distinguishable from CISA-derived prose."""
    target = run.failures()[0].policy_id
    poam = build_poam(run, remediation_guidance={target: "Do the thing."})
    risks = poam["plan-of-action-and-milestones"]["risks"]
    tagged = [
        r for r in risks
        if any(
            p["name"] == "generated-by" and p["value"] == "ai-assistant"
            for p in r["remediations"][0].get("props", [])
        )
    ]
    assert len(tagged) == 1
    assert tagged[0]["remediations"][0]["description"] == "Do the thing."


def test_mapping_provenance_method_matches_what_produced_it(index, run):
    """`method` must describe this document, not the data model's capability.

    It read "hybrid" while the document's own ai-proposed-mappings prop read 0,
    which tells any OSCAL-aware consumer that a model produced some of these
    mappings. None did.
    """
    from scuba_oscal.transformers.mapping import build_from_index

    doc = build_from_index(index, [p.policy_id for p in run.policies])["mapping-collection"]
    ai_proposed = next(
        p["value"] for p in doc["metadata"]["props"] if p["name"] == "ai-proposed-mappings"
    )
    assert ai_proposed == "0"
    assert doc["provenance"]["method"] == "automation"

    description = doc["provenance"]["mapping-description"]
    assert "none is model-generated" in description
    assert "are marked ai-proposed" not in description


def test_mapping_declares_hybrid_only_when_a_model_contributed():
    """The other branch, so the honest label is not merely a constant."""
    from scuba_oscal.parsers.mappings import ControlMapping, Provenance
    from scuba_oscal.transformers.mapping import build_mapping_collection

    proposed = ControlMapping(
        policy_id="MS.FAKE.1.1v1",
        nist_controls=("si-4",),
        raw_controls=("SI-4",),
        provenance=Provenance.AI,
        confidence=0.82,
    )
    doc = build_mapping_collection([proposed])
    assert validate_schema(doc) == []

    provenance = doc["mapping-collection"]["provenance"]
    assert provenance["method"] == "hybrid"
    assert "ai-proposed" in provenance["mapping-description"]


def test_ssp_flags_the_categorisation_it_did_not_assess(run):
    """FIPS 199 is required by OSCAL and not determined by ScubaGear.

    The value therefore has to be supplied, and the artifact has to say it is a
    default -- in an ATO package the categorisation selects the control
    baseline, so an unlabelled placeholder is a consequential invention.
    """
    from scuba_oscal.transformers.chain import build_ssp

    chars = build_ssp(run, ["ms.aad.1.1v1"], "p.json")["system-security-plan"][
        "system-characteristics"
    ]
    source = next(p for p in chars["props"] if p["name"] == "categorisation-source")
    assert source["value"] == "default-not-assessed"
    assert "NOT determined by ScubaGear" in source["remarks"]
    assert chars["security-sensitivity-level"] == "moderate"


def test_ssp_records_an_operator_supplied_categorisation_as_assessed(run):
    from scuba_oscal.transformers.chain import build_ssp

    doc = build_ssp(run, ["ms.aad.1.1v1"], "p.json", sensitivity="high")
    chars = doc["system-security-plan"]["system-characteristics"]
    source = next(p for p in chars["props"] if p["name"] == "categorisation-source")

    assert source["value"] == "assessed"
    assert chars["security-sensitivity-level"] == "high"
    assert chars["security-impact-level"]["security-objective-confidentiality"] == "fips-199-high"
    info = chars["system-information"]["information-types"][0]
    assert info["integrity-impact"]["base"] == "fips-199-high"
    assert validate_schema(doc) == []


def test_ssp_rejects_a_categorisation_outside_fips_199(run):
    from scuba_oscal.transformers.chain import build_ssp

    with pytest.raises(ValueError):
        build_ssp(run, ["ms.aad.1.1v1"], "p.json", sensitivity="very-high")
