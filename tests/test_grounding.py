"""Tests for the output-side grounding layer.

The audit badge in the app and the eval's fabrication numbers both come from
this module, so its behaviour is a stage-claim: an identifier flagged here is
publicly called a fabrication, and one passed here is publicly called
evidenced. Both directions get tested.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scuba_oscal.grounding import EvidenceCorpus, asserted_identifiers, sha256_of

ROOT = Path(__file__).resolve().parents[1]
OSCAL_DIR = ROOT / "data/oscal_out"


@pytest.fixture(scope="module", autouse=True)
def generated():
    if not (OSCAL_DIR / "scuba-m365-catalog.json").exists():
        subprocess.run([sys.executable, str(ROOT / "scripts/generate.py")], check=True)


@pytest.fixture(scope="module")
def corpus():
    return EvidenceCorpus(OSCAL_DIR)


# ------------------------------------------------------------------ extraction


def test_extracts_all_four_identifier_kinds():
    text = (
        "MS.AAD.3.1v1 maps to IA-2(1) and mitigates T1110.003; "
        "see observation 1a2b3c4d-0000-4000-8000-000000000000."
    )
    assert asserted_identifiers(text) == {
        "MS.AAD.3.1v1",
        "IA-2(1)",
        "T1110.003",
        "1a2b3c4d-0000-4000-8000-000000000000",
    }


def test_enhancement_suffix_is_not_truncated():
    # "AC-2(12)" collapsing to "AC-2" is exactly the precision loss that turns
    # a wrong mapping into a "supported" one.
    assert "AC-2(12)" in asserted_identifiers("maps to AC-2(12)")


# ----------------------------------------------------------------------- audit


def test_identifiers_from_the_artifacts_are_verified(corpus):
    audit = corpus.audit("MS.AAD.3.1v1 requires phishing-resistant MFA.")
    assert audit.ok
    assert audit.verified == ("MS.AAD.3.1v1",)


def test_invented_identifiers_are_flagged(corpus):
    audit = corpus.audit(
        "This maps to XX-99(42) per observation "
        "deadbeef-dead-4bad-8bad-deadbeefdead."
    )
    assert not audit.ok
    assert "XX-99(42)" in audit.unsupported
    assert "deadbeef-dead-4bad-8bad-deadbeefdead" in audit.unsupported


def test_question_supplied_identifier_is_quotation_not_fabrication(corpus):
    """Refusing the trap must not score as falling for it."""
    audit = corpus.audit(
        "No SCuBA policy MS.FAKE.9.9v9 exists in the catalog.",
        question="What does MS.FAKE.9.9v9 require?",
    )
    assert audit.ok
    assert audit.echoed == ("MS.FAKE.9.9v9",)
    assert audit.verified == ()


def test_an_answer_with_no_identifiers_audits_clean(corpus):
    audit = corpus.audit("Overall posture is broadly reasonable.")
    assert audit.ok and not audit.asserted


# --------------------------------------------------------------------- resolve


def test_resolve_traces_a_policy_id_to_its_oscal_node(corpus):
    evidence = corpus.resolve("MS.AAD.3.1v1")
    assert evidence, "a policy assessed in the sample must be resolvable"
    top = evidence[0]
    assert top.document.endswith(".json")
    assert "ms.aad.3.1v1" in json.dumps(top.node).lower()
    # The node is citable, not a bare string match.
    assert "id" in top.node or "uuid" in top.node


def test_resolve_traces_an_observation_uuid(corpus):
    results = json.loads((OSCAL_DIR / "scuba-assessment-results.json").read_text())
    uuid = results["assessment-results"]["results"][0]["observations"][0]["uuid"]
    evidence = corpus.resolve(uuid)
    assert any(e.node.get("uuid") == uuid for e in evidence)


def test_resolve_returns_nothing_for_an_unknown_identifier(corpus):
    assert corpus.resolve("deadbeef-dead-4bad-8bad-deadbeefdead") == []


# ------------------------------------------------------------------ provenance


def test_every_document_carries_the_hash_of_its_input_scan():
    """The provenance claim is in-band and re-checkable: rehash the scan CISA
    published, and it must equal what every generated document recorded."""
    expected = sha256_of(
        ROOT / "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"
    )
    for path in sorted(OSCAL_DIR.glob("*.json")):
        root = next(iter(json.loads(path.read_text()).values()))
        recorded = [
            p["value"]
            for p in root["metadata"].get("props", [])
            if p["name"] == "source-sha256" and p.get("class") == "scubagear-results"
        ]
        assert recorded == [expected], f"{path.name} lacks or mismatches provenance"
