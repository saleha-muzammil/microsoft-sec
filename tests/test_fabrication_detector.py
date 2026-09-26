"""Tests for the fabrication detector used in the grounded-vs-ungrounded comparison.

The comparison is the strongest claim this project makes, so the instrument
that produces it has to be trustworthy. These tests check that it detects an
asserted identifier absent from context, and — more importantly — that it does
not manufacture findings when the identifier really was available.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evals"))

from compare import analyse, asserted_identifiers  # noqa: E402


def test_extracts_nist_and_attack_identifiers():
    text = "This maps to CM-7 and AC-2(12), mitigating T1110 and T1110.003."
    assert asserted_identifiers(text) == {"CM-7", "AC-2(12)", "T1110", "T1110.003"}


def test_identifier_present_in_context_is_not_flagged():
    cases = [{"id": "x", "passed": True, "answer": "It maps to CM-7."}]
    result = analyse(cases, context="the crosswalk says CM-7", label="t")
    assert result["unsupported_identifier_count"] == 0


def test_identifier_absent_from_context_is_flagged():
    cases = [{"id": "x", "passed": True, "answer": "It maps to SI-3."}]
    result = analyse(cases, context="no control ids here", label="t")
    assert result["unsupported_identifier_count"] == 1
    assert result["detail"][0]["asserted_but_absent"] == ["SI-3"]


def test_a_passing_answer_can_still_be_unsupported():
    """The central point: being right is not the same as being evidenced."""
    cases = [{"id": "x", "passed": True, "answer": "Mitigates T1110.003."}]
    result = analyse(cases, context="", label="t")
    assert result["passed"] == 1
    assert result["unsupported_identifier_count"] == 1


def test_empty_answers_produce_no_findings():
    cases = [{"id": "x", "passed": False, "answer": ""}]
    assert analyse(cases, context="", label="t")["unsupported_identifier_count"] == 0


def test_grounded_arm_asserts_nothing_unsupported():
    """Regression guard on the headline claim.

    Every identifier our agents state must appear in the OSCAL documents their
    tools read. If this ever fails, the grounding boundary has leaked.

    This re-runs the analysis over the recorded *answers* and the *current*
    artifacts rather than reading the stored aggregate out of comparison.json.
    Asserting that a checked-in number equals itself would pass no matter what
    the pipeline later did to the catalog.
    """
    import json

    import pytest

    root = Path(__file__).resolve().parents[1]
    results = root / "evals/results.json"
    oscal = root / "data/oscal_out"

    if not results.exists():
        pytest.skip("run evals/run_eval.py to record grounded answers")
    if not list(oscal.glob("*.json")):
        pytest.skip("run scripts/generate.py to produce the artifacts")

    cases = json.loads(results.read_text())["cases"]
    # The corpus definition and the question exemption mirror compare.main()
    # exactly: everything the tools can reach counts as evidence, and an
    # identifier the question itself supplied is quotation, not assertion.
    context = "\n".join(
        [p.read_text() for p in sorted(oscal.glob("*.json"))]
        + [p.read_text() for p in sorted((root / "data/mappings").glob("*.csv"))]
    )
    golden = json.loads((root / "evals/golden_set.json").read_text())
    questions = {c["id"]: c.get("question", "") for c in golden["cases"]}

    report = analyse(cases, context, "grounded", questions)
    assert report["unsupported_identifier_count"] == 0, (
        "agents asserted identifiers absent from the artifacts their tools read: "
        f"{report['detail']}"
    )


def test_analysis_scope_is_the_whole_corpus_not_one_conversation():
    """Pin the known limit of this instrument, so the claim is not overstated.

    "Supported" here means *the identifier appears somewhere in the OSCAL
    document set the tools can reach* -- not "this answer's own tool calls
    returned it". The catalog carries every NIST and ATT&CK identifier in
    scope, so this test is a floor on fabrication, not a proof of per-answer
    citation. Narrowing it would require recording per-conversation tool
    output, which the eval harness does not yet capture.
    """
    cases = [{"id": "x", "passed": True, "answer": "Mitigates T1110.003."}]
    # Present anywhere in the corpus -> counted as supported, even though this
    # particular answer may never have called a tool that returned it.
    assert analyse(cases, "unrelated prose mentioning T1110.003", "t")[
        "unsupported_identifier_count"
    ] == 0
