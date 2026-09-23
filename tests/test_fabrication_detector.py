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
    """
    import json

    root = Path(__file__).resolve().parents[1]
    report = root / "evals/comparison.json"
    if not report.exists():
        import pytest

        pytest.skip("run evals/compare.py to generate the comparison")
    grounded = json.loads(report.read_text())["grounded"]
    assert grounded["unsupported_identifier_count"] == 0
