"""End-to-end pipeline guarantees: reproducibility and the validation gate.

These two properties are claimed prominently -- "regenerating artifacts
produces a byte-stable diff" and "every artifact must validate before it is
written to disk" -- so they are asserted against the real pipeline rather than
against a single transformer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import BASELINES, CROSSWALK, MIGRATIONS, SAMPLE_RUN

from scuba_oscal.pipeline import InvalidArtifactError, generate


def _generate(out: Path) -> dict[str, Path]:
    return generate(
        baselines_path=str(BASELINES),
        run_path=str(SAMPLE_RUN),
        out_dir=str(out),
        crosswalk_path=str(CROSSWALK),
        migrations_path=str(MIGRATIONS),
    )


def test_pipeline_output_is_byte_identical_across_runs(tmp_path):
    """Re-running on unchanged input must be a byte-for-byte no-op.

    Anything else makes `git diff` on the artifacts pure noise, and makes
    "nothing changed since the last assessment" indistinguishable from
    "everything changed".
    """
    first = {model: path.read_bytes() for model, path in _generate(tmp_path / "a").items()}
    second = {model: path.read_bytes() for model, path in _generate(tmp_path / "b").items()}

    assert first.keys() == second.keys()
    differing = sorted(model for model in first if first[model] != second[model])
    assert not differing, f"documents changed with no input change: {differing}"


def test_every_document_carries_the_assessment_timestamp(tmp_path):
    """`last-modified` tracks the run, not the clock, which is why it is stable."""
    written = _generate(tmp_path / "out")
    stamps = set()
    for path in written.values():
        doc = json.loads(path.read_text())
        stamps.add(next(iter(doc.values()))["metadata"]["last-modified"])
    assert stamps == {"2026-05-04T17:15:48.307Z"}


def test_generation_refuses_to_write_an_invalid_document(tmp_path, monkeypatch):
    """The validation gate is fatal, not advisory.

    An invalid artifact is not a degraded artifact: everything downstream reads
    what is on disk as evidence, so it must never get there.
    """
    import scuba_oscal.pipeline as pipeline

    real_build = pipeline.build_catalog

    def broken(baselines, products=None, last_modified=None):
        # Structurally intact so the pipeline gets as far as writing it, but
        # schema-invalid: `uuid` must match OSCAL's UUID datatype.
        doc = real_build(baselines, products, last_modified)
        doc["catalog"]["uuid"] = "not-a-uuid"
        return doc

    monkeypatch.setattr(pipeline, "build_catalog", broken)

    out = tmp_path / "out"
    with pytest.raises(InvalidArtifactError) as excinfo:
        _generate(out)
    assert excinfo.value.model == "catalog"
    assert not list(out.glob("*.json")), "an invalid document must not reach disk"


def test_validation_gate_can_be_observed_passing(tmp_path):
    """The happy path writes all eight documents with validation enabled."""
    written = _generate(tmp_path / "out")
    assert len(written) == 8
    assert all(path.exists() for path in written.values())


def test_pipeline_emits_exemption_risks_when_given_a_config(tmp_path):
    """The exemption ledger must reach a generated artifact, not just the UI."""
    config = BASELINES.parent.parent / "scubagear_samples/scuba_config_example.yaml"
    written = generate(
        baselines_path=str(BASELINES),
        run_path=str(SAMPLE_RUN),
        out_dir=str(tmp_path / "out"),
        crosswalk_path=str(CROSSWALK),
        migrations_path=str(MIGRATIONS),
        config_path=str(config),
    )
    poam = json.loads(written["poam"].read_text())["plan-of-action-and-milestones"]
    props = {p["name"]: p["value"] for p in poam["metadata"]["props"]}
    assert props["exemptions"] == "6"
    assert props["expired-exemptions"] == "2"

    emitted = [
        r for r in poam["risks"]
        if any(p["name"] == "exemption-kind" for p in r.get("props", []))
    ]
    assert len(emitted) == 6
    assert "expired" in poam["metadata"]["remarks"]


def test_pipeline_without_a_config_emits_no_exemption_risks(tmp_path):
    written = _generate(tmp_path / "out")
    poam = json.loads(written["poam"].read_text())["plan-of-action-and-milestones"]
    assert not [
        r for r in poam["risks"]
        if any(p["name"] == "exemption-kind" for p in r.get("props", []))
    ]
    assert not [p for p in poam["metadata"]["props"] if p["name"] == "exemptions"]
