"""Guard the project's central correctness claim.

Every SCuBA -> NIST 800-53 mapping we emit must be *exactly* what CISA
published. Third-party SCuBA tooling demonstrably drifts from CISA's crosswalk
-- one published tool maps MS.AAD.1.1v1 to IA-2(1) where CISA says CM-7 -- and
a mapping that silently contradicts the source of truth is a defect, not a
feature.

These tests fail the build on any divergence. They are the reason we can claim
provenance-correctness rather than merely assert it.
"""

from __future__ import annotations

import csv

import pytest
from conftest import CROSSWALK

from scuba_oscal.parsers.mappings import Provenance, normalise_control_id


def _cisa_rows() -> dict[str, list[str]]:
    """Read CISA's CSV independently of our parser, so a parser bug cannot
    make this test agree with itself."""
    out: dict[str, list[str]] = {}
    with open(CROSSWALK, newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            policy = row["scuba-control-id"].strip()
            controls = [c.strip() for c in row["nist-800-53-control-id"].split(",") if c.strip()]
            out.setdefault(policy, []).extend(controls)
    return out


def test_every_authoritative_mapping_matches_cisa_exactly(index):
    """No authoritative mapping may add, drop, or alter a NIST control."""
    cisa = _cisa_rows()
    divergences = []

    for policy_id, expected_raw in cisa.items():
        resolved = index.resolve(policy_id)
        assert resolved.provenance is Provenance.CISA, (
            f"{policy_id} is in CISA's crosswalk but resolved as "
            f"{resolved.provenance.value}"
        )
        expected = {normalise_control_id(c) for c in expected_raw}
        actual = set(resolved.nist_controls)
        if expected != actual:
            divergences.append(
                f"{policy_id}: CISA={sorted(expected)} ours={sorted(actual)}"
            )

    assert not divergences, "Mappings diverge from CISA's published crosswalk:\n" + "\n".join(
        divergences
    )


def test_known_divergence_of_third_party_tooling(index):
    """Pin the specific case where other tooling is wrong.

    MS.AAD.1.1v1 blocks legacy authentication. CISA maps it to CM-7 (Least
    Functionality) -- disabling an unnecessary protocol. At least one published
    tool maps it to IA-2(1), an MFA control. CM-7 is the correct reading, and
    this test makes sure we never drift toward the popular-but-wrong answer.
    """
    resolved = index.resolve("MS.AAD.1.1v1")
    assert resolved.nist_controls == ("cm-7",)
    assert "ia-2.1" not in resolved.nist_controls


def test_ai_mappings_are_never_authoritative():
    """An AI-proposed mapping must never claim CISA provenance."""
    from scuba_oscal.parsers.mappings import ControlMapping

    proposed = ControlMapping(
        policy_id="MS.DEFENDER.1.1v1",
        nist_controls=("si-4",),
        raw_controls=("SI-4",),
        provenance=Provenance.AI,
        confidence=0.82,
    )
    assert not proposed.provenance.is_authoritative


def test_ai_proposal_cannot_override_a_cisa_mapping(index):
    """Resolution order must always prefer CISA, whatever a model suggests."""
    resolved = index.resolve("MS.AAD.1.1v1")
    assert resolved.provenance.is_authoritative
    assert resolved.confidence is None, "authoritative mappings carry no numeric confidence"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CM-7", "cm-7"),
        ("AC-2(12)", "ac-2.12"),
        ("IA-5c", "ia-5"),           # trailing statement part is not a control
        ("SC-7(10)(a)", "sc-7.10"),
        ("IA-2(1)", "ia-2.1"),
    ],
)
def test_control_id_normalisation(raw, expected):
    assert normalise_control_id(raw) == expected


def test_migration_preserves_cisa_provenance(index):
    """A policy renamed across baseline versions keeps CISA's mapping."""
    migrated = [
        index.resolve(p) for p in index.migrations if index.resolve(p).migrated_from
    ]
    assert migrated, "expected at least one policy resolved via the migration table"
    for mapping in migrated:
        assert mapping.provenance is Provenance.CISA_MIGRATED
        assert mapping.provenance.is_authoritative
        assert mapping.nist_controls


def test_range_notation_resolves_to_cisas_published_answer(index):
    """Regression guard for a bug that produced a factually false statement.

    CISA's migration table supersedes MS.DEFENDER.1.1v1 with the range
    MS.SECURITYSUITE.1.1v1 - .1.4v1. Every policy in that range maps to SI-3,
    so CISA *has* published an answer. Declining to follow the range made the
    tool report "CISA has not published a NIST mapping for this policy" --
    an unsupported claim about CISA, in the subsystem whose whole purpose is
    provenance correctness.
    """
    resolved = index.resolve("MS.DEFENDER.1.1v1")
    assert resolved.nist_controls == ("si-3",)
    assert resolved.provenance is Provenance.CISA_MIGRATED
    assert resolved.provenance.is_authoritative


def test_range_only_resolves_when_every_member_agrees(index):
    """If policies in a range disagreed on their mapping, there would be no
    unambiguous answer and we must not pick one."""
    from scuba_oscal.parsers.mappings import MigrationKind, normalise_control_id

    for record in index.migration_records.values():
        if record.kind is not MigrationKind.RANGE:
            continue
        sets = [index.crosswalk.get(n) for n in record.new_ids]
        if not all(sets):
            assert index.resolve(record.old_id).provenance is Provenance.NONE
            continue
        distinct = {frozenset(normalise_control_id(c) for c in s) for s in sets}
        resolved = index.resolve(record.old_id)
        if len(distinct) == 1:
            assert resolved.provenance.is_authoritative
        else:
            assert resolved.provenance is Provenance.NONE


def test_deterministic_coverage_on_the_sample_run(index, run):
    """Pin the headline number so it cannot drift silently."""
    coverage = index.coverage([p.policy_id for p in run.policies])
    deterministic = sum(v for k, v in coverage.items() if k.startswith("cisa"))
    assert deterministic == 89
    assert coverage.get("unmapped", 0) == 3
    assert deterministic + coverage.get("unmapped", 0) == len(run.policies)
