"""Resolve SCuBA policies to NIST SP 800-53 Rev 5 controls.

The critical design decision in this project: **CISA already publishes the
authoritative crosswalk**, so we bind to it rather than asking a language model
to guess. ``scuba-to-nist-sp-800-53-r5-fedramp-high.csv`` ships in the
ScubaGear repository under CC0.

This matters because existing third-party tooling silently disagrees with CISA.
One published tool maps ``MS.AAD.1.1v1`` to ``IA-2(1)``; CISA says ``CM-7``.
A mapping that contradicts the source of truth is not a feature, it is a defect,
and no amount of model confidence makes it correct.

Resolution order:

1. **Direct hit** in CISA's crosswalk -> provenance ``cisa-authoritative``.
2. **Migrated hit**: the policy ID changed between baseline versions, so the
   ID is translated through CISA's own migration table first -> still
   ``cisa-authoritative``, because the underlying mapping is CISA's.
3. **Unmapped** -> eligible for an AI-proposed mapping, which is recorded with
   a confidence score, kept provenance-tagged as ``ai-proposed``, and never
   silently merged into the authoritative set.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Provenance(str, Enum):
    CISA = "cisa-authoritative"
    CISA_MIGRATED = "cisa-authoritative-migrated"
    AI = "ai-proposed"
    NONE = "unmapped"

    @property
    def is_authoritative(self) -> bool:
        return self in (Provenance.CISA, Provenance.CISA_MIGRATED)


# "AC-2(12)" -> ac-2.12 ; "IA-5c" -> ia-5 ; "SC-7(10)(a)" -> sc-7.10
_CTRL = re.compile(r"^([A-Za-z]{2})-(\d+)((?:\(\d+\))*)([a-z])?", re.IGNORECASE)


def normalise_control_id(raw: str) -> str:
    """Normalise a NIST 800-53 control ID to OSCAL catalog form.

    CISA writes control IDs in publication style (``AC-2(12)``, ``IA-5c``,
    ``SC-7(10)(a)``). The NIST OSCAL 800-53 catalog uses ``ac-2.12``,
    ``ia-5``, ``sc-7.10``. Lowercase statement-part suffixes identify a
    statement *within* a control, not a separate control, so they are dropped
    from the control reference (the original string is retained as a property
    so nothing is lost).
    """
    text = (raw or "").strip()
    match = _CTRL.match(text)
    if not match:
        return text.lower()
    family, number, enhancements, _suffix = match.groups()
    out = f"{family.lower()}-{number}"
    for enh in re.findall(r"\((\d+)\)", enhancements or ""):
        out += f".{enh}"
    return out


@dataclass(frozen=True)
class ControlMapping:
    policy_id: str
    nist_controls: tuple[str, ...]      # normalised OSCAL ids
    raw_controls: tuple[str, ...]       # exactly as CISA published them
    provenance: Provenance
    confidence: float | None = None     # only meaningful for ai-proposed
    rationale: str = ""
    migrated_from: str | None = None


class MappingIndex:
    """CISA's authoritative crosswalk plus the baseline migration table."""

    def __init__(self, crosswalk_csv: str | Path, migrations_csv: str | Path | None = None):
        self.crosswalk: dict[str, tuple[str, ...]] = {}
        with open(crosswalk_csv, newline="", encoding="utf-8-sig") as handle:
            for row in csv.DictReader(handle):
                policy = (row.get("scuba-control-id") or "").strip()
                controls = (row.get("nist-800-53-control-id") or "").strip()
                if not policy:
                    continue
                parts = tuple(c.strip() for c in controls.split(",") if c.strip())
                # CISA's CSV contains at least one duplicated policy row
                # (MS.SECURITYSUITE.2.4v1). Merge rather than let the last
                # row silently win.
                if policy in self.crosswalk:
                    merged = list(self.crosswalk[policy])
                    merged += [p for p in parts if p not in merged]
                    self.crosswalk[policy] = tuple(merged)
                else:
                    self.crosswalk[policy] = parts

        # old policy id -> new policy id, across baseline versions
        self.migrations: dict[str, str] = {}
        if migrations_csv and Path(migrations_csv).exists():
            with open(migrations_csv, newline="", encoding="utf-8-sig") as handle:
                for row in csv.DictReader(handle):
                    old = (row.get("Old ID") or "").strip()
                    new = (row.get("New ID") or "").strip()
                    if old and new:
                        self.migrations[old] = new

    def resolve(self, policy_id: str) -> ControlMapping:
        """Resolve one SCuBA policy to NIST controls, recording provenance."""
        raw = self.crosswalk.get(policy_id)
        if raw:
            return ControlMapping(
                policy_id=policy_id,
                nist_controls=tuple(normalise_control_id(c) for c in raw),
                raw_controls=raw,
                provenance=Provenance.CISA,
                rationale="Direct entry in CISA's published SCuBA to NIST SP 800-53 Rev 5 crosswalk.",
            )

        # Follow the migration chain: a policy renamed across baseline versions
        # still carries CISA's mapping under its new identifier.
        seen: set[str] = set()
        current = policy_id
        while current in self.migrations and current not in seen:
            seen.add(current)
            current = self.migrations[current]
            raw = self.crosswalk.get(current)
            if raw:
                return ControlMapping(
                    policy_id=policy_id,
                    nist_controls=tuple(normalise_control_id(c) for c in raw),
                    raw_controls=raw,
                    provenance=Provenance.CISA_MIGRATED,
                    rationale=(
                        f"{policy_id} was superseded by {current} in a later baseline "
                        f"version; CISA's crosswalk entry for {current} applies."
                    ),
                    migrated_from=current,
                )

        return ControlMapping(
            policy_id=policy_id,
            nist_controls=(),
            raw_controls=(),
            provenance=Provenance.NONE,
            rationale="No entry in CISA's crosswalk, directly or via baseline migration.",
        )

    def resolve_all(self, policy_ids: list[str]) -> list[ControlMapping]:
        return [self.resolve(p) for p in policy_ids]

    def coverage(self, policy_ids: list[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for mapping in self.resolve_all(policy_ids):
            counts[mapping.provenance.value] = counts.get(mapping.provenance.value, 0) + 1
        return counts
