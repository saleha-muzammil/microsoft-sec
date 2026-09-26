"""Output-side grounding: audit an answer, then show the evidence.

The agent layer is grounded *by construction* — tools over validated OSCAL are
the only way a compliance fact enters a conversation. This module closes the
other half of the loop by auditing what comes *out*: every checkable identifier
in a finished answer (SCuBA policy IDs, NIST 800-53 control IDs, MITRE ATT&CK
technique IDs, OSCAL UUIDs) is verified to exist in the evidence corpus the
tools can reach. An identifier the corpus has never seen could only have come
from model memory, so it is flagged before anyone acts on it.

This is deliberately the same detector the offline eval uses
(``evals/compare.py`` imports its patterns from here), so the number shown on
screen and the number in the published comparison are produced by one piece of
tested code, not two implementations that could drift.

The second half, :meth:`EvidenceCorpus.resolve`, answers the reviewer's next
question — *show me* — by locating the exact OSCAL node an identifier lives in,
so a cited fact can be traced to the validated JSON that carries it.

What this audits and what it does not: identifiers are checkable because they
are exact strings; prose and arithmetic are not audited here. The audit shows
that nothing was cited from outside the evidence, not that every sentence is a
faithful summary of it — that guarantee comes from the tool layer's tests.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

#: Repository root; mirrors the reasoning in agents.tools — reference data
#: ships with the code even when the OSCAL set came from an uploaded scan.
DATA_ROOT = Path(__file__).resolve().parents[2]

# No trailing \b on the NIST pattern: a word boundary cannot follow ")", which
# would silently truncate "AC-2(12)" to "AC-2" and lose exactly the
# enhancement-level precision that distinguishes a correct mapping from a
# wrong one.
NIST_ID = re.compile(r"\b[A-Z]{2}-\d+(?:\(\d+\))*[a-z]?")
ATTACK_ID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
SCUBA_ID = re.compile(r"\bMS\.[A-Za-z]+\.\d+\.\d+v\d+\b")
UUID_ID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def asserted_identifiers(text: str) -> set[str]:
    """Every checkable identifier asserted in *text*, as written."""
    return (
        set(NIST_ID.findall(text))
        | set(ATTACK_ID.findall(text))
        | set(SCUBA_ID.findall(text))
        | set(UUID_ID.findall(text))
    )


def sha256_of(path: str | Path) -> str:
    """Hex SHA-256 of a file, streamed so large scans do not load into memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class GroundingAudit:
    """The verdict on one answer: what it cited, and what nothing supports."""

    asserted: tuple[str, ...]
    unsupported: tuple[str, ...]
    #: In the question but not the evidence: quoted back, not asserted. An
    #: agent answering "MS.FAKE.9.9v9 does not exist" must be able to name the
    #: thing it is denying without the audit calling that a fabrication.
    echoed: tuple[str, ...] = ()

    @property
    def verified(self) -> tuple[str, ...]:
        excluded = set(self.unsupported) | set(self.echoed)
        return tuple(i for i in self.asserted if i not in excluded)

    @property
    def ok(self) -> bool:
        return not self.unsupported


@dataclass(frozen=True)
class Evidence:
    """One place an identifier lives: a document, a path into it, the node."""

    document: str
    pointer: str
    node: dict


class EvidenceCorpus:
    """Everything the agent's tools can reach, as an auditable identifier set.

    The corpus is the generated OSCAL document set plus the shipped reference
    data the tools also read — CISA's NIST crosswalk and rename table, and the
    SEC530 control IDs the Virginia join can surface. Auditing against the
    OSCAL set alone would flag a correctly-cited SEC530 control as fabricated,
    which is precisely the kind of false alarm that teaches people to ignore
    the audit.
    """

    def __init__(self, oscal_dir: str | Path, data_root: str | Path | None = None):
        self.oscal_dir = Path(oscal_dir)
        self.data_root = Path(data_root) if data_root else DATA_ROOT

    # ------------------------------------------------------------------ corpus

    #: Resolution order. Alphabetical order would answer "show me
    #: MS.AAD.3.1v1" with the assessment *plan* — true, but not what a reviewer
    #: means by evidence. The requirement and the observed result come first.
    _PREFERRED = (
        "scuba-m365-catalog.json",
        "scuba-assessment-results.json",
        "scuba-poam.json",
        "scuba-nist-mapping.json",
    )

    def _documents(self) -> list[Path]:
        paths = sorted(p for p in self.oscal_dir.glob("*.json") if p.is_file())
        rank = {name: i for i, name in enumerate(self._PREFERRED)}
        return sorted(paths, key=lambda p: (rank.get(p.name, len(rank)), p.name))

    @cached_property
    def identifiers(self) -> set[str]:
        """Lower-cased identifiers present anywhere in the evidence."""
        pieces: list[str] = [p.read_text() for p in self._documents()]

        mappings = self.data_root / "data/mappings"
        for csv in sorted(mappings.glob("*.csv")) if mappings.exists() else []:
            pieces.append(csv.read_text())

        found = {i.lower() for i in asserted_identifiers("\n".join(pieces))}

        # SEC530 IDs come from an xlsx the regexes cannot read; take them from
        # the same parser the Virginia tool uses. Optional dependency, optional
        # file — absence just means Virginia IDs are not vouched for.
        workbook = self.data_root / "data/virginia/SEC530_Control_Summaries.xlsx"
        if workbook.exists():
            try:
                from .virginia import parse_sec530

                for control in parse_sec530(workbook).values():
                    found.update(
                        i.lower() for i in asserted_identifiers(control.published_id)
                    )
            except Exception:
                pass
        return found

    # ------------------------------------------------------------------- audit

    def audit(self, answer: str, question: str = "") -> GroundingAudit:
        """Check every identifier the answer asserts against the corpus.

        Identifiers that appear in *question* but not in the corpus are
        reported as ``echoed``, not ``unsupported``: the user introduced them,
        so repeating one back (typically to deny it exists) is quotation, not
        a claim from model memory.
        """
        asked = {i.lower() for i in asserted_identifiers(question)}
        asserted = sorted(asserted_identifiers(answer))
        unknown = [i for i in asserted if i.lower() not in self.identifiers]
        return GroundingAudit(
            asserted=tuple(asserted),
            unsupported=tuple(i for i in unknown if i.lower() not in asked),
            echoed=tuple(i for i in unknown if i.lower() in asked),
        )

    # ----------------------------------------------------------------- resolve

    def resolve(self, identifier: str, limit: int = 3) -> list[Evidence]:
        """Locate the OSCAL nodes that carry *identifier*.

        Returns the nearest enclosing citable object (one with a ``uuid`` or
        ``id``) rather than the raw string match, because "show me the
        evidence" means the observation or control, not a bare prop.
        """
        target = identifier.lower()
        out: list[Evidence] = []
        for path in self._documents():
            doc = json.loads(path.read_text())
            # One node per document: the requirement, the observed result and
            # the POA&M item tell a reviewer more than three parts of the same
            # control ever would.
            for pointer, node in _matches(doc, target):
                out.append(Evidence(document=path.name, pointer=pointer, node=node))
                break
            if len(out) >= limit:
                return out
        return out


def _matches(doc: Any, target: str) -> Iterator[tuple[str, dict]]:
    """Yield (json-pointer, citable-node) for each place *target* appears.

    A scalar matches when it equals the target or contains it in a short
    value (props and id-refs, not paragraphs of prose). The node returned is
    the innermost ancestor carrying a ``uuid`` or ``id`` — unless serialising
    it would drown the reader, in which case the immediate parent object wins.
    """
    seen: set[str] = set()

    def walk(node: Any, pointer: str, ancestors: list[tuple[str, dict]]) -> Iterator:
        if isinstance(node, dict):
            here = ancestors + [(pointer, node)]
            for key, value in node.items():
                if isinstance(value, str) and _hit(value, target):
                    anchor_ptr, anchor = _anchor(here)
                    if anchor_ptr not in seen:
                        seen.add(anchor_ptr)
                        yield anchor_ptr, anchor
                elif isinstance(value, (dict, list)):
                    yield from walk(value, f"{pointer}/{key}", here)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                yield from walk(item, f"{pointer}/{i}", ancestors)

    yield from walk(doc, "", [])


def _hit(value: str, target: str) -> bool:
    lowered = value.lower()
    return lowered == target or (len(value) <= 300 and target in lowered)


def _anchor(ancestors: list[tuple[str, dict]]) -> tuple[str, dict]:
    for pointer, node in reversed(ancestors):
        if "uuid" in node or "id" in node:
            if len(json.dumps(node)) <= 6000:
                return pointer, node
    # Nothing citable and small: fall back to the innermost object.
    return ancestors[-1]
