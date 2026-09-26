"""Emit the SCuBA -> NIST 800-53 crosswalk as an OSCAL **mapping-collection**.

OSCAL 1.2 introduced a first-class Control Mapping model, and it fits this
problem unusually well: ``provenance``, ``confidence-score`` and
``matching-rationale`` are native fields, not conventions we had to invent.
That means our provenance distinction is expressed in the standard itself and
is machine-readable by any OSCAL-aware tool.

As shipped, **every mapping in this document is CISA's own** and the emitted
``provenance.method`` is ``automation`` accordingly. The ``ai-proposed`` branch
exists in the data model for a future human-in-the-loop workflow; the document
describes whichever case actually produced it, because provenance metadata that
overstates machine involvement is as much a defect as provenance that hides it.

``matching-rationale`` values align with NIST IR 8477 s4.3 (Set Theory
Relationship Mapping).
"""

from __future__ import annotations

from datetime import datetime

from ..ids import det_uuid
from ..parsers.mappings import ControlMapping, MappingIndex
from .catalog import OSCAL_VERSION, SCUBA_NS, _line, oscal_timestamp

NIST_80053_HREF = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/"
    "SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)


def _confidence(mapping: ControlMapping) -> dict:
    """Confidence expressed in OSCAL's native form.

    Authoritative mappings are a category, not a probability: CISA published
    them, so a numeric score would imply a false precision. AI-proposed
    mappings carry an explicit percentage.
    """
    if mapping.provenance.is_authoritative:
        return {"category": "authoritative"}
    return {"percentage": round(mapping.confidence or 0.0, 2)}


BASE_DESCRIPTION = (
    "Derived from CISA's published SCuBA to NIST SP 800-53 Rev 5 (FedRAMP High) "
    "crosswalk, with policy identifiers resolved through CISA's baseline migration "
    "table where they changed between baseline versions."
)


def _provenance_description(ai_proposed: int) -> str:
    """Describe how this document was actually produced.

    The description must match the document in hand, not the capability the
    data model reserves. Stating that unpublished mappings "are marked
    ai-proposed and carry a confidence score" in an artifact containing zero of
    them tells a reader that a model touched mappings here. None did.
    """
    if not ai_proposed:
        return (
            f"{BASE_DESCRIPTION} Every mapping in this document is CISA's own; none is "
            "model-generated or inferred. Policies CISA has not mapped are omitted "
            "rather than guessed at."
        )
    return (
        f"{BASE_DESCRIPTION} {ai_proposed} mapping(s) CISA has not published are marked "
        "ai-proposed and carry a numeric confidence score; they are never merged into "
        "the authoritative set."
    )


def build_mapping_collection(
    mappings: list[ControlMapping],
    catalog_href: str = "scuba-m365-catalog.json",
    last_modified: datetime | None = None,
) -> dict:
    """Build an OSCAL mapping-collection from resolved control mappings."""
    resolved = [m for m in mappings if m.nist_controls]

    maps = []
    for mapping in resolved:
        props = [
            {"name": "provenance", "ns": SCUBA_NS, "value": mapping.provenance.value},
            {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": mapping.policy_id},
        ]
        # Preserve CISA's original publication-style IDs alongside the
        # normalised OSCAL ones, so nothing is lost in translation.
        for raw in mapping.raw_controls:
            props.append({"name": "source-control-id", "ns": SCUBA_NS, "value": raw})
        if mapping.migrated_from:
            props.append(
                {"name": "migrated-to", "ns": SCUBA_NS, "value": mapping.migrated_from}
            )

        maps.append(
            {
                "uuid": det_uuid("map", mapping.policy_id),
                # SCuBA policies are narrower than the 800-53 controls they
                # support, so the SCuBA policy is a subset of the NIST control.
                "relationship": "subset-of",
                "matching-rationale": "semantic",
                "confidence-score": _confidence(mapping),
                "sources": [{"type": "control", "id-ref": mapping.policy_id.lower()}],
                "targets": [{"type": "control", "id-ref": cid} for cid in mapping.nist_controls],
                "props": props,
                "remarks": _line(mapping.rationale),
            }
        )

    total = len(mappings)
    covered = len(resolved)
    authoritative = sum(1 for m in resolved if m.provenance.is_authoritative)
    ai_proposed = covered - authoritative

    return {
        "mapping-collection": {
            "uuid": det_uuid("mapping-collection", ",".join(sorted(m.policy_id for m in mappings))),
            "metadata": {
                "title": "CISA SCuBA to NIST SP 800-53 Rev 5 Control Mapping",
                "last-modified": oscal_timestamp(last_modified),
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "authoritative-mappings", "ns": SCUBA_NS, "value": str(authoritative)},
                    {"name": "ai-proposed-mappings", "ns": SCUBA_NS, "value": str(ai_proposed)},
                ],
            },
            "provenance": {
                # OSCAL allows human | automation | hybrid. Every mapping here
                # is produced by mechanically consuming CISA's published
                # crosswalk and migration table -- no model proposes one, and
                # no human adjudicates one per-map -- so this is "automation".
                # It said "hybrid" previously, which told any OSCAL-aware
                # consumer that some mappings were model-generated while the
                # document's own ai-proposed-mappings prop read 0.
                "method": "hybrid" if ai_proposed else "automation",
                "matching-rationale": "semantic",
                "status": "complete" if covered == total else "not-complete",
                "mapping-description": _provenance_description(ai_proposed),
                "coverage": {
                    "generation-method": "ratio of SCuBA policies with a resolved NIST mapping",
                    "target-coverage": round(covered / total, 4) if total else 0.0,
                },
            },
            "mappings": [
                {
                    "uuid": det_uuid("mapping", "scuba-to-80053"),
                    "source-resource": {"type": "catalog", "href": catalog_href},
                    "target-resource": {"type": "catalog", "href": NIST_80053_HREF},
                    "maps": maps,
                }
            ],
        }
    }


def build_from_index(
    index: MappingIndex,
    policy_ids: list[str],
    catalog_href: str = "scuba-m365-catalog.json",
    last_modified: datetime | None = None,
) -> dict:
    return build_mapping_collection(index.resolve_all(policy_ids), catalog_href, last_modified)
