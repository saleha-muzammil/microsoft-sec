"""Emit the SCuBA -> NIST 800-53 crosswalk as an OSCAL **mapping-collection**.

OSCAL 1.2 introduced a first-class Control Mapping model, and it fits this
problem unusually well: ``provenance``, ``confidence-score`` and
``matching-rationale`` are native fields, not conventions we had to invent.
That means our "authoritative vs AI-proposed" distinction is expressed in the
standard itself and is machine-readable by any OSCAL-aware tool.

``matching-rationale`` values align with NIST IR 8477 s4.3 (Set Theory
Relationship Mapping).
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..ids import det_uuid
from ..parsers.mappings import ControlMapping, MappingIndex
from .catalog import OSCAL_VERSION, SCUBA_NS, _line

NIST_80053_HREF = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/"
    "SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _confidence(mapping: ControlMapping) -> dict:
    """Confidence expressed in OSCAL's native form.

    Authoritative mappings are a category, not a probability: CISA published
    them, so a numeric score would imply a false precision. AI-proposed
    mappings carry an explicit percentage.
    """
    if mapping.provenance.is_authoritative:
        return {"category": "authoritative"}
    return {"percentage": round(mapping.confidence or 0.0, 2)}


def build_mapping_collection(
    mappings: list[ControlMapping],
    catalog_href: str = "scuba-m365-catalog.json",
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

    return {
        "mapping-collection": {
            "uuid": det_uuid("mapping-collection", ",".join(sorted(m.policy_id for m in mappings))),
            "metadata": {
                "title": "CISA SCuBA to NIST SP 800-53 Rev 5 Control Mapping",
                "last-modified": _now(),
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "authoritative-mappings", "ns": SCUBA_NS, "value": str(authoritative)},
                    {
                        "name": "ai-proposed-mappings",
                        "ns": SCUBA_NS,
                        "value": str(covered - authoritative),
                    },
                ],
            },
            "provenance": {
                # "hybrid": the overwhelming majority is CISA's published
                # crosswalk consumed mechanically; a labelled minority is
                # AI-proposed for policies CISA has not yet mapped.
                "method": "hybrid",
                "matching-rationale": "semantic",
                "status": "complete" if covered == total else "not-complete",
                "mapping-description": (
                    "Derived from CISA's published SCuBA to NIST SP 800-53 Rev 5 (FedRAMP High) "
                    "crosswalk, with policy identifiers resolved through CISA's baseline "
                    "migration table where they changed between baseline versions. Mappings "
                    "CISA has not published are marked ai-proposed and carry a numeric "
                    "confidence score; they are never merged into the authoritative set."
                ),
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
    index: MappingIndex, policy_ids: list[str], catalog_href: str = "scuba-m365-catalog.json"
) -> dict:
    return build_mapping_collection(index.resolve_all(policy_ids), catalog_href)
