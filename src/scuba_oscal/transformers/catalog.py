"""Transform CISA SCuBA baselines into an OSCAL **catalog**.

Structure mirrors SCuBA's own organisation so the mapping stays auditable:

    catalog
      group  ms.aad                 (one per M365 product)
        group  ms.aad.1             (one per baseline policy section)
          control  ms.aad.1.1v1     (one per SCuBA policy)

Nothing here is inferred by a language model. Every field is a mechanical
projection of CISA-authored content, which is what makes the output citable.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..ids import control_uuid, det_uuid
from ..parsers.baselines import BaselineCatalog, BaselinePolicy

OSCAL_VERSION = "1.2.3"

#: Namespace for SCuBA-specific properties, so they cannot be confused with
#: OSCAL core props of the same name.
SCUBA_NS = "https://github.com/cisagov/ScubaGear/ns/oscal"

PRODUCT_TITLES = {
    "aad": "Microsoft Entra ID (Azure Active Directory)",
    "defender": "Microsoft 365 Defender",
    "exo": "Exchange Online",
    "powerbi": "Power BI",
    "powerplatform": "Power Platform",
    "securitysuite": "Microsoft 365 Security Suite",
    "sharepoint": "SharePoint Online and OneDrive",
    "teams": "Microsoft Teams",
}


def _control_id(policy_id: str) -> str:
    """OSCAL control id. Lowercased by convention; dots are legal in a token."""
    return policy_id.lower()


def _line(text: str) -> str:
    """Collapse a string to a single line.

    OSCAL's ``markup-line`` datatype (used by title, link text, and prop
    values) forbids newlines: the pattern is ``^[^\n]+$``. CISA's baseline
    JSON wraps some resource names across lines, so those values must be
    flattened before they can be emitted.
    """
    return " ".join((text or "").split())


def _dedupe(items: list[dict], *keys: str) -> list[dict]:
    """Drop duplicates, preserving first-seen order.

    OSCAL enforces uniqueness of props by (name, ns, class, value) and of links
    by (href, rel) within a given context. CISA's baseline JSON legitimately
    repeats some MITRE techniques and resource URLs within a single policy, so
    a faithful projection would otherwise emit a document the validator
    rejects. We de-duplicate rather than mangle the source data.
    """
    seen: set[tuple] = set()
    out: list[dict] = []
    for item in items:
        signature = tuple(item.get(k) for k in keys)
        if signature in seen:
            continue
        seen.add(signature)
        out.append(item)
    return out


def _policy_parts(policy: BaselinePolicy) -> list[dict]:
    """Build the control's prose parts.

    OSCAL arrays carry ``minItems: 1``, so a part is only emitted when it
    actually has prose. Emitting an empty array fails validation.
    """
    cid = _control_id(policy.policy_id)
    parts: list[dict] = [
        {"id": f"{cid}_smt", "name": "statement", "prose": policy.name}
    ]
    if policy.rationale:
        # "rationale" is not one of OSCAL's core part names (the allowed set is
        # assessment, assessment-method, assessment-objective, example,
        # guidance, objective, overview, statement). Rather than discard
        # CISA's rationale prose or mislabel it as guidance, we declare it in
        # our own namespace, which is the mechanism OSCAL provides for
        # domain-specific extensions.
        parts.append(
            {"id": f"{cid}_rat", "name": "rationale", "ns": SCUBA_NS, "prose": policy.rationale}
        )
    if policy.implementation:
        parts.append({"id": f"{cid}_gdn", "name": "guidance", "prose": policy.implementation})
    return parts


def _policy_props(policy: BaselinePolicy) -> list[dict]:
    props = [
        {"name": "label", "value": policy.policy_id},
        {"name": "criticality", "ns": SCUBA_NS, "value": policy.criticality},
        # SHALL policies are mandatory; surfacing this as a discrete prop lets
        # downstream tooling filter without re-parsing the criticality string.
        {"name": "mandatory", "ns": SCUBA_NS, "value": "true" if policy.is_mandatory else "false"},
        {"name": "product", "ns": SCUBA_NS, "value": policy.product},
    ]
    if policy.last_modified:
        props.append({"name": "last-modified", "ns": SCUBA_NS, "value": _line(policy.last_modified)})
    for technique in policy.mitre:
        if technique.technique_id:
            props.append(
                {
                    "name": "mitre-attack-technique",
                    "ns": SCUBA_NS,
                    "value": technique.technique_id,
                    "remarks": _line(technique.name),
                }
            )
    for badge in policy.badges:
        if badge:
            props.append({"name": "badge", "ns": SCUBA_NS, "value": _line(badge)})
    return _dedupe(props, "name", "ns", "class", "value")


def _policy_links(policy: BaselinePolicy) -> list[dict]:
    links = [
        {"href": r.url, "rel": "reference", "text": _line(r.name)}
        for r in policy.resources
        if r.url
    ]
    links += [
        {"href": t.url, "rel": "related", "text": _line(f"MITRE ATT&CK {t.technique_id}: {t.name}")}
        for t in policy.mitre
        if t.url
    ]
    return _dedupe(links, "href", "rel")


def _build_control(policy: BaselinePolicy) -> dict:
    control: dict = {
        "id": _control_id(policy.policy_id),
        "title": _line(policy.name),
        "props": _policy_props(policy),
        "parts": _policy_parts(policy),
    }
    links = _policy_links(policy)
    if links:
        control["links"] = links
    return control


def build_catalog(baselines: BaselineCatalog, products: list[str] | None = None) -> dict:
    """Return a complete OSCAL catalog document.

    :param products: restrict to these product keys (e.g. ``["aad", "exo"]``).
        ``None`` includes every product in the baseline set.
    """
    selected = [p.lower() for p in products] if products else baselines.products
    groups = []

    for product in selected:
        policies = baselines.by_product(product)
        if not policies:
            continue

        # Sub-group per SCuBA policy section, preserving first-seen order.
        # Section numbers are NOT contiguous, so they are read from the policy
        # ID rather than enumerated.
        sections: dict[str, list[BaselinePolicy]] = {}
        for policy in policies:
            sections.setdefault(policy.group_number, []).append(policy)

        subgroups = []
        for number, members in sections.items():
            first = members[0]
            subgroup: dict = {
                "id": f"ms.{product}.{number}",
                "title": _line(first.section) or f"{product.upper()} group {number}",
                "controls": [_build_control(p) for p in members],
            }
            if first.section_description:
                subgroup["parts"] = [
                    {
                        "id": f"ms.{product}.{number}_ovw",
                        "name": "overview",
                        "prose": first.section_description,
                    }
                ]
            subgroups.append(subgroup)

        groups.append(
            {
                "id": f"ms.{product}",
                "title": PRODUCT_TITLES.get(product, product.upper()),
                "groups": subgroups,
            }
        )

    return {
        "catalog": {
            "uuid": det_uuid("catalog", "scuba-m365", baselines.version, ",".join(selected)),
            "metadata": {
                "title": "CISA SCuBA Secure Configuration Baselines for Microsoft 365",
                "last-modified": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "version": baselines.version,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "source", "ns": SCUBA_NS, "value": "cisagov/ScubaGear"},
                    {"name": "baseline-version", "ns": SCUBA_NS, "value": baselines.version},
                ],
                "remarks": (
                    "Derived mechanically from CISA's machine-readable SCuBA baselines "
                    "(ScubaBaselines.json, CC0-1.0). Control text, rationale, implementation "
                    "guidance and MITRE ATT&CK mappings are CISA-authored and reproduced "
                    "unmodified. This OSCAL rendering is not a CISA product and carries no "
                    "CISA endorsement."
                ),
            },
            "groups": groups,
        }
    }


def control_count(catalog: dict) -> int:
    total = 0
    for group in catalog["catalog"]["groups"]:
        for subgroup in group.get("groups", []):
            total += len(subgroup.get("controls", []))
        total += len(group.get("controls", []))
    return total
