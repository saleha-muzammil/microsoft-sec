"""Build the OSCAL document chain that assessment-results depends on.

OSCAL is a linked model, and the linkage is enforced, not decorative. The NIST
validator dereferences ``import-*`` hrefs transitively::

    assessment-results --import-ap--> assessment-plan
                                        --import-ssp--> system-security-plan
                                                          --import-profile--> profile
                                                                                --import--> catalog

A dangling reference anywhere in that chain fails the whole document. CISA's
abandoned ``oscal-exploration`` branch hit exactly this wall, and its README
concedes "you can't have an assessment plan model without implementing all the
preceeding layers", leaving component-definition, SSP and POA&M as TODO.

This module implements those layers, so the chain resolves end to end.
"""

from __future__ import annotations

from datetime import datetime

from ..ids import det_uuid
from ..models import ScubaRun
from .catalog import OSCAL_VERSION, PRODUCT_TITLES, SCUBA_NS, _line, oscal_timestamp


def _meta(
    title: str,
    version: str,
    extra_props: list[dict] | None = None,
    last_modified: datetime | None = None,
) -> dict:
    meta = {
        "title": title,
        "last-modified": oscal_timestamp(last_modified),
        "version": version,
        "oscal-version": OSCAL_VERSION,
    }
    if extra_props:
        meta["props"] = extra_props
    return meta


def build_profile(
    control_ids: list[str],
    catalog_href: str,
    version: str,
    last_modified: datetime | None = None,
) -> dict:
    """A profile selecting the SCuBA controls actually assessed."""
    return {
        "profile": {
            "uuid": det_uuid("profile", catalog_href, ",".join(sorted(control_ids))),
            "metadata": _meta("SCuBA M365 Assessed Control Selection", version, last_modified=last_modified),
            "imports": [{"href": catalog_href, "include-controls": [{"with-ids": sorted(control_ids)}]}],
            "merge": {"as-is": True},
        }
    }


def build_component_definition(
    products: list[str],
    catalog_href: str,
    version: str,
    last_modified: datetime | None = None,
) -> dict:
    """Component definition describing the M365 services under assessment."""
    components = []
    for product in sorted(products):
        components.append(
            {
                "uuid": det_uuid("component", product),
                "type": "service",
                "title": PRODUCT_TITLES.get(product.lower(), product.upper()),
                "description": f"Microsoft 365 service assessed by ScubaGear: {product}.",
                "props": [{"name": "product", "ns": SCUBA_NS, "value": product}],
            }
        )
    return {
        "component-definition": {
            "uuid": det_uuid("component-definition", ",".join(sorted(products))),
            "metadata": _meta(
                "Microsoft 365 Services Component Definition", version, last_modified=last_modified
            ),
            "components": components,
        }
    }


#: FIPS 199 categorisation is **required** by the OSCAL SSP model, and
#: ScubaGear does not determine it -- it grades configuration, it does not
#: categorise a system. So a value has to be supplied, and the only honest
#: thing to do is say where it came from.
#:
#: `moderate` is the placeholder because it is the most common categorisation
#: for a general-purpose M365 tenant, not because this tenant was assessed as
#: moderate. It is marked in the artifact with `categorisation-source =
#: default-not-assessed` so a reader -- or an ATO package pulling this in,
#: where the categorisation selects the control baseline -- cannot mistake it
#: for a finding. Pass `sensitivity` to state the real one.
DEFAULT_SENSITIVITY = "moderate"

FIPS_199 = {"low": "fips-199-low", "moderate": "fips-199-moderate", "high": "fips-199-high"}


def build_ssp(
    run: ScubaRun,
    control_ids: list[str],
    profile_href: str,
    last_modified: datetime | None = None,
    sensitivity: str | None = None,
) -> dict:
    """A system security plan for the assessed M365 tenant.

    Deliberately minimal but *honest*: it asserts only what ScubaGear actually
    establishes -- which controls are in scope and which service implements
    them -- rather than inventing implementation narrative prose.

    :param sensitivity: FIPS 199 categorisation (``low``/``moderate``/``high``).
        ``None`` emits :data:`DEFAULT_SENSITIVITY`, explicitly flagged in the
        document as a default rather than an assessed value. See the note on
        that constant: this is the one required field ScubaGear cannot supply.
    """
    assessed_sensitivity = (sensitivity or "").strip().lower()
    if assessed_sensitivity and assessed_sensitivity not in FIPS_199:
        raise ValueError(
            f"sensitivity must be one of {sorted(FIPS_199)}, got {sensitivity!r}"
        )
    level = assessed_sensitivity or DEFAULT_SENSITIVITY
    impact = FIPS_199[level]
    was_assessed = bool(assessed_sensitivity)
    component_uuid = det_uuid("component", "m365-tenant", run.run_id)

    implemented = [
        {
            "uuid": det_uuid("implemented-requirement", run.run_id, cid),
            "control-id": cid,
            "by-components": [
                {
                    "component-uuid": component_uuid,
                    "uuid": det_uuid("by-component", run.run_id, cid),
                    "description": (
                        "Implemented by Microsoft 365 tenant configuration; "
                        "assessed automatically by ScubaGear."
                    ),
                }
            ],
        }
        for cid in sorted(control_ids)
    ]

    return {
        "system-security-plan": {
            "uuid": det_uuid("ssp", run.run_id),
            "metadata": _meta(
                f"M365 Tenant SSP - {run.tenant_display_name}",
                run.tool_version,
                last_modified=last_modified,
            ),
            "import-profile": {"href": profile_href},
            "system-characteristics": {
                # The field is `id`, not `identifier`. M365 tenant IDs are
                # RFC4122 UUIDs, so the identification system is declared
                # explicitly rather than left ambiguous.
                "system-ids": [
                    {
                        "identifier-type": "https://ietf.org/rfc/rfc4122",
                        "id": run.tenant_id or "unknown-tenant",
                    }
                ],
                "system-name": _line(f"Microsoft 365 Tenant {run.tenant_display_name}"),
                "description": (
                    f"Microsoft 365 tenant {run.tenant_domain}, assessed against the CISA "
                    f"SCuBA secure configuration baselines."
                ),
                "props": [
                    {
                        "name": "categorisation-source",
                        "ns": SCUBA_NS,
                        "value": "assessed" if was_assessed else "default-not-assessed",
                        "remarks": (
                            "FIPS 199 categorisation supplied by the operator."
                            if was_assessed
                            else (
                                "FIPS 199 categorisation is required by the OSCAL SSP model "
                                "but is NOT determined by ScubaGear, which grades "
                                f"configuration rather than categorising a system. '{level}' "
                                "is a default placeholder, not an assessment of this tenant. "
                                "Replace it with the system's actual categorisation before "
                                "using this SSP in an authorisation package, where the "
                                "categorisation selects the control baseline."
                            )
                        ),
                    }
                ],
                "security-sensitivity-level": level,
                "system-information": {
                    "information-types": [
                        {
                            "uuid": det_uuid("information-type", run.run_id),
                            "title": "Microsoft 365 collaboration and identity data",
                            "description": (
                                "Email, files, chat, and identity configuration held in the "
                                "assessed tenant."
                            ),
                            "confidentiality-impact": {"base": impact},
                            "integrity-impact": {"base": impact},
                            "availability-impact": {"base": impact},
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": impact,
                    "security-objective-integrity": impact,
                    "security-objective-availability": impact,
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": (
                        "The Microsoft 365 tenant and the cloud services enabled within it "
                        "that fall in scope of the SCuBA baselines."
                    )
                },
            },
            "system-implementation": {
                "components": [
                    {
                        "uuid": component_uuid,
                        "type": "service",
                        "title": "Microsoft 365 Tenant",
                        "description": f"Assessed tenant {run.tenant_domain}.",
                        "status": {"state": "operational"},
                    }
                ]
            },
            "control-implementation": {
                "description": (
                    "SCuBA baseline controls in scope for this tenant. Implementation status "
                    "is established by ScubaGear assessment rather than asserted narratively."
                ),
                "implemented-requirements": implemented,
            },
        }
    }


def build_assessment_plan(
    run: ScubaRun,
    control_ids: list[str],
    ssp_href: str,
    last_modified: datetime | None = None,
) -> dict:
    """The assessment procedure ScubaGear performs."""
    return {
        "assessment-plan": {
            "uuid": det_uuid("assessment-plan", run.run_id),
            "metadata": _meta(
                f"ScubaGear Assessment Plan - {run.tenant_display_name}",
                run.tool_version,
                [{"name": "tool", "ns": SCUBA_NS, "value": "ScubaGear"}],
                last_modified=last_modified,
            ),
            "import-ssp": {"href": ssp_href},
            "reviewed-controls": {
                "control-selections": [
                    {
                        "description": "SCuBA baseline policies evaluated by ScubaGear.",
                        "include-controls": [{"control-id": cid} for cid in sorted(control_ids)],
                    }
                ]
            },
        }
    }
