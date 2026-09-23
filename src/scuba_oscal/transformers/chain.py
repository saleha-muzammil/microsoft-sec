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

from datetime import UTC, datetime

from ..ids import det_uuid
from ..models import ScubaRun
from .catalog import OSCAL_VERSION, PRODUCT_TITLES, SCUBA_NS, _line


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _meta(title: str, version: str, extra_props: list[dict] | None = None) -> dict:
    meta = {
        "title": title,
        "last-modified": _now(),
        "version": version,
        "oscal-version": OSCAL_VERSION,
    }
    if extra_props:
        meta["props"] = extra_props
    return meta


def build_profile(control_ids: list[str], catalog_href: str, version: str) -> dict:
    """A profile selecting the SCuBA controls actually assessed."""
    return {
        "profile": {
            "uuid": det_uuid("profile", catalog_href, ",".join(sorted(control_ids))),
            "metadata": _meta("SCuBA M365 Assessed Control Selection", version),
            "imports": [{"href": catalog_href, "include-controls": [{"with-ids": sorted(control_ids)}]}],
            "merge": {"as-is": True},
        }
    }


def build_component_definition(products: list[str], catalog_href: str, version: str) -> dict:
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
            "metadata": _meta("Microsoft 365 Services Component Definition", version),
            "components": components,
        }
    }


def build_ssp(run: ScubaRun, control_ids: list[str], profile_href: str) -> dict:
    """A system security plan for the assessed M365 tenant.

    Deliberately minimal but *honest*: it asserts only what ScubaGear actually
    establishes -- which controls are in scope and which service implements
    them -- rather than inventing implementation narrative prose.
    """
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
            "metadata": _meta(f"M365 Tenant SSP - {run.tenant_display_name}", run.tool_version),
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
                "security-sensitivity-level": "moderate",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": det_uuid("information-type", run.run_id),
                            "title": "Microsoft 365 collaboration and identity data",
                            "description": (
                                "Email, files, chat, and identity configuration held in the "
                                "assessed tenant."
                            ),
                            "confidentiality-impact": {"base": "fips-199-moderate"},
                            "integrity-impact": {"base": "fips-199-moderate"},
                            "availability-impact": {"base": "fips-199-moderate"},
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "fips-199-moderate",
                    "security-objective-integrity": "fips-199-moderate",
                    "security-objective-availability": "fips-199-moderate",
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


def build_assessment_plan(run: ScubaRun, control_ids: list[str], ssp_href: str) -> dict:
    """The assessment procedure ScubaGear performs."""
    return {
        "assessment-plan": {
            "uuid": det_uuid("assessment-plan", run.run_id),
            "metadata": _meta(
                f"ScubaGear Assessment Plan - {run.tenant_display_name}",
                run.tool_version,
                [{"name": "tool", "ns": SCUBA_NS, "value": "ScubaGear"}],
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
