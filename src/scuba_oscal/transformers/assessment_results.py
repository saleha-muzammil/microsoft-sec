"""Transform a ScubaGear run into an OSCAL **assessment-results** document.

Mapping rationale:

* every assessed policy becomes an **observation** -- the raw evidence of what
  ScubaGear saw, with the assessment method recorded honestly (``TEST`` for
  automated checks, ``EXAMINE`` for policies ScubaGear cannot automate);
* every assessed policy becomes a **finding** whose target status is
  ``satisfied`` or ``not-satisfied``;
* every actionable failure additionally becomes a **risk**, which is what a
  POA&M can later reference.

No model is involved. Each value is a deterministic function of ScubaGear
output, which is precisely why the resulting artifact can be cited as evidence.
"""

from __future__ import annotations

from datetime import datetime

from ..ids import det_uuid, finding_uuid, observation_uuid, risk_uuid
from ..models import Result, ScubaRun
from .catalog import OSCAL_VERSION, SCUBA_NS, _line, oscal_timestamp

#: Anything not automatically testable is recorded as EXAMINE, because
#: reporting a human-assessed policy as a machine TEST would misstate evidence.
METHOD_AUTOMATED = "TEST"
METHOD_MANUAL = "EXAMINE"


def _ts(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _control_id(policy_id: str) -> str:
    return policy_id.lower()


def build_assessment_results(
    run: ScubaRun,
    ap_href: str = "scuba-assessment-plan.json",
    synthetic: bool = False,
    last_modified: datetime | None = None,
) -> dict:
    """Render ``run`` as an OSCAL assessment-results document.

    :param synthetic: when True, label the artifact as synthetic *inside the
        document*, so the disclosure travels with the data rather than living
        only in a README.
    """
    collected = _ts(run.timestamp)

    observations: list[dict] = []
    findings: list[dict] = []
    risks: list[dict] = []
    reviewed: list[dict] = []

    for policy in run.policies:
        cid = _control_id(policy.policy_id)
        reviewed.append({"control-id": cid})

        obs_uuid = observation_uuid(run.run_id, policy.policy_id)
        method = METHOD_AUTOMATED if policy.criticality.is_automated else METHOD_MANUAL
        observations.append(
            {
                "uuid": obs_uuid,
                "title": _line(f"{policy.policy_id}: {policy.requirement}"),
                "description": policy.details
                or f"ScubaGear evaluated {policy.policy_id} and reported '{policy.result.value}'.",
                "methods": [method],
                "props": [
                    {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": policy.policy_id},
                    {"name": "scuba-result", "ns": SCUBA_NS, "value": policy.result.value},
                    {"name": "criticality", "ns": SCUBA_NS, "value": policy.criticality.value},
                    {"name": "product", "ns": SCUBA_NS, "value": policy.product},
                ],
                "collected": collected,
            }
        )

        # N/A policies are not evidence of compliance or of deficiency, so they
        # are observed but produce no finding.
        if policy.result is Result.NOT_APPLICABLE:
            continue

        findings.append(
            {
                "uuid": finding_uuid(run.run_id, policy.policy_id),
                "title": _line(f"{policy.policy_id} - {policy.result.value}"),
                "description": policy.details or policy.requirement,
                "props": [
                    {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": policy.policy_id},
                    {"name": "criticality", "ns": SCUBA_NS, "value": policy.criticality.value},
                ],
                "target": {
                    "type": "objective-id",
                    "target-id": f"{cid}_smt",
                    "status": {"state": policy.result.oscal_state},
                },
                "related-observations": [{"observation-uuid": obs_uuid}],
            }
        )

        if policy.is_actionable_failure:
            risks.append(
                {
                    "uuid": risk_uuid(run.run_id, policy.policy_id),
                    "title": _line(f"Unmet SCuBA requirement {policy.policy_id}"),
                    "description": policy.requirement,
                    "statement": policy.details
                    or f"{policy.policy_id} was reported as {policy.result.value}.",
                    "props": [
                        {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": policy.policy_id},
                        {
                            "name": "mandatory",
                            "ns": SCUBA_NS,
                            "value": "true" if policy.criticality.is_mandatory else "false",
                        },
                    ],
                    "status": "open",
                    "related-observations": [{"observation-uuid": obs_uuid}],
                }
            )

    # `import-ap` is REQUIRED on assessment-results, and oscal-cli dereferences
    # hrefs transitively. Pointing at a back-matter resource keeps the document
    # self-contained: there is no assessment plan file to chase.
    ap_resource_uuid = det_uuid("resource", "assessment-plan", run.run_id)

    result_block: dict = {
        "uuid": det_uuid("result", run.run_id),
        "title": f"ScubaGear assessment of {run.tenant_display_name}",
        "description": (
            f"Automated CISA SCuBA secure configuration assessment of M365 tenant "
            f"{run.tenant_domain} performed by ScubaGear {run.tool_version}."
        ),
        "start": collected,
        "end": collected,
        "reviewed-controls": {
            "control-selections": [
                {
                    "description": "SCuBA policies evaluated during this run.",
                    "include-controls": reviewed,
                }
            ]
        },
        "observations": observations,
    }
    # OSCAL arrays carry minItems:1 -- omit rather than emit an empty list.
    if findings:
        result_block["findings"] = findings
    if risks:
        result_block["risks"] = risks

    metadata_props = [
        {"name": "tool", "ns": SCUBA_NS, "value": "ScubaGear"},
        {"name": "tool-version", "ns": SCUBA_NS, "value": run.tool_version},
        {"name": "tenant-id", "ns": SCUBA_NS, "value": run.tenant_id},
    ]
    if synthetic:
        metadata_props.append({"name": "data-classification", "ns": SCUBA_NS, "value": "SYNTHETIC"})

    return {
        "assessment-results": {
            "uuid": det_uuid("assessment-results", run.run_id),
            "metadata": {
                "title": f"SCuBA Assessment Results - {run.tenant_display_name}",
                "last-modified": oscal_timestamp(last_modified),
                "version": run.tool_version,
                "oscal-version": OSCAL_VERSION,
                "props": metadata_props,
                "remarks": (
                    "SYNTHETIC DATA - not a real tenant assessment. "
                    if synthetic
                    else ""
                )
                + (
                    "Generated from ScubaGear output. Observation methods reflect how each "
                    "policy was actually assessed: TEST for automated checks, EXAMINE for "
                    "policies ScubaGear cannot evaluate automatically."
                ),
            },
            "import-ap": {"href": f"#{ap_resource_uuid}"},
            "results": [result_block],
            "back-matter": {
                "resources": [
                    {
                        "uuid": ap_resource_uuid,
                        "title": "ScubaGear automated assessment procedure",
                        "description": (
                            "ScubaGear evaluates SCuBA policies via Microsoft Graph and "
                            "service-specific APIs, applying Rego policy rules to the "
                            "exported configuration. This resource names that procedure "
                            "and resolves to the companion OSCAL assessment-plan document "
                            "generated alongside this one. See "
                            "https://github.com/cisagov/ScubaGear."
                        ),
                        # The rlink MUST resolve to a real assessment-plan
                        # document: oscal-cli follows import-ap through this
                        # resource and parses whatever it finds. A resource
                        # without an rlink is rejected outright.
                        "rlinks": [{"href": ap_href}],
                    },
                ]
            },
        }
    }
