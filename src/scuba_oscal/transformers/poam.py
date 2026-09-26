"""Generate an OSCAL **Plan of Action and Milestones** from failed SCuBA policies.

POA&M is the artifact an auditor or authorising official actually works from:
what is broken, how bad it is, what will be done, and by when. It was listed as
TODO in CISA's abandoned OSCAL exploration and does not exist in any published
SCuBA tooling.

Severity and deadlines here are **deterministic**, derived from the policy's own
SHALL/SHOULD criticality and ScubaGear's result. No model is consulted. The AI
layer later *explains and re-prioritises* these items, but it never invents one.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from ..exemptions import Exemption, build_ledger, to_oscal_risks
from ..ids import det_uuid, observation_uuid, poam_item_uuid, risk_uuid
from ..models import PolicyResult, Result, ScubaRun
from .catalog import OSCAL_VERSION, SCUBA_NS, _line, oscal_timestamp

#: Remediation windows follow the convention used in federal POA&M practice
#: (FedRAMP: high 30 days, moderate 90, low 180). Chosen because it is an
#: external, citable standard rather than a number we invented.
DEADLINE_DAYS = {"high": 30, "moderate": 90, "low": 180}


def severity(policy: PolicyResult) -> str:
    """Deterministic severity from criticality x result.

    A SHALL is mandatory under CISA BOD 25-01; a failed SHALL is therefore the
    most serious outcome. A Warning indicates partial conformance, so it is one
    step below an outright Fail at the same criticality.
    """
    mandatory = policy.criticality.is_mandatory
    if policy.result is Result.FAIL:
        return "high" if mandatory else "moderate"
    if policy.result is Result.WARNING:
        return "moderate" if mandatory else "low"
    return "low"


def _deadline(assessed: datetime, sev: str) -> str:
    due: date = (assessed + timedelta(days=DEADLINE_DAYS[sev])).date()
    return datetime(due.year, due.month, due.day, tzinfo=UTC).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def build_poam(
    run: ScubaRun,
    ssp_href: str | None = "scuba-m365-ssp.json",
    remediation_guidance: dict[str, str] | None = None,
    synthetic: bool = False,
    last_modified: datetime | None = None,
    exemptions: list[Exemption] | None = None,
) -> dict | None:
    """Build a POA&M from a run's actionable failures.

    :param remediation_guidance: optional ``policy_id -> prose`` overrides. This
        is the single seam where AI-generated remediation text may enter, and
        it is clearly labelled in the output when it does.
    :param exemptions: policies omitted from the report by ScubaGear
        configuration. Each becomes an OSCAL **risk** carrying a deviation
        status, which is the whole point: an exemption that exists only in a
        YAML file cannot be reviewed, aggregated or audited, and OSCAL already
        has the vocabulary for one (``deviation-requested`` /
        ``deviation-approved``, and plain ``open`` once it has expired).

        They are emitted as risks and **not** as poam-items on purpose. A
        poam-item is a commitment to remediate by a date; a deviation is the
        opposite -- a decision not to. Filing one as the other would overstate
        what the organisation has actually undertaken to do.
    :returns: the POA&M document, or ``None`` when there is nothing to plan.
    """
    failures = run.failures()
    if not failures:
        # OSCAL requires at least one poam-item; a fully-compliant tenant
        # correctly has no POA&M at all rather than an empty one.
        return None

    guidance = remediation_guidance or {}
    collected = run.timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    observations: list[dict] = []
    risks: list[dict] = []
    items: list[dict] = []

    # Order by severity so the document reads as a work queue, not a data dump.
    order = {"high": 0, "moderate": 1, "low": 2}
    for policy in sorted(failures, key=lambda p: (order[severity(p)], p.policy_id)):
        sev = severity(policy)
        obs_uuid = observation_uuid(run.run_id, policy.policy_id)
        rsk_uuid = risk_uuid(run.run_id, policy.policy_id)

        observations.append(
            {
                "uuid": obs_uuid,
                "title": _line(f"{policy.policy_id}: {policy.requirement}"),
                "description": policy.details
                or f"ScubaGear reported '{policy.result.value}' for {policy.policy_id}.",
                "methods": ["TEST"],
                "collected": collected,
            }
        )

        ai_text = guidance.get(policy.policy_id)
        remediation_description = ai_text or (
            f"Reconfigure the tenant so that {policy.policy_id} is satisfied: "
            f"{policy.requirement} Refer to the CISA SCuBA implementation guidance "
            f"for this policy in the companion OSCAL catalog."
        )
        remediation_props = [{"name": "severity", "ns": SCUBA_NS, "value": sev}]
        if ai_text:
            # Provenance is explicit: a reader can always tell which prose was
            # machine-generated and which is CISA-derived.
            remediation_props.append(
                {"name": "generated-by", "ns": SCUBA_NS, "value": "ai-assistant"}
            )

        risks.append(
            {
                "uuid": rsk_uuid,
                "title": _line(f"Unmet SCuBA requirement {policy.policy_id}"),
                "description": policy.requirement,
                "statement": policy.details
                or f"{policy.policy_id} was assessed as {policy.result.value}.",
                "props": [
                    {"name": "severity", "ns": SCUBA_NS, "value": sev},
                    {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": policy.policy_id},
                    {
                        "name": "criticality",
                        "ns": SCUBA_NS,
                        "value": policy.criticality.value,
                    },
                ],
                "status": "open",
                "deadline": _deadline(run.timestamp, sev),
                "related-observations": [{"observation-uuid": obs_uuid}],
                "remediations": [
                    {
                        "uuid": det_uuid("remediation", run.run_id, policy.policy_id),
                        "lifecycle": "recommendation",
                        "title": _line(f"Remediate {policy.policy_id}"),
                        "description": remediation_description,
                        "props": remediation_props,
                    }
                ],
            }
        )

        items.append(
            {
                "uuid": poam_item_uuid(run.run_id, policy.policy_id),
                "title": _line(f"{policy.policy_id} ({sev.upper()}): {policy.requirement}"),
                "description": policy.details or policy.requirement,
                "props": [
                    {"name": "severity", "ns": SCUBA_NS, "value": sev},
                    {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": policy.policy_id},
                    {"name": "product", "ns": SCUBA_NS, "value": policy.product},
                ],
                "related-observations": [{"observation-uuid": obs_uuid}],
                "related-risks": [{"risk-uuid": rsk_uuid}],
            }
        )

    # Exemptions become risks carrying a deviation status, so what the config
    # silently removes from the compliance figure is at least on the record.
    exemption_remark = ""
    if exemptions:
        ledger = build_ledger(run, exemptions)
        exemption_risks = to_oscal_risks(ledger, run.run_id)
        risks.extend(exemption_risks)
        expired = len(ledger.expired)
        exemption_remark = (
            f" {len(exemption_risks)} risk(s) record policies excluded from the reported "
            f"compliance figure by the ScubaGear configuration; {expired} of those "
            "exemption(s) have expired and are carried as 'open' rather than as an "
            "approved deviation, because nothing in the scanner enforces the expiry date."
        )

    props = [
        {"name": "tool", "ns": SCUBA_NS, "value": "ScubaGear"},
        {"name": "open-items", "ns": SCUBA_NS, "value": str(len(items))},
    ]
    if exemptions:
        # Surfaced as props so a consumer can filter without walking every risk.
        props += [
            {"name": "exemptions", "ns": SCUBA_NS, "value": str(len(exemptions))},
            {"name": "expired-exemptions", "ns": SCUBA_NS, "value": str(len(ledger.expired))},
            {
                "name": "exemptions-suppressing-mandatory",
                "ns": SCUBA_NS,
                "value": str(len(ledger.suppressed_mandatory)),
            },
        ]
    if synthetic:
        props.append({"name": "data-classification", "ns": SCUBA_NS, "value": "SYNTHETIC"})

    doc: dict = {
        "plan-of-action-and-milestones": {
            "uuid": det_uuid("poam", run.run_id),
            "metadata": {
                "title": f"SCuBA Plan of Action and Milestones - {run.tenant_display_name}",
                "last-modified": oscal_timestamp(last_modified),
                "version": run.tool_version,
                "oscal-version": OSCAL_VERSION,
                "props": props,
                "remarks": (
                    ("SYNTHETIC DATA - not a real tenant assessment. " if synthetic else "")
                    + "Severity is derived deterministically from SCuBA criticality "
                    "(SHALL/SHOULD) and the ScubaGear result. Remediation deadlines follow "
                    "federal POA&M convention: high 30 days, moderate 90, low 180."
                    + exemption_remark
                ),
            },
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": run.tenant_id or "unknown-tenant",
            },
            "observations": observations,
            "risks": risks,
            "poam-items": items,
        }
    }
    if ssp_href:
        doc["plan-of-action-and-milestones"]["import-ssp"] = {"href": ssp_href}
    return doc


def summarise(poam: dict) -> dict[str, int]:
    """Count POA&M items by severity."""
    counts: dict[str, int] = {}
    for item in poam["plan-of-action-and-milestones"]["poam-items"]:
        sev = next(
            (p["value"] for p in item.get("props", []) if p["name"] == "severity"), "unknown"
        )
        counts[sev] = counts.get(sev, 0) + 1
    return counts
