"""Exemptions: the part of a compliance score nobody audits.

ScubaGear lets an organisation omit policies from its report via a YAML config::

    OmitPolicy:
      MS.EXO.4.3v1:
        Rationale: "Policy only applies to federal executive branch agencies"
        Expiration: 2025-12-31

Omitted policies render grey as "Omitted" and drop out of the denominator, so
**adding lines to a YAML file raises the reported compliance rate.** CISA warns
about this directly -- "this can inadvertently introduce blind spots" -- but the
mechanism has no owner, no approver, no enforced expiry, and no machine-readable
existence outside the config.

The ``Expiration`` field is the sharpest part. It is optional, and nothing in
ScubaGear enforces it. The example in CISA's own documentation uses
``2025-12-31``, a date now in the past. An exemption whose expiry has lapsed is
still suppressing its policy.

This module compiles that config into something auditable, and reports the gap
between the compliance rate shown and the rate over all assessed policies.

OSCAL already has the vocabulary: ``risk-status`` includes
``deviation-requested`` and ``deviation-approved``. An exemption is a deviation.
An **expired** exemption is a deviation that has lapsed back to ``open``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from .models import Result, ScubaRun


@dataclass(frozen=True)
class Exemption:
    policy_id: str
    rationale: str
    expiration: date | None
    kind: str = "omission"          # omission | annotation

    def is_expired(self, today: date | None = None) -> bool:
        if self.expiration is None:
            return False
        return self.expiration < (today or date.today())

    @property
    def has_rationale(self) -> bool:
        return bool(self.rationale.strip())

    def status(self, today: date | None = None) -> str:
        """OSCAL risk-status for this exemption."""
        if self.is_expired(today):
            # The deviation lapsed; the risk is open again whatever the report says.
            return "open"
        return "deviation-approved" if self.has_rationale else "deviation-requested"


@dataclass
class ExemptionLedger:
    exemptions: list[Exemption] = field(default_factory=list)
    assessed_total: int = 0
    assessed_pass: int = 0
    reported_total: int = 0
    reported_pass: int = 0
    suppressed: list[str] = field(default_factory=list)
    suppressed_mandatory: list[str] = field(default_factory=list)
    suppressed_passing: list[str] = field(default_factory=list)
    #: Every policy the run actually assessed. Kept so a config entry naming a
    #: policy that was never assessed can be reported as exactly that, rather
    #: than as an exclusion it did not cause.
    assessed_ids: frozenset[str] = frozenset()

    @property
    def stale(self) -> list[Exemption]:
        """Config entries for policies this run never assessed.

        Neither harmless nor an exclusion: the policy is not in the report, so
        the entry suppresses nothing, but it is still an un-reviewed statement
        about a control -- usually a leftover from an older baseline version.
        """
        return [e for e in self.exemptions if e.policy_id not in self.assessed_ids]

    @property
    def expired(self) -> list[Exemption]:
        return [e for e in self.exemptions if e.is_expired()]

    @property
    def without_rationale(self) -> list[Exemption]:
        return [e for e in self.exemptions if not e.has_rationale]

    @property
    def reported_rate(self) -> float:
        """Compliance rate as the report shows it: exemptions removed from the denominator."""
        return 100 * self.reported_pass / self.reported_total if self.reported_total else 0.0

    @property
    def true_rate(self) -> float:
        """Rate over every assessed policy, using each policy's actual result.

        This is the number the exemptions are hiding, and it is the only one
        directly comparable to ``reported_rate``: same population, same
        scoring, the omissions simply put back. A policy ScubaGear genuinely
        did not evaluate carries no ``Pass``, so it lands in the denominator
        without helping the numerator -- which is the correct treatment and
        needs no special case.
        """
        return 100 * self.assessed_pass / self.assessed_total if self.assessed_total else 0.0

    @property
    def worst_case_rate(self) -> float:
        """Rate if every exempted policy were assumed non-compliant.

        A deliberately conservative bound, reported *separately* rather than
        as "the true rate". Asserting that an exempted policy fails is a claim
        about evidence we do not have, and on this data it would be wrong: see
        :attr:`suppressed_passing`.
        """
        return 100 * self.reported_pass / self.assessed_total if self.assessed_total else 0.0

    @property
    def inflation(self) -> float:
        """Percentage points the exemptions add to the headline number.

        Measured against :attr:`true_rate`, so it isolates the effect of the
        *mechanism* -- shrinking the denominator -- from the unrelated question
        of how the omitted policies would have scored.
        """
        return self.reported_rate - self.true_rate


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return datetime.strptime(str(value).strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_config(path: str | Path) -> list[Exemption]:
    """Read a ScubaGear config file's OmitPolicy / AnnotatePolicy sections."""
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return parse_config_dict(doc)


def parse_config_dict(doc: dict) -> list[Exemption]:
    out: list[Exemption] = []
    for key, kind in (("OmitPolicy", "omission"), ("AnnotatePolicy", "annotation")):
        section = doc.get(key) or {}
        if not isinstance(section, dict):
            continue
        for policy_id, body in section.items():
            body = body or {}
            out.append(
                Exemption(
                    policy_id=str(policy_id).strip(),
                    rationale=str(body.get("Rationale") or body.get("Comment") or "").strip(),
                    expiration=_parse_date(body.get("Expiration")),
                    kind=kind,
                )
            )
    return out


def build_ledger(
    run: ScubaRun,
    exemptions: list[Exemption],
    mandatory_ids: set[str] | None = None,
) -> ExemptionLedger:
    """Quantify what the exemptions hide.

    :param mandatory_ids: policies that are SHALL (mandatory under CISA
        BOD 25-01). Exempting one of these is materially different from
        exempting a recommendation, and the ledger reports them separately.
    """
    # Only omissions remove a policy from the report; annotations do not.
    omitted = {e.policy_id for e in exemptions if e.kind == "omission"}

    assessed = [p for p in run.policies if p.result is not Result.NOT_APPLICABLE]
    reported = [p for p in assessed if p.policy_id not in omitted]

    suppressed = sorted(p.policy_id for p in assessed if p.policy_id in omitted)
    mandatory = mandatory_ids or {
        p.policy_id for p in assessed if p.criticality.is_mandatory
    }

    return ExemptionLedger(
        exemptions=exemptions,
        assessed_total=len(assessed),
        assessed_pass=sum(1 for p in assessed if p.result is Result.PASS),
        reported_total=len(reported),
        reported_pass=sum(1 for p in reported if p.result is Result.PASS),
        suppressed=suppressed,
        suppressed_mandatory=sorted(p for p in suppressed if p in mandatory),
        # Omitting a *passing* policy lowers the reported rate rather than
        # raising it, so these are worth naming: they are the reason a blanket
        # "exempted means failing" assumption overstates the distortion.
        suppressed_passing=sorted(
            p.policy_id
            for p in assessed
            if p.policy_id in omitted and p.result is Result.PASS
        ),
        assessed_ids=frozenset(p.policy_id for p in assessed),
    )


def to_oscal_risks(ledger: ExemptionLedger, run_id: str, today: date | None = None) -> list[dict]:
    """Render exemptions as OSCAL risks carrying deviation status.

    This is the governance artifact the YAML config is not: each exemption
    becomes a risk with an explicit status, an owner-facing rationale, and a
    deadline, so it can be reviewed, aggregated and reported rather than living
    untracked in a file.
    """
    from .ids import det_uuid
    from .transformers.catalog import SCUBA_NS, _line

    risks = []
    for exemption in ledger.exemptions:
        expired = exemption.is_expired(today)
        assessed = exemption.policy_id in ledger.assessed_ids
        props = [
            {"name": "scuba-policy-id", "ns": SCUBA_NS, "value": exemption.policy_id},
            {"name": "exemption-kind", "ns": SCUBA_NS, "value": exemption.kind},
            {
                "name": "suppresses-mandatory",
                "ns": SCUBA_NS,
                "value": "true" if exemption.policy_id in ledger.suppressed_mandatory else "false",
            },
            # Whether this entry actually did anything to this run's figures.
            {
                "name": "policy-assessed",
                "ns": SCUBA_NS,
                "value": "true" if assessed else "false",
            },
        ]
        if exemption.expiration:
            props.append(
                {"name": "expiration", "ns": SCUBA_NS, "value": exemption.expiration.isoformat()}
            )
        if expired:
            props.append({"name": "expired", "ns": SCUBA_NS, "value": "true"})

        statement = exemption.rationale or "No rationale was recorded for this exemption."
        if expired:
            statement += (
                f" This exemption expired on {exemption.expiration.isoformat()} and is "
                "no longer authorised, but nothing in the scanner enforces that."
            )
        elif not exemption.has_rationale:
            statement += " ScubaGear warns when a rationale is omitted."
        if not assessed:
            statement += (
                " This run did not assess the policy, so the entry changed nothing here; "
                "it is most likely left over from an earlier baseline version."
            )

        # The description must say what this entry actually does. An annotation
        # attaches a comment; only an omission removes the policy from the
        # reported figure, and neither does anything if the policy was never
        # assessed. Describing all three as an exclusion would misreport two.
        if not assessed:
            description = (
                f"{exemption.policy_id} is named by the ScubaGear configuration but was "
                f"not assessed in this run."
            )
        elif exemption.kind == "omission":
            description = (
                f"{exemption.policy_id} is excluded from the reported compliance "
                f"figure by the ScubaGear configuration."
            )
        else:
            description = (
                f"{exemption.policy_id} carries an annotation in the ScubaGear "
                f"configuration. It remains in the reported compliance figure."
            )

        risks.append(
            {
                "uuid": det_uuid("exemption", run_id, exemption.policy_id),
                "title": _line(f"Exemption for {exemption.policy_id}"),
                "description": _line(description),
                "statement": _line(statement),
                "props": props,
                "status": exemption.status(today),
            }
        )
    return risks
