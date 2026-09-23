"""Typed domain models sitting between ScubaGear output and OSCAL.

Deliberately a separate layer rather than passing raw dicts around: it is where
ScubaGear's quirks are normalised exactly once, so every downstream transformer
sees clean, predictable data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Result(str, Enum):
    """ScubaGear per-policy outcome.

    Values are the literal strings ScubaGear emits. Note ``OMITTED`` is
    "Omitted", not "Omit" as some CISA documentation states -- the JSON is the
    source of truth here.
    """

    PASS = "Pass"
    FAIL = "Fail"
    WARNING = "Warning"
    NOT_APPLICABLE = "N/A"
    OMITTED = "Omitted"
    INCORRECT = "Incorrect Result"
    ERROR = "Error"
    ERROR_MISSING = "Error - Test results missing"

    @classmethod
    def parse(cls, raw: str) -> "Result":
        value = (raw or "").strip()
        for member in cls:
            if member.value.lower() == value.lower():
                return member
        if value.lower().startswith("error"):
            return cls.ERROR
        raise ValueError(f"unrecognised ScubaGear Result: {raw!r}")

    @property
    def is_failure(self) -> bool:
        """Whether this outcome represents a control that is not satisfied."""
        return self in (self.FAIL, self.WARNING)

    @property
    def oscal_state(self) -> str:
        """Map to the OSCAL finding objective status state."""
        return "satisfied" if self is Result.PASS else "not-satisfied"


class Criticality(str, Enum):
    """SHALL vs SHOULD, plus ScubaGear's implementation-status suffixes.

    CISA documentation writes the suffix lowercase ("-implemented") while the
    Rego emits it capitalised ("-Implemented"), so parsing is case-insensitive.
    """

    SHALL = "Shall"
    SHOULD = "Should"
    SHALL_3P = "Shall/3rd Party"
    SHOULD_3P = "Should/3rd Party"
    SHALL_NOT_IMPL = "Shall/Not-Implemented"
    SHOULD_NOT_IMPL = "Should/Not-Implemented"

    @classmethod
    def parse(cls, raw: str) -> "Criticality":
        value = (raw or "").strip().lower()
        for member in cls:
            if member.value.lower() == value:
                return member
        raise ValueError(f"unrecognised ScubaGear Criticality: {raw!r}")

    @property
    def is_mandatory(self) -> bool:
        """SHALL policies are mandatory; SHOULD policies are recommended."""
        return self.value.lower().startswith("shall")

    @property
    def is_automated(self) -> bool:
        """False when ScubaGear cannot test this policy automatically.

        Both the ``/Not-Implemented`` and ``/3rd Party`` variants require a
        human to assess. This distinction matters for OSCAL: an untested
        control must not be reported as a machine-observed TEST result.
        """
        return "not-implemented" not in self.value.lower() and "3rd party" not in self.value.lower()


@dataclass(frozen=True)
class PolicyResult:
    """One SCuBA policy evaluated against one tenant."""

    policy_id: str
    requirement: str
    result: Result
    criticality: Criticality
    details: str
    product: str
    group_number: str
    group_name: str

    @property
    def is_actionable_failure(self) -> bool:
        """A failure that should become a POA&M item.

        Excludes policies ScubaGear could not automatically assess, since we
        have no evidence they are actually deficient.
        """
        return self.result.is_failure and self.criticality.is_automated


@dataclass(frozen=True)
class ScubaRun:
    """A complete ScubaGear assessment run."""

    report_uuid: str
    tenant_id: str
    tenant_display_name: str
    tenant_domain: str
    tool_version: str
    timestamp: datetime
    products_assessed: list[str]
    policies: list[PolicyResult] = field(default_factory=list)

    @property
    def run_id(self) -> str:
        """Stable identity for this run, used to derive deterministic UUIDs."""
        return self.report_uuid

    def by_id(self, policy_id: str) -> PolicyResult | None:
        return next((p for p in self.policies if p.policy_id == policy_id), None)

    def failures(self) -> list[PolicyResult]:
        return [p for p in self.policies if p.is_actionable_failure]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for policy in self.policies:
            out[policy.result.value] = out.get(policy.result.value, 0) + 1
        return out
