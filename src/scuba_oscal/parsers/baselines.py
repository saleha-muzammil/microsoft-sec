"""Parse CISA's machine-readable SCuBA baselines (``ScubaBaselines.json``).

CISA ships a pre-parsed JSON rendering of all eight M365 baseline documents,
which is far more reliable to consume than scraping the baseline markdown.
Each policy carries rationale, implementation guidance, MITRE ATT&CK technique
mappings, resource links, and licence requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scubagear import load_json


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str   # e.g. "T1110.003"
    name: str           # e.g. "Password Spraying"
    url: str

    @classmethod
    def parse(cls, raw: dict[str, Any] | str) -> "MitreTechnique":
        # Usually {"Name": "T1110.003: Password Spraying", "Url": ...}, but the
        # baseline JSON is hand-maintained and a few entries are bare strings.
        if isinstance(raw, str):
            label, url = raw, ""
        else:
            label, url = raw.get("Name", ""), raw.get("Url", "")
        tech_id, _, name = label.partition(":")
        return cls(technique_id=tech_id.strip(), name=name.strip(), url=url)


@dataclass(frozen=True)
class Resource:
    name: str
    url: str

    @classmethod
    def parse(cls, raw: dict[str, Any] | str) -> "Resource":
        # Same hand-maintenance caveat as MitreTechnique: a few entries are
        # plain strings rather than {"Name", "Url"} objects.
        if isinstance(raw, str):
            return cls(name=raw, url=raw if raw.startswith("http") else "")
        return cls(name=raw.get("Name", ""), url=raw.get("Url", ""))


@dataclass(frozen=True)
class BaselinePolicy:
    """One SCuBA baseline policy as authored by CISA."""

    policy_id: str
    name: str
    product: str
    section: str
    section_description: str
    rationale: str
    criticality: str          # "SHALL" | "SHOULD"
    last_modified: str
    implementation: str
    mitre: list[MitreTechnique] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    license_requirements: list[str] = field(default_factory=list)
    badges: list[str] = field(default_factory=list)

    @property
    def group_number(self) -> str:
        # "MS.AAD.1.1v1" -> "1"
        parts = self.policy_id.split(".")
        return parts[2] if len(parts) > 2 else ""

    @property
    def is_mandatory(self) -> bool:
        return self.criticality.upper() == "SHALL"


@dataclass(frozen=True)
class BaselineCatalog:
    version: str
    policies: list[BaselinePolicy]

    def by_id(self, policy_id: str) -> BaselinePolicy | None:
        return next((p for p in self.policies if p.policy_id == policy_id), None)

    def by_product(self, product: str) -> list[BaselinePolicy]:
        return [p for p in self.policies if p.product.upper() == product.upper()]

    @property
    def products(self) -> list[str]:
        seen: list[str] = []
        for policy in self.policies:
            if policy.product not in seen:
                seen.append(policy.product)
        return seen


def parse_baselines(path: str) -> BaselineCatalog:
    doc = load_json(path)
    version = doc.get("Version", "unknown")
    policies: list[BaselinePolicy] = []

    for product, entries in doc["baselines"].items():
        for raw in entries:
            policy_id = raw.get("id", "")
            if not policy_id:
                continue
            policies.append(
                BaselinePolicy(
                    policy_id=policy_id,
                    name=raw.get("name", ""),
                    product=product,
                    section=raw.get("policySection", ""),
                    section_description=raw.get("sectionDescription", ""),
                    rationale=raw.get("rationale", ""),
                    criticality=raw.get("criticality", ""),
                    last_modified=raw.get("lastModified", ""),
                    implementation=raw.get("implementation", ""),
                    mitre=[MitreTechnique.parse(m) for m in raw.get("mitreMapping") or []],
                    resources=[Resource.parse(r) for r in raw.get("resources") or []],
                    license_requirements=[
                        x for x in (raw.get("licenseRequirements") or []) if x and x != "N/A"
                    ],
                    badges=[
                        b.get("label", "") if isinstance(b, dict) else str(b)
                        for b in raw.get("badges") or []
                    ],
                )
            )
    return BaselineCatalog(version=version, policies=policies)
