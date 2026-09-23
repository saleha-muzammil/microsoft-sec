"""Function tools the Foundry agents call to answer questions.

This module is the project's integrity boundary. Agents are instructed never to
state a compliance fact from their own knowledge; they must call one of these
tools, each of which reads the **validated OSCAL artifacts** and returns
structured data carrying the policy IDs and OSCAL UUIDs needed for citation.

The consequence is that "how do you know the model didn't invent this number?"
has a concrete answer: it couldn't have. The number came from a pure function
over a document that passed the NIST validator, and that function has tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field


@dataclass
class OscalStore:
    """Read-only view over a generated OSCAL document set."""

    directory: Path

    def __post_init__(self) -> None:
        self.directory = Path(self.directory)

    def _load(self, name: str) -> dict[str, Any]:
        path = self.directory / name
        if not path.exists():
            raise FileNotFoundError(
                f"{name} not found in {self.directory}. Run scripts/generate.py first."
            )
        return json.loads(path.read_text())

    @cached_property
    def catalog(self) -> dict:
        return self._load("scuba-m365-catalog.json")["catalog"]

    @cached_property
    def assessment_results(self) -> dict:
        return self._load("scuba-assessment-results.json")["assessment-results"]

    @cached_property
    def poam(self) -> dict | None:
        try:
            return self._load("scuba-poam.json")["plan-of-action-and-milestones"]
        except FileNotFoundError:
            return None

    @cached_property
    def mapping(self) -> dict | None:
        try:
            return self._load("scuba-nist-mapping.json")["mapping-collection"]
        except FileNotFoundError:
            return None

    @cached_property
    def baselines(self):
        from ..parsers.baselines import parse_baselines

        path = self.directory.parents[1] / "data/baselines/ScubaBaselines.json"
        return parse_baselines(str(path)) if path.exists() else None

    @cached_property
    def controls(self) -> dict[str, dict]:
        """control id -> control object."""
        out: dict[str, dict] = {}
        for group in self.catalog.get("groups", []):
            for sub in group.get("groups", []):
                for control in sub.get("controls", []):
                    out[control["id"]] = control
        return out

    @cached_property
    def observations(self) -> list[dict]:
        return self.assessment_results["results"][0].get("observations", [])

    @cached_property
    def findings(self) -> list[dict]:
        return self.assessment_results["results"][0].get("findings", [])


def _reconstruct_run(store: OscalStore):
    """Rebuild a ScubaRun view from the assessment-results document.

    Coverage needs per-policy results, and the OSCAL artifact is the validated
    record of them -- so we read it back rather than re-parsing the scan, which
    keeps the artifacts as the single source of truth.
    """
    from ..models import Criticality, PolicyResult, Result, ScubaRun

    policies = []
    for obs in store.observations:
        policy_id = _prop(obs, "scuba-policy-id")
        if not policy_id:
            continue
        try:
            result = Result.parse(_prop(obs, "scuba-result"))
            criticality = Criticality.parse(_prop(obs, "criticality"))
        except ValueError:
            continue
        policies.append(
            PolicyResult(
                policy_id=policy_id,
                requirement=obs.get("title", ""),
                result=result,
                criticality=criticality,
                details=obs.get("description", ""),
                product=_prop(obs, "product"),
                group_number="",
                group_name="",
            )
        )
    meta = store.assessment_results["metadata"]
    return ScubaRun(
        report_uuid=store.assessment_results["uuid"],
        tenant_id=_prop(meta, "tenant-id"),
        tenant_display_name=meta.get("title", ""),
        tenant_domain="",
        tool_version=meta.get("version", ""),
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        products_assessed=[],
        policies=policies,
    )


def _prop(obj: dict, name: str, default: str = "") -> str:
    return next((p["value"] for p in obj.get("props", []) if p["name"] == name), default)


def _part(control: dict, name: str) -> str:
    return next((p.get("prose", "") for p in control.get("parts", []) if p["name"] == name), "")


class ComplianceTools:
    """Bound tool implementations over one OSCAL document set."""

    def __init__(self, directory: str | Path, semantic: bool = True):
        self.store = OscalStore(Path(directory))
        self._coverage_cache = None
        self._run_cache = None
        self._semantic = None
        if semantic:
            from .retrieval import SemanticIndex

            index = SemanticIndex()
            self._semantic = index if index.configured else None

    def _run(self):
        if self._run_cache is None:
            self._run_cache = _reconstruct_run(self.store)
        return self._run_cache

    def _coverage(self):
        if self._coverage_cache is None:
            baselines = self.store.baselines
            if baselines is None:
                return None
            from ..coverage import build_coverage

            self._coverage_cache = build_coverage(self._run(), baselines)
        return self._coverage_cache

    # ---------------------------------------------------------------- posture

    def get_posture_summary(self) -> str:
        """Return the overall SCuBA compliance posture for the assessed tenant:
        totals by result, and a breakdown of failures by severity and product."""
        obs = self.store.observations
        by_result: dict[str, int] = {}
        by_product: dict[str, dict[str, int]] = {}
        for o in obs:
            result = _prop(o, "scuba-result")
            product = _prop(o, "product")
            by_result[result] = by_result.get(result, 0) + 1
            bucket = by_product.setdefault(product, {})
            bucket[result] = bucket.get(result, 0) + 1

        poam = self.store.poam
        severities: dict[str, int] = {}
        if poam:
            for item in poam.get("poam-items", []):
                sev = _prop(item, "severity", "unknown")
                severities[sev] = severities.get(sev, 0) + 1

        total = len(obs)
        passing = by_result.get("Pass", 0)
        assessed = total - by_result.get("N/A", 0)
        return json.dumps(
            {
                "tenant": self.store.assessment_results["metadata"]["title"],
                "total_policies_assessed": total,
                "results": by_result,
                "compliance_rate_excluding_na": (
                    f"{100 * passing / assessed:.1f}%" if assessed else "n/a"
                ),
                "open_poam_items_by_severity": severities,
                "by_product": by_product,
            },
            indent=2,
        )

    # --------------------------------------------------------------- failures

    def list_failures(
        self,
        severity: Annotated[
            str, Field(description="Filter by severity: high, moderate, low, or 'all'.")
        ] = "all",
        product: Annotated[
            str, Field(description="Filter by product, e.g. AAD, EXO, DEFENDER, or 'all'.")
        ] = "all",
        limit: Annotated[int, Field(description="Maximum number of items to return.")] = 20,
    ) -> str:
        """List SCuBA policies that failed, with severity, product and the
        remediation deadline. Use this to answer 'what is broken' questions."""
        poam = self.store.poam
        if not poam:
            return json.dumps({"failures": [], "note": "No POA&M: the tenant has no open failures."})

        risks = {r["uuid"]: r for r in poam.get("risks", [])}
        out = []
        for item in poam.get("poam-items", []):
            sev = _prop(item, "severity")
            prod = _prop(item, "product")
            if severity != "all" and sev != severity.lower():
                continue
            if product != "all" and prod.upper() != product.upper():
                continue
            risk_uuid = (item.get("related-risks") or [{}])[0].get("risk-uuid")
            risk = risks.get(risk_uuid, {})
            out.append(
                {
                    "policy_id": _prop(item, "scuba-policy-id"),
                    "severity": sev,
                    "product": prod,
                    "title": item["title"],
                    "deadline": risk.get("deadline", ""),
                    "poam_item_uuid": item["uuid"],
                }
            )
        return json.dumps({"count": len(out), "failures": out[:limit]}, indent=2)

    # ---------------------------------------------------------------- control

    def get_control_details(
        self,
        policy_id: Annotated[str, Field(description="SCuBA policy ID, e.g. MS.AAD.3.1v1.")],
    ) -> str:
        """Return the full CISA baseline detail for one SCuBA policy: the
        requirement, CISA's rationale, implementation guidance, criticality,
        MITRE ATT&CK techniques, and the assessed result."""
        cid = policy_id.lower().strip()
        control = self.store.controls.get(cid)
        if not control:
            return json.dumps({"error": f"No SCuBA policy '{policy_id}' in the catalog."})

        observation = next(
            (o for o in self.store.observations if _prop(o, "scuba-policy-id").lower() == cid), None
        )
        return json.dumps(
            {
                "policy_id": _prop(control, "label", policy_id),
                "title": control["title"],
                "criticality": _prop(control, "criticality"),
                "mandatory": _prop(control, "mandatory") == "true",
                "rationale": _part(control, "rationale"),
                "implementation_guidance": _part(control, "guidance"),
                "mitre_attack": [
                    p["value"] for p in control.get("props", [])
                    if p["name"] == "mitre-attack-technique"
                ],
                "assessed_result": _prop(observation, "scuba-result") if observation else "not assessed",
                "evidence": observation.get("description", "") if observation else "",
                "observation_uuid": observation["uuid"] if observation else None,
            },
            indent=2,
        )

    # ---------------------------------------------------------------- mapping

    def get_nist_mapping(
        self,
        policy_id: Annotated[str, Field(description="SCuBA policy ID, e.g. MS.AAD.1.1v1.")],
    ) -> str:
        """Return the NIST SP 800-53 Rev 5 controls a SCuBA policy maps to,
        including whether the mapping is CISA-authoritative or AI-proposed."""
        collection = self.store.mapping
        if not collection:
            return json.dumps({"error": "No mapping document generated."})
        target = policy_id.lower().strip()
        for entry in collection["mappings"][0]["maps"]:
            if entry["sources"][0]["id-ref"].lower() == target:
                return json.dumps(
                    {
                        "policy_id": _prop(entry, "scuba-policy-id", policy_id),
                        "nist_controls": [t["id-ref"] for t in entry["targets"]],
                        "cisa_published_ids": [
                            p["value"] for p in entry.get("props", [])
                            if p["name"] == "source-control-id"
                        ],
                        "provenance": _prop(entry, "provenance"),
                        "confidence": entry.get("confidence-score"),
                        "rationale": entry.get("remarks", ""),
                    },
                    indent=2,
                )
        # Distinguish the three reasons we might have nothing, because they
        # mean different things to an auditor. Saying "CISA has not published a
        # mapping" when the policy simply is not in our catalog would be an
        # unsupported claim about CISA.
        known = policy_id.lower().strip() in self.store.controls
        if not known:
            return json.dumps(
                {
                    "policy_id": policy_id,
                    "nist_controls": [],
                    "provenance": "unknown-policy",
                    "note": f"No SCuBA policy '{policy_id}' exists in the catalog.",
                }
            )
        return json.dumps(
            {
                "policy_id": policy_id,
                "nist_controls": [],
                "provenance": "unmapped",
                "note": (
                    "This policy was not assessed in the current run, or CISA has not "
                    "published a NIST mapping for it. No mapping is inferred."
                ),
            }
        )

    # -------------------------------------------------------- threat coverage

    def get_threat_coverage(
        self,
        status: Annotated[
            str,
            Field(description="Filter: 'uncovered', 'degraded', 'covered', or 'all'."),
        ] = "uncovered",
        limit: Annotated[int, Field(description="Maximum techniques to return.")] = 15,
    ) -> str:
        """Show which MITRE ATT&CK techniques still have a working mitigation.

        A technique is 'uncovered' when every SCuBA policy CISA maps to it is
        currently failing — nothing in the assessed baseline is stopping it.
        Use this to answer "what can still happen to us", which is different
        from "what is non-compliant". Note this is coverage arithmetic over
        CISA's published mappings, not a claim about real-world exploitability.
        """
        report = self._coverage()
        if report is None:
            return json.dumps({"error": "Coverage requires the SCuBA baselines."})
        chosen = (
            list(report.techniques.values())
            if status == "all"
            else report.of(status.lower())
        )
        return json.dumps(
            {
                "counts": report.counts(),
                "techniques": [
                    {
                        "technique": t.technique_id,
                        "name": t.name,
                        "status": t.status,
                        "surviving_mitigations": t.depth,
                        "failing_policies": list(t.failing),
                        "passing_policies": list(t.passing),
                    }
                    for t in chosen[:limit]
                ],
            },
            indent=2,
        )

    def rank_fixes_by_threat(
        self,
        limit: Annotated[int, Field(description="How many fixes to rank.")] = 8,
    ) -> str:
        """Rank failing policies by how many currently-uncovered ATT&CK techniques
        each fix would close.

        This ordering is NOT the same as compliance severity, and the difference
        matters: a failing SHOULD can be the only remaining mitigation for a
        technique, while a failing SHALL may have other controls still covering
        it. Use this alongside severity, not instead of it — SHALL policies are
        mandatory under CISA BOD 25-01 regardless of coverage.
        """
        report = self._coverage()
        if report is None:
            return json.dumps({"error": "Coverage requires the SCuBA baselines."})
        from ..transformers.poam import severity

        by_id = {p.policy_id: p for p in self._run().policies} if self._run() else {}
        rows = []
        for policy_id, techniques in report.remediation_ranking(limit):
            policy = by_id.get(policy_id)
            rows.append(
                {
                    "policy_id": policy_id,
                    "techniques_closed": len(techniques),
                    "techniques": techniques,
                    "compliance_severity": severity(policy) if policy else "unknown",
                }
            )
        return json.dumps({"ranked_by_threat_coverage": rows}, indent=2)

    # ----------------------------------------------------------------- search

    def search_controls(
        self,
        query: Annotated[
            str,
            Field(description="A topic or question, e.g. 'how do we stop password spraying?'"),
        ],
        limit: Annotated[int, Field(description="Maximum results.")] = 10,
    ) -> str:
        """Find SCuBA policies relevant to a topic or question.

        Uses semantic search over CISA's baseline text when Azure AI Search is
        configured, so it matches on meaning rather than exact wording, and
        falls back to keyword matching otherwise. Use this when the user
        describes a problem rather than naming a policy ID, then call
        get_control_details for the authoritative requirement."""
        if self._semantic is not None:
            hits = self._semantic.search(query, limit=limit)
            if hits:
                return json.dumps(
                    {
                        "retrieval": "semantic (Azure AI Search)",
                        "matches": [
                            {
                                "policy_id": h.policy_id,
                                "title": h.title,
                                "product": h.product,
                                "criticality": h.criticality,
                                "relevance": round(h.score, 4),
                            }
                            for h in hits
                        ],
                    },
                    indent=2,
                )

        terms = [t for t in query.lower().split() if len(t) > 2]
        scored = []
        for cid, control in self.store.controls.items():
            haystack = " ".join(
                [control["title"], _part(control, "rationale"), _part(control, "guidance")]
            ).lower()
            score = sum(haystack.count(t) for t in terms)
            if score:
                scored.append((score, cid, control["title"], _prop(control, "criticality")))
        scored.sort(reverse=True)
        return json.dumps(
            {
                "retrieval": "keyword",
                "matches": [
                    {"policy_id": c.upper(), "title": t, "criticality": crit}
                    for _, c, t, crit in scored[:limit]
                ],
            },
            indent=2,
        )
