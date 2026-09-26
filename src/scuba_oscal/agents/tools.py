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

#: Repository root, resolved from *this module* rather than from the OSCAL
#: output directory.
#:
#: The reference data below (CISA's baselines, the crosswalk, VITA's SEC530
#: workbook) ships with the code, while generated artifacts do not: an uploaded
#: scan is written to a temporary directory. Deriving the data root from the
#: output path therefore worked for the bundled sample and silently disabled
#: threat coverage and the Virginia join for every upload -- the tools returned
#: "not available" and the agent lost capabilities without anything erroring.
DATA_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class OscalStore:
    """Read-only view over a generated OSCAL document set."""

    directory: Path
    data_root: Path = DATA_ROOT

    def __post_init__(self) -> None:
        self.directory = Path(self.directory)
        self.data_root = Path(self.data_root)

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

        path = self.data_root / "data/baselines/ScubaBaselines.json"
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

    def __init__(
        self,
        directory: str | Path,
        semantic: bool = True,
        data_root: str | Path | None = None,
        config_path: str | Path | None = None,
    ):
        """
        :param data_root: where the shipped reference data lives. Defaults to
            the repository root, which is correct whether the artifacts came
            from ``scripts/generate.py`` or from an uploaded scan in a temp
            directory.
        :param config_path: optional ScubaGear YAML config, so
            :meth:`get_exemptions` can report what it removes from the
            compliance figure. Without one that tool correctly reports that no
            configuration was supplied.
        """
        self.store = OscalStore(Path(directory), Path(data_root) if data_root else DATA_ROOT)
        self.config_path = Path(config_path) if config_path else None
        self._coverage_cache = None
        self._run_cache = None
        self._ledger_cache = None
        self._semantic = None
        if semantic:
            from .retrieval import SemanticIndex

            index = SemanticIndex()
            self._semantic = index if index.configured else None

    def _run(self):
        if self._run_cache is None:
            self._run_cache = _reconstruct_run(self.store)
        return self._run_cache

    def _exemption_ledger(self):
        """Compile the supplied ScubaGear config against the assessed policies."""
        if self.config_path is None or not self.config_path.exists():
            return None
        if self._ledger_cache is None:
            from ..exemptions import build_ledger, parse_config

            self._ledger_cache = build_ledger(self._run(), parse_config(self.config_path))
        return self._ledger_cache

    def _coverage(self):
        if self._coverage_cache is None:
            baselines = self.store.baselines
            if baselines is None:
                return None
            from ..coverage import build_coverage

            self._coverage_cache = build_coverage(self._run(), baselines)
        return self._coverage_cache

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
        currently failing, nothing in the assessed baseline is stopping it.
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
        it. Use this alongside severity, not instead of it, SHALL policies are
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

    def get_exemptions(self) -> str:
        """Report policies excluded from the compliance figure by configuration.

        ScubaGear lets an organisation omit policies via its config file, which
        removes them from the denominator, so the reported compliance rate can
        be raised by editing YAML. Use this to answer "is this number real?" and
        to surface exemptions that have expired but are still suppressing their
        policy. Returns nothing if no configuration was supplied.
        """
        ledger = self._exemption_ledger()
        if ledger is None or not ledger.exemptions:
            return json.dumps(
                {"exemptions": [], "note": "No ScubaGear configuration was supplied."}
            )
        return json.dumps(
            {
                "reported_compliance_rate": f"{ledger.reported_rate:.1f}%",
                "true_rate_all_assessed": f"{ledger.true_rate:.1f}%",
                "inflation_percentage_points": round(ledger.inflation, 1),
                "inflation_note": (
                    "The true rate scores every assessed policy on its actual result, "
                    "with the omissions put back -- the only figure directly comparable "
                    "to the reported rate."
                ),
                "worst_case_rate_if_all_exemptions_hid_failures": (
                    f"{ledger.worst_case_rate:.1f}%"
                ),
                "worst_case_note": (
                    "A conservative bound, NOT the true rate. Do not present it as what "
                    "the tenant's compliance actually is."
                ),
                "policies_suppressed": ledger.suppressed,
                "suppressed_that_are_mandatory": ledger.suppressed_mandatory,
                "suppressed_that_were_actually_passing": ledger.suppressed_passing,
                "expired_but_still_suppressing": [
                    {
                        "policy_id": e.policy_id,
                        "expired_on": e.expiration.isoformat() if e.expiration else None,
                        "rationale": e.rationale,
                    }
                    for e in ledger.expired
                ],
                "missing_rationale": [e.policy_id for e in ledger.without_rationale],
                "named_but_not_assessed": [e.policy_id for e in ledger.stale],
                "named_but_not_assessed_note": (
                    "Config entries for policies this run did not assess. They suppress "
                    "nothing here, but they are un-reviewed statements about a control -- "
                    "usually left over from an earlier baseline version."
                ),
                "recorded_in_oscal": (
                    "Each exemption is emitted into the POA&M as a risk carrying an OSCAL "
                    "risk-status: deviation-approved, deviation-requested, or open once it "
                    "has expired."
                ),
            },
            indent=2,
        )

    def get_virginia_obligations(
        self,
        policy_id: Annotated[
            str, Field(description="A SCuBA policy ID, or 'failures' for all failing policies.")
        ] = "failures",
    ) -> str:
        """Say what a SCuBA finding means under Virginia's SEC530 standard.

        SEC530 is VITA's Information Security Standard, mandatory for Virginia
        public bodies including every public college, university and school
        division. It adopts NIST 800-53 Rev 5 and uses its control IDs, so a
        SCuBA finding can be composed through CISA's crosswalk to a Virginia
        obligation, including who the Commonwealth says owns it.

        Some controls are WITHDRAWN in Virginia ("not applicable to COV"). A
        finding mapping only to withdrawn controls is a federal obligation with
        no Virginia equivalent, say so rather than implying a state duty.
        """
        from ..virginia import map_to_virginia, parse_sec530

        workbook = self.store.data_root / "data/virginia/SEC530_Control_Summaries.xlsx"
        crosswalk = self.store.data_root / "data/mappings"
        if not workbook.exists():
            return json.dumps({"error": "SEC530 control summaries not available."})

        from ..parsers.mappings import MappingIndex

        index = MappingIndex(
            crosswalk / "scuba-to-nist-sp-800-53-r5-fedramp-high.csv",
            crosswalk / "scuba-baseline-policy-migrations.csv",
        )
        sec530 = parse_sec530(workbook)

        if policy_id.lower() == "failures":
            run = self._run()
            ids = [p.policy_id for p in run.failures()] if run else []
        else:
            ids = [policy_id.strip().upper()]

        rows = []
        for obligation in map_to_virginia(ids, index, sec530):
            rows.append(
                {
                    "policy_id": obligation.policy_id,
                    "is_virginia_obligation": obligation.is_state_obligation,
                    "sec530_controls": [c.published_id for c in obligation.in_scope],
                    "owned_by": list(obligation.owners),
                    "withdrawn_in_virginia": [
                        {"control": c.published_id, "reason": c.withdrawal_note}
                        for c in obligation.withdrawn
                    ],
                }
            )
        return json.dumps(
            {"standard": "Virginia ITRM SEC530", "obligations": rows}, indent=2
        )

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
