"""Multi-agent compliance assistant on Microsoft Foundry.

Four specialists, each with a narrow remit and only the tools it needs:

* **Posture** - what is our compliance state, and what does a given policy say.
* **Risk**    - which failures matter most, and why, in what order.
* **Remediation** - concretely how to fix a specific policy.
* **Report**  - audience-appropriate written summaries.

Every agent shares one non-negotiable rule: compliance facts come from tool
calls over validated OSCAL, never from model recall. The grounding rule is
stated once and appended to each agent's instructions so it cannot drift
between specialists.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agent_framework import Agent
from agent_framework.foundry import FoundryChatClient
from azure.identity.aio import AzureCliCredential

from .tools import ComplianceTools

GROUNDING_RULE = """
NON-NEGOTIABLE GROUNDING RULES:
1. Never state a compliance fact - a count, a result, a control requirement, a
   NIST mapping, a deadline - unless you obtained it from a tool call in this
   conversation. You have no reliable memory of this tenant.
2. Cite the SCuBA policy ID (e.g. MS.AAD.3.1v1) for every specific claim.
3. If a tool returns no data, say so plainly. Never fill the gap by guessing.
4. When reporting a NIST 800-53 mapping, always state its provenance. A
   CISA-authoritative mapping and an AI-proposed one are not interchangeable,
   and the distinction matters to an auditor.
5. Distinguish SHALL (mandatory under CISA BOD 25-01) from SHOULD
   (recommended). Never imply a SHOULD is mandatory.
6. Vagueness is NOT a safe alternative to grounding. Rule 1 tells you where
   facts come from; it does not license you to omit them. Writing "a
   substantial number of policies failed" when a tool call would give you the
   exact count is a worse answer, not a more cautious one. Always call the
   tools, then state the specific figures they return.
"""

AUDIENCE_STYLES = {
    "executive": (
        "Your reader is a non-technical executive. Lead with business risk and "
        "cost of inaction. Short paragraphs, no jargon, no PowerShell."
    ),
    "auditor": (
        "Your reader is a compliance auditor. Be precise and traceable. Cite "
        "policy IDs, control IDs and OSCAL UUIDs. State evidence and its limits."
    ),
    "engineer": (
        "Your reader is a systems engineer. Be concrete and actionable: exact "
        "portal paths, PowerShell or Graph calls, and the order of operations."
    ),
}


@dataclass
class FoundryConfig:
    """How to reach Microsoft Foundry, and how to authenticate to it.

    Two auth modes, in priority order:

    * **Azure AD (default, preferred).** ``AzureCliCredential`` uses whoever ran
      ``az login``. Nothing secret is stored anywhere, which is why this repo
      contains no keys.
    * **API key (opt-in).** Set ``FOUNDRY_API_KEY`` and the Azure OpenAI
      endpoint is used with key auth instead. This exists so a collaborator who
      is not in the resource owner's Azure directory can still run the agents
      without being invited as a guest and granted RBAC.

    The key is read from the environment and never committed: ``.env`` is
    gitignored and ``.env.example`` ships only placeholders.
    """

    endpoint: str
    model: str
    api_key: str | None = None
    azure_openai_endpoint: str | None = None
    # Azure OpenAI's v1 surface. Established by probing: every dated version
    # we tried (2024-08 through 2025-04 preview) returned
    # "API version not supported" against this resource. Override with
    # FOUNDRY_API_VERSION if a future resource needs a dated one.
    api_version: str = "preview"

    @property
    def uses_key_auth(self) -> bool:
        return bool(self.api_key and self.azure_openai_endpoint)

    @property
    def auth_mode(self) -> str:
        return "api-key" if self.uses_key_auth else "azure-ad (keyless)"

    @classmethod
    def from_env(cls, env_path: str | Path | None = None) -> FoundryConfig:
        if env_path:
            from dotenv import load_dotenv

            load_dotenv(str(env_path))
        endpoint = os.environ.get("FOUNDRY_PROJECT_ENDPOINT")
        model = os.environ.get("FOUNDRY_MODEL", "gpt-5-mini")
        if not endpoint:
            raise RuntimeError(
                "FOUNDRY_PROJECT_ENDPOINT is not set. Copy .env.example to .env "
                "and fill it in (see README)."
            )
        return cls(
            endpoint=endpoint,
            model=model,
            api_key=os.environ.get("FOUNDRY_API_KEY") or None,
            azure_openai_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT") or None,
            api_version=os.environ.get("FOUNDRY_API_VERSION") or "preview",
        )


class ComplianceAssistant:
    """Builds and runs the Foundry agents against a generated OSCAL set."""

    def __init__(self, oscal_dir: str | Path, config: FoundryConfig, audience: str = "auditor"):
        self.tools = ComplianceTools(oscal_dir)
        self.config = config
        self.audience = audience if audience in AUDIENCE_STYLES else "auditor"
        self._credential: AzureCliCredential | None = None
        self._client: FoundryChatClient | None = None

    async def __aenter__(self) -> ComplianceAssistant:
        if self.config.uses_key_auth:
            # Key auth path. Lets a collaborator outside the resource owner's
            # Azure directory run the agents without a guest invitation and
            # RBAC propagation. Uses the Azure OpenAI endpoint, which is the
            # surface that accepts an api-key header.
            from agent_framework.openai import OpenAIChatClient

            self._credential = None
            self._client = OpenAIChatClient(
                model=self.config.model,
                api_key=self.config.api_key,
                azure_endpoint=self.config.azure_openai_endpoint,
                api_version=self.config.api_version,
            )
            return self

        # Default: no secret anywhere. AzureCliCredential rather than
        # DefaultAzureCredential because on macOS the default chain probes
        # Keychain and managed identity first, adding latency and sometimes
        # hanging. We know we are developer-authenticated.
        self._credential = AzureCliCredential()
        self._client = FoundryChatClient(
            project_endpoint=self.config.endpoint,
            model=self.config.model,
            credential=self._credential,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._credential is not None:
            await self._credential.close()

    def _agent(self, name: str, role: str, tools: list) -> Agent:
        return Agent(
            client=self._client,
            name=name,
            instructions=f"{role}\n\n{AUDIENCE_STYLES[self.audience]}\n{GROUNDING_RULE}",
            tools=tools,
        )

    # ------------------------------------------------------------ specialists

    def posture_agent(self) -> Agent:
        return self._agent(
            "PostureAnalyst",
            "You answer questions about the tenant's current SCuBA compliance posture "
            "and explain what individual SCuBA policies require.",
            [
                self.tools.get_posture_summary,
                self.tools.get_control_details,
                self.tools.search_controls,
                self.tools.get_nist_mapping,
                self.tools.get_threat_coverage,
            ],
        )

    def risk_agent(self) -> Agent:
        return self._agent(
            "RiskPrioritiser",
            "You prioritise remediation. Rank failures by real-world risk, weighing "
            "SHALL over SHOULD, the MITRE ATT&CK techniques a control mitigates, and "
            "blast radius. Always call get_threat_coverage and rank_fixes_by_threat "
            "before answering: compliance severity and threat coverage give different "
            "orderings, and the difference is usually the most useful thing you can "
            "tell someone. Explain your ranking; never simply restate severity.",
            [
                self.tools.list_failures,
                self.tools.get_control_details,
                self.tools.get_posture_summary,
                self.tools.get_threat_coverage,
                self.tools.rank_fixes_by_threat,
            ],
        )

    def remediation_agent(self) -> Agent:
        return self._agent(
            "RemediationEngineer",
            "You explain how to fix a failing SCuBA policy, grounded in CISA's own "
            "implementation guidance returned by get_control_details. Do not invent "
            "configuration steps that are not in that guidance.",
            [self.tools.get_control_details, self.tools.search_controls, self.tools.list_failures],
        )

    def report_agent(self) -> Agent:
        return self._agent(
            "ReportWriter",
            "You write compliance reports from assessment data: an accurate summary "
            "of posture, the most significant gaps, and what happens next. ALWAYS "
            "call get_posture_summary before writing, and always include the "
            "concrete figures it returns - total policies assessed, the pass/fail/"
            "warning counts, the compliance rate, and the number of open "
            "high-severity items. A report without numbers is not a report.",
            [
                self.tools.get_posture_summary,
                self.tools.list_failures,
                self.tools.get_control_details,
                self.tools.get_nist_mapping,
            ],
        )

    def all_agents(self) -> dict[str, Agent]:
        return {
            "posture": self.posture_agent(),
            "risk": self.risk_agent(),
            "remediation": self.remediation_agent(),
            "report": self.report_agent(),
        }

    # ------------------------------------------------------------- entrypoint

    async def ask(self, question: str, specialist: str = "posture") -> str:
        """Route a question to one specialist and return its grounded answer."""
        agent = self.all_agents()[specialist]
        result = await agent.run(question)
        return result.text
