"""Quantified effort and cost model for the SCuBA -> OSCAL pipeline.

The Economic Value criterion asks for a *measurable* benefit, so this module
separates two things that are usually blurred together in vendor claims:

* **Measurements** -- counted directly from the generated OSCAL artifacts.
  These are facts about what the pipeline produced. They are not estimates and
  do not depend on any assumption.
* **Assumptions** -- how long a human takes to produce one of those artifacts by
  hand, and what an hour of that person's time costs. These are genuinely
  uncertain, so every one is named, defaulted conservatively, cited where a
  public source exists, and adjustable by the reader.

We deliberately do **not** publish a single headline figure. A point estimate
would imply a precision we do not have. Instead we report a low/mid/high band
and expose the inputs, so a reader can substitute their own numbers and watch
the answer move. For a compliance audience that posture is more persuasive
than confidence, and it is consistent with the rest of this project: state what
is measured, label what is assumed, and never blur the two.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

#: Virginia mean hourly wage, Information Security Analysts (SOC 15-1212),
#: BLS Occupational Employment and Wage Statistics via O*NET, 2025.
VA_ANALYST_HOURLY_WAGE = 62.11

#: A loaded rate (benefits, overhead) is conventionally 1.3-1.4x base salary.
#: We use the low end.
LOADED_RATE_MULTIPLIER = 1.3

#: Virginia public institutions running Microsoft 365, from primary sources.
#:
#: SCHEV counts *39 public institutions* in total: 15 four-year, 23 community
#: colleges, and Richard Bland College. An earlier version of this table
#: labelled that 39 as "public four-year institutions" and then added the 23
#: community colleges alongside it, double-counting them and inflating the
#: Commonwealth total from 303 to 326.
VA_INSTITUTIONS = {
    "K-12 school divisions": 131,
    "Counties and independent cities": 133,
    "Public four-year institutions": 15,
    "Community colleges": 23,
    "Richard Bland College": 1,
}

SOURCES = {
    "wage": ("Virginia mean hourly wage, Information Security Analysts (15-1212), "
             "BLS OEWS via O*NET", "https://www.onetonline.org/link/localwages/15-1212.00?st=VA"),
    "divisions": ("Virginia Department of Education school division directory",
                  "https://www.doe.virginia.gov/about-vdoe/virginia-school-directories"),
    "localities": ("95 counties + 38 independent cities",
                   "https://en.wikipedia.org/wiki/List_of_cities_and_counties_in_Virginia"),
    "highered": ("Virginia State Council of Higher Education, 39 public institutions: "
                 "15 four-year, 23 community colleges, Richard Bland College",
                 "https://www.schev.edu/students/applying-for-college/colleges-universities"),
}


@dataclass(frozen=True)
class Measured:
    """Counted from the generated artifacts. No assumptions involved."""

    policies_assessed: int
    oscal_documents: int
    ssp_requirements: int
    poam_items: int
    observations: int
    findings: int
    mappings_resolved: int
    phantom_findings_avoided: int

    def as_rows(self) -> list[tuple[str, int]]:
        return [
            ("SCuBA policies assessed", self.policies_assessed),
            ("OSCAL documents generated", self.oscal_documents),
            ("SSP implemented-requirements written", self.ssp_requirements),
            ("POA&M items with severity and deadline", self.poam_items),
            ("Assessment observations recorded", self.observations),
            ("Findings with pass/fail status", self.findings),
            ("NIST 800-53 mappings resolved", self.mappings_resolved),
            ("Phantom drift findings avoided", self.phantom_findings_avoided),
        ]


def measure(oscal_dir: str | Path, phantom_findings: int = 0) -> Measured:
    """Count artifact volume from a generated OSCAL document set.

    :param phantom_findings: false drift events avoided, which requires *two*
        runs to compute and therefore cannot be read out of one document set.
        The caller passes the figure it actually measured.

        This defaults to 0 rather than to the sample's 26 on purpose. A default
        of 26 meant the "Measured" table -- explicitly captioned "no
        assumptions involved" -- reported a literal, and reported it even for
        an uploaded tenant with no second run to compare against. A number you
        cannot derive from the inputs in front of you does not belong in that
        table unless someone hands it to you.
    """
    directory = Path(oscal_dir)

    def load(name: str) -> dict:
        return json.loads((directory / name).read_text())

    ar = load("scuba-assessment-results.json")["assessment-results"]["results"][0]
    ssp = load("scuba-m365-ssp.json")["system-security-plan"]
    poam_path = directory / "scuba-poam.json"
    poam_items = (
        len(json.loads(poam_path.read_text())["plan-of-action-and-milestones"]["poam-items"])
        if poam_path.exists()
        else 0
    )
    mapping_path = directory / "scuba-nist-mapping.json"
    mappings = (
        len(json.loads(mapping_path.read_text())["mapping-collection"]["mappings"][0]["maps"])
        if mapping_path.exists()
        else 0
    )

    return Measured(
        policies_assessed=len(ar.get("observations", [])),
        oscal_documents=len(list(directory.glob("*.json"))),
        ssp_requirements=len(ssp["control-implementation"]["implemented-requirements"]),
        poam_items=poam_items,
        observations=len(ar.get("observations", [])),
        findings=len(ar.get("findings", [])),
        mappings_resolved=mappings,
        phantom_findings_avoided=phantom_findings,
    )


@dataclass
class Assumptions:
    """Every uncertain input, named and adjustable.

    Defaults are deliberately conservative: they describe an experienced analyst
    working efficiently from a scanner report, not a slow one starting blank.
    """

    minutes_per_poam_item: float = 20.0
    minutes_per_ssp_requirement: float = 10.0
    minutes_per_mapping_lookup: float = 6.0
    minutes_per_phantom_triage: float = 15.0
    hourly_wage: float = VA_ANALYST_HOURLY_WAGE
    loaded_multiplier: float = LOADED_RATE_MULTIPLIER

    #: How much to scale the minute estimates for the low and high bands.
    low_factor: float = 0.5
    high_factor: float = 1.75

    @property
    def loaded_hourly(self) -> float:
        return self.hourly_wage * self.loaded_multiplier

    def rows(self) -> list[tuple[str, str]]:
        return [
            ("Authoring one POA&M item by hand", f"{self.minutes_per_poam_item:.0f} min"),
            ("Writing one SSP implemented-requirement", f"{self.minutes_per_ssp_requirement:.0f} min"),
            ("Looking up one NIST 800-53 mapping", f"{self.minutes_per_mapping_lookup:.0f} min"),
            ("Triaging one phantom drift finding", f"{self.minutes_per_phantom_triage:.0f} min"),
            ("Analyst wage (BLS, Virginia)", f"${self.hourly_wage:.2f}/hr"),
            ("Loaded-cost multiplier", f"{self.loaded_multiplier:.2f}x"),
        ]


@dataclass(frozen=True)
class EffortBand:
    low_hours: float
    mid_hours: float
    high_hours: float
    loaded_hourly: float
    breakdown: list[tuple[str, float]] = field(default_factory=list)

    def cost(self, hours: float) -> float:
        return hours * self.loaded_hourly

    @property
    def low_cost(self) -> float:
        return self.cost(self.low_hours)

    @property
    def mid_cost(self) -> float:
        return self.cost(self.mid_hours)

    @property
    def high_cost(self) -> float:
        return self.cost(self.high_hours)


def effort_per_assessment(measured: Measured, assumptions: Assumptions | None = None) -> EffortBand:
    """Manual effort to produce, by hand, what one pipeline run produces."""
    a = assumptions or Assumptions()

    components = [
        ("POA&M items", measured.poam_items * a.minutes_per_poam_item),
        ("SSP requirements", measured.ssp_requirements * a.minutes_per_ssp_requirement),
        ("NIST mappings", measured.mappings_resolved * a.minutes_per_mapping_lookup),
        ("Phantom drift triage", measured.phantom_findings_avoided * a.minutes_per_phantom_triage),
    ]
    mid_minutes = sum(m for _, m in components)

    return EffortBand(
        low_hours=mid_minutes * a.low_factor / 60,
        mid_hours=mid_minutes / 60,
        high_hours=mid_minutes * a.high_factor / 60,
        loaded_hourly=a.loaded_hourly,
        breakdown=[(name, minutes / 60) for name, minutes in components],
    )


#: Azure list prices, USD per 1M tokens, gpt-5-mini (GlobalStandard). These are
#: published figures, not estimates.
GPT5_MINI_INPUT_PER_1M = 0.25
GPT5_MINI_OUTPUT_PER_1M = 2.00

#: **Assumed**, not measured. A grounded answer is one question plus a few tool
#: round-trips carrying JSON from the artifacts, which puts it in this range --
#: but the eval harness does not record token usage, so we do not have a
#: measurement and will not label one. Adjustable, like every other assumption
#: in this module.
ASSUMED_INPUT_TOKENS_PER_QUESTION = 6_000
ASSUMED_OUTPUT_TOKENS_PER_QUESTION = 800

#: Also assumed: how heavily a team queries the assistant.
ASSUMED_QUESTIONS_PER_MONTH = 200


def run_cost(
    questions_per_month: int = ASSUMED_QUESTIONS_PER_MONTH,
    input_tokens: int = ASSUMED_INPUT_TOKENS_PER_QUESTION,
    output_tokens: int = ASSUMED_OUTPUT_TOKENS_PER_QUESTION,
) -> dict[str, float]:
    """What it costs to operate, so the saving can be stated as a net."""
    input_cost = questions_per_month * input_tokens / 1e6 * GPT5_MINI_INPUT_PER_1M
    output_cost = questions_per_month * output_tokens / 1e6 * GPT5_MINI_OUTPUT_PER_1M
    return {
        "ai_questions": round(input_cost + output_cost, 2),
        # The deterministic pipeline is pure local computation.
        "pipeline": 0.0,
        # Azure AI Search Free tier is sufficient for 127 baseline policies.
        "search": 0.0,
        "total_monthly": round(input_cost + output_cost, 2),
    }


def annual_return(
    band: EffortBand, monthly_cost: float, cycles_per_year: int = 4
) -> dict[str, float]:
    """Value and cost over the same period, so the ratio means something.

    Dividing a per-*assessment* saving by a per-*month* cost compares two
    different periods and overstates the ratio by roughly 3x at quarterly
    cadence. Both sides are annualised here: assessments happen
    ``cycles_per_year`` times, the platform is paid for all twelve months.
    """
    value = band.mid_cost * cycles_per_year
    cost = monthly_cost * 12
    return {
        "cycles_per_year": cycles_per_year,
        "annual_value": value,
        "annual_cost": cost,
        "ratio": value / cost if cost else float("inf"),
    }


def commonwealth_scale(band: EffortBand, institutions: int | None = None,
                       cycles_per_year: int = 4) -> dict[str, float]:
    """Scale one assessment to Virginia's public institutions.

    ``cycles_per_year`` defaults to 4 because Virginia's own security standard
    (VITA SEC530) requires quarterly remediation reporting.
    """
    count = institutions if institutions is not None else sum(VA_INSTITUTIONS.values())
    return {
        "institutions": count,
        "cycles_per_year": cycles_per_year,
        "low_hours": band.low_hours * count * cycles_per_year,
        "mid_hours": band.mid_hours * count * cycles_per_year,
        "high_hours": band.high_hours * count * cycles_per_year,
        "low_cost": band.low_cost * count * cycles_per_year,
        "mid_cost": band.mid_cost * count * cycles_per_year,
        "high_cost": band.high_cost * count * cycles_per_year,
    }
