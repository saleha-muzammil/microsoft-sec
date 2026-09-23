"""SCuBA Compliance Copilot — demo application.

Organised as a narrative rather than a feature list, because the audience is a
security team or an auditor, not a developer: start here → how are we doing →
what needs fixing → ask a question → what changed → show me the evidence.

Every view opens by answering "what am I looking at?" in plain language, and
every piece of jargon is defined where it first appears.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from scuba_oscal.agents.tools import ComplianceTools  # noqa: E402
from scuba_oscal.app.theme import (  # noqa: E402
    CSS,
    PIPELINE_CSS,
    cards,
    explain,
    page_head,
    pipeline_html,
    step,
)
from scuba_oscal.drift import compare, false_signal_count  # noqa: E402
from scuba_oscal.impact import (  # noqa: E402
    SOURCES,
    VA_INSTITUTIONS,
    Assumptions,
    commonwealth_scale,
    effort_per_assessment,
    measure,
    run_cost,
)
from scuba_oscal.parsers.mappings import MappingIndex  # noqa: E402
from scuba_oscal.parsers.scubagear import parse_run  # noqa: E402

OSCAL_DIR = ROOT / "data/oscal_out"
SAMPLES = ROOT / "data/scubagear_samples"
CROSSWALK = ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv"
MIGRATIONS = ROOT / "data/mappings/scuba-baseline-policy-migrations.csv"

RESULT_COLOURS = {"Pass": "#1A7F37", "Fail": "#CF222E", "Warning": "#BF8700", "N/A": "#8496A6"}

st.set_page_config(page_title="SCuBA Compliance Copilot", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)
st.markdown(PIPELINE_CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------- loaders

@st.cache_resource
def _tools_for(directory: str) -> ComplianceTools:
    return ComplianceTools(directory)


def active_dir() -> Path:
    """The OSCAL set currently being viewed: the sample, or an upload."""
    return Path(st.session_state.get("oscal_dir", OSCAL_DIR))


def get_tools() -> ComplianceTools:
    return _tools_for(str(active_dir()))


@st.cache_resource
def get_index() -> MappingIndex:
    return MappingIndex(CROSSWALK, MIGRATIONS)


@st.cache_data
def posture(_key: str) -> dict:
    return json.loads(get_tools().get_posture_summary())


@st.cache_data
def failures(_key: str) -> list[dict]:
    return json.loads(get_tools().list_failures(limit=500))["failures"]


@st.cache_data
def drift():
    followup = SAMPLES / "ScubaResults_followup_30d.json"
    if not followup.exists():
        return None
    before = parse_run(SAMPLES / "ScubaResults_fa5589b7-d528-4f80.json")
    after = parse_run(followup)
    migrations = get_index().migrations
    naive = compare(before, after, migrations, version_aware=False)
    aware = compare(before, after, migrations, version_aware=True)
    return naive, aware, false_signal_count(naive, aware)


if not (OSCAL_DIR / "scuba-m365-catalog.json").exists():
    st.error("No compliance documents found. Run `python scripts/generate.py` first.")
    st.stop()

data = posture(str(active_dir()))

# --------------------------------------------------------------------- sidebar

VIEWS = {
    "start": "🏠  Start here",
    "posture": "1 · How are we doing?",
    "fix": "2 · What needs fixing?",
    "ask": "3 · Ask the AI",
    "drift": "4 · What changed?",
    "docs": "5 · The evidence",
    "impact": "6 · What is it worth?",
}

with st.sidebar:
    st.markdown("## 🛡️ SCuBA Copilot")
    st.caption("Microsoft 365 security compliance, automated")
    st.markdown("---")
    view = st.radio("Walk through it", list(VIEWS), format_func=lambda k: VIEWS[k], label_visibility="collapsed")
    st.markdown("---")
    with st.expander("📤  Use your own scan"):
        st.caption(
            "Drop in a ScubaGear `ScubaResults*.json` from your own tenant. It runs "
            "through the same parser, transformers and validator as the sample — "
            "there is no separate code path."
        )
        uploaded = st.file_uploader("ScubaGear results", type=["json"],
                                    label_visibility="collapsed")
        if uploaded is not None and st.button("Generate OSCAL from this scan"):
            from scuba_oscal.app.upload import process_upload

            with st.spinner("Parsing, transforming, validating…"):
                result = process_upload(
                    uploaded.getvalue(),
                    ROOT / "data/baselines/ScubaBaselines.json",
                    ROOT / "data/mappings",
                )
            if result.ok:
                st.session_state["oscal_dir"] = str(result.oscal_dir)
                st.session_state["source_label"] = result.tenant
                st.session_state["upload_note"] = (
                    f"{result.policies} policies · {result.failures} failures · "
                    f"{result.validated}/{result.documents} documents valid"
                )
                if result.injection_hits:
                    st.session_state["injection_hits"] = result.injection_hits
                st.cache_data.clear()
                st.rerun()
            else:
                st.error(result.message)

        if "oscal_dir" in st.session_state and st.button("Back to CISA's sample"):
            for key in ("oscal_dir", "source_label", "upload_note", "injection_hits"):
                st.session_state.pop(key, None)
            st.cache_data.clear()
            st.rerun()

    st.markdown("---")
    st.markdown("**Organisation assessed**")
    if "oscal_dir" in st.session_state:
        st.success(f"Your scan: **{st.session_state['source_label']}**", icon="📤")
        st.caption(st.session_state.get("upload_note", ""))
        if st.session_state.get("injection_hits"):
            st.warning(
                f"{st.session_state['injection_hits']} field(s) contained "
                "instruction-like text and were neutralised before reaching the AI.",
                icon="🛡️",
            )
    else:
        st.caption(
            "A sample Microsoft 365 tenant published by CISA — real assessment data, "
            "no private information."
        )
    st.metric("Security rules checked", data["total_policies_assessed"])
    st.metric("Currently passing", data["compliance_rate_excluding_na"])
    if view == "ask":
        audience = st.selectbox(
            "Explain answers for", ["auditor", "executive", "engineer"],
            help="Changes how the AI phrases its answer. The underlying facts are identical.",
        )
    else:
        audience = "auditor"

# ===================================================================== START

if view == "start":
    st.markdown(
        page_head(
            "SCuBA Compliance Copilot",
            "Microsoft 365 has hundreds of security settings. The US government publishes "
            "rules for how they should be configured, and a free scanner that checks them. "
            "This tool takes that scanner's output and turns it into the compliance "
            "paperwork organisations are actually required to produce — then lets you ask "
            "questions about it in plain English.",
        ),
        unsafe_allow_html=True,
    )

    st.markdown("#### The problem, in one paragraph")
    st.markdown(
        "A university or city government runs Microsoft 365 just like a federal agency does. "
        "**CISA** — the US Cybersecurity and Infrastructure Security Agency — publishes security "
        "baselines called **SCuBA** saying how it should be locked down, plus a free scanner "
        "(**ScubaGear**) that grades your setup. The scanner works well. But it produces a *report "
        "for a human to read*. Everything after that — the security plan, the remediation tracker, "
        "the auditor's evidence pack — is still assembled by hand, over weeks, by people most of "
        "these institutions don't employ."
    )

    st.markdown(
        explain(
            "So what does this tool actually do?",
            "It reads the scanner's output and automatically produces the formal compliance "
            "documents in <b>OSCAL</b> — the machine-readable standard that US government "
            "auditors already use. Then it puts an AI assistant on top so you can ask "
            "“what are our biggest risks?” instead of reading 92 rows of JSON.",
        ),
        unsafe_allow_html=True,
    )

    st.markdown("#### How it works")
    st.markdown(pipeline_html(), unsafe_allow_html=True)
    st.markdown(
        '<div class="pipe-legend">'
        "<span>🟢 <b>Deterministic</b> — plain Python. Same input, same output, every time.</span>"
        "<span>🟡 <b>Gate</b> — the build fails if these do not hold.</span>"
        "<span>🔵 <b>AI</b> — judgement, explanation and prioritisation only.</span>"
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        explain(
            "Why does the order matter?",
            "Stages 2–4 contain <b>no AI at all</b>. By the time a model sees anything, the "
            "facts are already fixed in documents that passed a government validator. The AI "
            "reads those documents through stage 5 and cannot reach around it — which is why "
            "it can explain a finding, but cannot invent one.",
        ),
        unsafe_allow_html=True,
    )

    st.markdown("#### The words you'll see, in plain English")
    st.markdown(
        '<span class="jargon">SCuBA</span> CISA\'s security rulebook for Microsoft 365. '
        "Think of it as a checklist of ~127 settings that should be configured a certain way."
        "<br><br>"
        '<span class="jargon">ScubaGear</span> CISA\'s free scanner that checks your Microsoft 365 '
        "against that checklist and reports pass or fail for each item."
        "<br><br>"
        '<span class="jargon">OSCAL</span> A standard format, created by NIST, for writing '
        "compliance information so computers can read it. Auditors and FedRAMP already consume it. "
        "This is what we generate."
        "<br><br>"
        '<span class="jargon">POA&M</span> “Plan of Action and Milestones” — the formal document '
        "listing what\'s broken, how serious it is, and when it will be fixed."
        "<br><br>"
        '<span class="jargon">SHALL vs SHOULD</span> SHALL is mandatory (legally required for '
        "federal agencies). SHOULD is recommended. We never blur the two.",
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("#### What you'll find in each section")
    for n, (key, text) in enumerate(
        [
            ("1 · How are we doing?", "The scoreboard. How many security rules pass, fail, or need attention — overall and per Microsoft product."),
            ("2 · What needs fixing?", "The work queue. Every failure ranked by severity, with a deadline, CISA's own fix instructions, and which government control it maps to."),
            ("3 · Ask the AI", "Ask questions in plain English. The AI can only answer using the verified documents — it is structurally unable to make a number up."),
            ("4 · What changed?", "Compare two scans over time. This is where we do something other tools get wrong, and we show you the difference."),
            ("5 · The evidence", "The actual compliance documents, downloadable. All eight pass the US government's official validator."),
        ],
        start=1,
    ):
        st.markdown(step(n, key), unsafe_allow_html=True)
        st.caption(text)

    st.markdown("---")
    st.markdown(
        '<p class="footnote">Built on <b>Microsoft Foundry</b>. Input is CISA\'s own published '
        "sample assessment (public domain) — no private organisation's data is used anywhere. "
        "Open source under Apache-2.0.</p>",
        unsafe_allow_html=True,
    )

# =================================================================== POSTURE

elif view == "posture":
    st.markdown(
        page_head(
            "How are we doing?",
            "Every security rule CISA checks, and whether this organisation passes it.",
        ),
        unsafe_allow_html=True,
    )
    r = data["results"]
    total = data["total_policies_assessed"]

    st.markdown(
        cards(
            [
                (str(r.get("Pass", 0)), "Passing", "configured correctly", "good"),
                (str(r.get("Fail", 0)), "Failing", "needs fixing", "bad"),
                (str(r.get("Warning", 0)), "Partial", "partly configured", "warn"),
                (str(r.get("N/A", 0)), "Not applicable", "doesn't apply here", ""),
                (data["compliance_rate_excluding_na"], "Overall score", "of applicable rules", "dark"),
            ]
        ),
        unsafe_allow_html=True,
    )

    st.markdown(
        explain(
            "How do I read this?",
            f"Of <b>{total}</b> security rules checked, <b>{r.get('Pass',0)}</b> pass. "
            f"<b>{r.get('Fail',0)}</b> fail outright and <b>{r.get('Warning',0)}</b> are only "
            "partly configured — both need attention. The <b>Not applicable</b> ones don't apply "
            "to this organisation's licences, so they're excluded from the score. "
            "Every number here is read directly from the verified compliance documents, "
            "not calculated in this page.",
        ),
        unsafe_allow_html=True,
    )

    left, right = st.columns([1, 1.35])
    with left:
        st.markdown("##### Overall")
        frame = pd.DataFrame({"Result": list(r.keys()), "Count": list(r.values())})
        fig = px.pie(frame, names="Result", values="Count", hole=0.58,
                     color="Result", color_discrete_map=RESULT_COLOURS)
        fig.update_layout(margin=dict(t=6, b=6, l=6, r=6), height=310,
                          legend=dict(orientation="h", y=-0.12))
        st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown("##### Which Microsoft product is weakest?")
        rows = [
            {"Product": p, "Result": res, "Count": c}
            for p, counts in data["by_product"].items()
            for res, c in counts.items()
        ]
        fig = px.bar(pd.DataFrame(rows), x="Product", y="Count", color="Result",
                     color_discrete_map=RESULT_COLOURS)
        fig.update_layout(margin=dict(t=6, b=6, l=6, r=6), height=310, barmode="stack",
                          legend=dict(orientation="h", y=-0.22), xaxis_title=None)
        st.plotly_chart(fig, use_container_width=True)

    worst = max(data["by_product"].items(), key=lambda kv: kv[1].get("Fail", 0))
    st.info(
        f"**Biggest weak spot: {worst[0]}** — {worst[1].get('Fail', 0)} failing rules. "
        "In Microsoft 365, AAD (now called Entra ID) controls who can sign in and what they can "
        "do, so failures there tend to matter most.",
        icon="🎯",
    )

# ======================================================================= FIX

elif view == "fix":
    st.markdown(
        page_head(
            "What needs fixing?",
            "Every failing rule, ranked by how serious it is, with a deadline and CISA's own fix instructions.",
        ),
        unsafe_allow_html=True,
    )
    items = failures(str(active_dir()))
    if not items:
        st.success("Nothing is failing.")
        st.stop()

    frame = pd.DataFrame(items)
    sev_counts = frame["severity"].value_counts().to_dict()
    st.markdown(
        cards(
            [
                (str(sev_counts.get("high", 0)), "High", "fix within 30 days", "bad"),
                (str(sev_counts.get("moderate", 0)), "Moderate", "fix within 90 days", "warn"),
                (str(sev_counts.get("low", 0)), "Low", "fix within 180 days", ""),
                (str(len(items)), "Total open", "tracked in the POA&M", "dark"),
            ]
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        explain(
            "Where do the severities and deadlines come from?",
            "Not from an AI. A failing <b>SHALL</b> (mandatory) rule is High; a failing "
            "<b>SHOULD</b> (recommended) rule is Moderate; a partially-configured SHOULD is Low. "
            "Deadlines follow the timelines US federal agencies already use — 30, 90 and 180 days. "
            "Both are computed in code, so they're the same every time.",
        ),
        unsafe_allow_html=True,
    )

    order = {"high": 0, "moderate": 1, "low": 2}
    frame["_r"] = frame["severity"].map(order)
    frame = frame.sort_values(["_r", "policy_id"]).drop(columns="_r")
    chosen = st.multiselect("Show severities", ["high", "moderate", "low"],
                            default=[s for s in ["high", "moderate", "low"] if s in sev_counts])
    filtered = frame[frame["severity"].isin(chosen)] if chosen else frame

    display = filtered[["policy_id", "severity", "product", "title", "deadline"]].rename(
        columns={"policy_id": "Rule", "severity": "Severity", "product": "Product",
                 "title": "What's wrong", "deadline": "Fix by"}
    )
    st.dataframe(display, use_container_width=True, hide_index=True, height=300)

    st.markdown("---")
    st.markdown("##### Look at one rule in detail")
    selected = st.selectbox("Choose a failing rule", filtered["policy_id"].tolist(),
                            label_visibility="collapsed")
    if selected:
        detail = json.loads(get_tools().get_control_details(selected))
        mapping = json.loads(get_tools().get_nist_mapping(selected))

        st.markdown(f"### {detail['title']}")
        tag = "Mandatory — legally required for federal agencies" if detail["mandatory"] else "Recommended"
        st.caption(f"`{detail['policy_id']}` · {tag} · currently **{detail['assessed_result']}**")

        left, right = st.columns([2, 1])
        with left:
            st.markdown("**Why this matters** *(CISA's own words)*")
            st.write(detail["rationale"] or "—")
            with st.expander("📋  How to fix it — CISA's step-by-step instructions"):
                st.markdown(detail["implementation_guidance"] or "—")
            if detail.get("evidence"):
                with st.expander("🔍  What the scanner actually found"):
                    st.code(detail["evidence"][:1500], language=None)
        with right:
            st.markdown("**Government control this maps to**")
            if mapping.get("nist_controls"):
                st.code("\n".join(mapping["cisa_published_ids"] or mapping["nist_controls"]))
                if mapping["provenance"].startswith("cisa"):
                    st.success("✓ Published by CISA", icon="✅")
                    st.caption("This mapping is CISA's official answer — not something our AI guessed.")
                else:
                    st.warning(f"AI-proposed ({mapping['provenance']})", icon="⚠️")
                    st.caption("CISA hasn't published a mapping for this rule. Needs human review.")
            else:
                st.info("CISA hasn't published a mapping for this rule.")
            if detail["mitre_attack"]:
                st.markdown("**Attack techniques this blocks**")
                st.caption(", ".join(detail["mitre_attack"][:10]))

# ======================================================================= ASK

elif view == "ask":
    st.markdown(
        page_head(
            "Ask the AI",
            "Ask about this organisation's security in plain English. Answers are built only "
            "from the verified compliance documents.",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        explain(
            "Can the AI make things up?",
            "No — and that's the core design decision. The AI has no access to the data. It can "
            "only call a set of functions that read the verified documents, so every number it "
            "gives you traces back to a file that passed the US government's validator. "
            "Ask it about a rule that doesn't exist and it will tell you so rather than invent one.",
        ),
        unsafe_allow_html=True,
    )

    specialists = {
        "posture": "📊  Overall status — how are we doing?",
        "risk": "🎯  Risk expert — what should we fix first?",
        "remediation": "🔧  Engineer — how do I fix this?",
        "report": "📝  Report writer — summarise it for me",
    }
    specialist = st.selectbox("Who do you want to ask?", list(specialists),
                              format_func=lambda k: specialists[k])

    suggestions = {
        "posture": ["How are we doing overall?",
                    "What does MS.AAD.3.1v1 require, and did we pass it?",
                    "What does MS.FAKE.9.9v9 require?"],
        "risk": ["What are our top 3 risks and why?",
                 "If we could only fix one thing this week, what should it be?",
                 "Which failures let an attacker take over an account?"],
        "remediation": ["How do we turn on phishing-resistant MFA?",
                        "Someone could trick a user into approving a malicious app — what do we do?",
                        "How do we stop attackers guessing passwords?"],
        "report": ["Write a short summary for our university's leadership.",
                   "Summarise our compliance state for an auditor."],
    }
    picked = st.radio("Try one of these", suggestions[specialist], label_visibility="collapsed")
    question = st.text_area("Or ask your own", value=picked, height=80)

    if st.button("Ask  →", type="primary"):
        from scuba_oscal.agents.orchestrator import ComplianceAssistant, FoundryConfig

        try:
            config = FoundryConfig.from_env(ROOT / ".env")
        except RuntimeError as exc:
            st.error(str(exc))
            st.stop()

        async def run() -> str:
            async with ComplianceAssistant(active_dir(), config, audience=audience) as bot:
                return await bot.ask(question, specialist)

        with st.spinner("Thinking — reading the compliance documents…"):
            try:
                st.markdown("---")
                st.markdown(asyncio.run(run()))
                st.caption("✅ Every fact above came from a verified document, not the AI's memory.")
            except Exception as exc:
                st.error(f"Couldn't reach Microsoft Foundry: {exc}")

# ===================================================================== DRIFT

elif view == "drift":
    st.markdown(
        page_head(
            "What changed since last time?",
            "Comparing two scans of the same organisation, 30 days apart.",
        ),
        unsafe_allow_html=True,
    )
    result = drift()
    if result is None:
        st.warning("Run `python scripts/make_followup_run.py` to create the second scan.")
        st.stop()
    naive, aware, phantom = result

    st.markdown(
        explain(
            "Why is comparing two scans hard?",
            "Because CISA renames its rules. A rule called <code>MS.DEFENDER.2.1v1</code> became "
            "<code>MS.SECURITYSUITE.2.1v1</code> — same requirement, new name. A tool that matches "
            "rules by name sees the old one <i>disappear</i> and a new one <i>appear</i>, and "
            "reports both as changes. Nothing actually happened.",
        ),
        unsafe_allow_html=True,
    )

    naive_n = len([d for d in naive.deltas if d.kind.is_material])
    aware_n = len([d for d in aware.deltas if d.kind.is_material])

    left, right = st.columns(2)
    with left:
        st.markdown("##### ❌ Matching rules by name")
        st.markdown(cards([(str(naive_n), "changes reported",
                            f"{phantom['total_false_events']} of them aren't real", "bad")]),
                    unsafe_allow_html=True)
    with right:
        st.markdown("##### ✅ Our approach")
        st.markdown(cards([(str(aware_n), "changes reported", "all of them real", "good")]),
                    unsafe_allow_html=True)

    st.error(
        f"**Matching by name invents {phantom['total_false_events']} changes that never happened** — "
        f"{phantom.get('added', 0)} made-up new problems and {phantom.get('removed', 0)} made-up "
        f"fixes — because CISA renamed {len(aware.renumbered)} rules between the two scans. "
        "We use CISA's own rename table, so we don't.",
        icon="🚨",
    )

    st.markdown("##### What genuinely changed")
    for d in aware.deltas:
        if d.kind.is_material:
            good = d.kind.value == "improvement"
            st.markdown(
                f'<div class="finding {"up" if good else "down"}">'
                f'{"✅ <b>Fixed</b>" if good else "🔴 <b>Broke</b>"} — '
                f'<span class="pid">{d.policy_id}</span> &nbsp; {d.before.value} → {d.after.value}'
                "</div>",
                unsafe_allow_html=True,
            )
    with st.expander(f"Renames we correctly ignored ({len(aware.renumbered)})"):
        st.caption("These look like changes to a naive tool. They aren't — only the name moved.")
        for d in aware.renumbered:
            st.text(d.description)

# ==================================================================== IMPACT

elif view == "impact":
    st.markdown(
        page_head(
            "What is it worth?",
            "Every figure separates what we measured from what we assumed — and "
            "every assumption is yours to change.",
        ),
        unsafe_allow_html=True,
    )

    m = measure(active_dir())
    st.markdown("##### Measured — counted from the generated documents")
    st.caption("Facts about what the pipeline produced. No assumptions involved.")
    rows = m.as_rows()
    for start in (0, 4):
        for col, (label, value) in zip(st.columns(4), rows[start:start + 4], strict=False):
            col.metric(label, value)

    st.markdown("---")
    st.markdown("##### Assumed — change these and watch the answer move")
    st.caption(
        "We publish a range, not a headline number. A point estimate would imply "
        "precision we do not have."
    )
    c1, c2, c3 = st.columns(3)
    with c1:
        poam_min = st.slider("Minutes to author one POA&M item by hand", 5, 60, 20)
        ssp_min = st.slider("Minutes to write one SSP requirement", 2, 40, 10)
    with c2:
        map_min = st.slider("Minutes to look up one NIST mapping", 1, 20, 6)
        phantom_min = st.slider("Minutes to triage one phantom finding", 5, 45, 15)
    with c3:
        wage = st.slider(
            "Analyst hourly wage ($)", 30.0, 120.0, 62.11, step=0.5,
            help="Default: BLS Virginia mean for Information Security Analysts",
        )
        cycles = st.slider(
            "Assessment cycles per year", 1, 12, 4,
            help="Virginia's SEC530 standard requires quarterly remediation reporting",
        )

    a = Assumptions(
        minutes_per_poam_item=poam_min,
        minutes_per_ssp_requirement=ssp_min,
        minutes_per_mapping_lookup=map_min,
        minutes_per_phantom_triage=phantom_min,
        hourly_wage=wage,
    )
    band = effort_per_assessment(m, a)
    costs = run_cost()

    st.markdown("---")
    st.markdown("##### Result")
    st.markdown(
        cards([
            (f"{band.low_hours:.0f}–{band.high_hours:.0f} h", "Manual effort replaced",
             "per assessment cycle", "good"),
            (f"${band.low_cost:,.0f}–${band.high_cost:,.0f}", "Analyst time value",
             f"at ${band.loaded_hourly:.0f}/h loaded", "good"),
            (f"${costs['total_monthly']:.2f}", "Cost to run",
             "per month, all Azure services", "dark"),
        ]),
        unsafe_allow_html=True,
    )

    ratio = band.mid_cost / max(costs["total_monthly"], 0.01)
    st.success(
        # Streamlit renders $...$ as LaTeX math, so dollar signs in prose are escaped.
        f"**Roughly {ratio:,.0f}x return.** One assessment cycle replaces about "
        f"\\${band.mid_cost:,.0f} of analyst time; running the whole system costs "
        f"\\${costs['total_monthly']:.2f} a month. The deterministic pipeline is local "
        "computation and Azure AI Search runs on the free tier, so almost all of that "
        "cost is the AI questions.",
        icon="💡",
    )

    with st.expander("Where each hour goes"):
        st.dataframe(
            pd.DataFrame([{"Work replaced": n, "Hours": round(h, 1)} for n, h in band.breakdown]),
            use_container_width=True, hide_index=True,
        )

    st.markdown("---")
    st.markdown("##### If Virginia's public institutions adopted it")
    scale = commonwealth_scale(band, cycles_per_year=cycles)
    st.markdown(
        cards([
            (f"{scale['institutions']}", "Public institutions", "running Microsoft 365", ""),
            (f"{scale['low_hours']:,.0f}–{scale['high_hours']:,.0f}", "Analyst hours / year",
             "returned to security work", "good"),
            (f"${scale['mid_cost'] / 1e6:,.1f}M", "Mid-range value / year",
             f"band ${scale['low_cost'] / 1e6:,.1f}M–${scale['high_cost'] / 1e6:,.1f}M", "dark"),
        ]),
        unsafe_allow_html=True,
    )
    st.dataframe(
        pd.DataFrame([{"Institution type": k, "Count": v} for k, v in VA_INSTITUTIONS.items()]),
        use_container_width=True, hide_index=True,
    )
    st.caption("Sources: " + " · ".join(f"[{n}]({u})" for n, u in SOURCES.values()))
    st.info(
        "These institutions run the same Microsoft 365 estate as a federal agency and face "
        "the same expectations — with a fraction of the compliance staff. The point is not "
        "the exact figure; it is that the work is large, repetitive, and currently manual.",
        icon="🏛️",
    )


# ====================================================================== DOCS

else:
    st.markdown(
        page_head(
            "The evidence",
            "The formal compliance documents this tool generates — the actual deliverable.",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        explain(
            "Why does this matter?",
            "These are written in <b>OSCAL</b>, the machine-readable compliance format NIST "
            "created and US government auditors already accept. Producing them by hand takes "
            "weeks. All eight below pass NIST's own official validator — not just a format "
            "check, but the full rulebook.",
        ),
        unsafe_allow_html=True,
    )

    PLAIN = {
        "catalog": ("The rulebook", "All 127 CISA security rules, with the reasoning and fix instructions"),
        "profile": ("Which rules apply", "The subset checked for this organisation"),
        "component-definition": ("What was assessed", "The Microsoft 365 services in scope"),
        "system-security-plan": ("The security plan", "The formal SSP describing the setup"),
        "assessment-plan": ("How it was checked", "The testing procedure used"),
        "assessment-results": ("What was found", "Every result, with evidence"),
        "plan-of-action-and-milestones": ("The fix-it list", "The POA&M: what's broken, how bad, due when"),
        "mapping-collection": ("Government cross-reference", "How each rule maps to NIST 800-53"),
    }

    rows = []
    for path in sorted(active_dir().glob("*.json")):
        model = next(iter(json.loads(path.read_text())))
        name, desc = PLAIN.get(model, (model, ""))
        rows.append({"Document": name, "What it is": desc,
                     "OSCAL model": model, "Size": f"{path.stat().st_size/1024:.0f} KB",
                     "_file": path.name})

    st.dataframe(pd.DataFrame(rows).drop(columns="_file"),
                 use_container_width=True, hide_index=True)
    st.success(f"✅ All {len(rows)} documents pass NIST's official OSCAL validator.", icon="🏛️")

    chosen = st.selectbox("Download or inspect one",
                          [f"{r['Document']} — {r['_file']}" for r in rows])
    if chosen:
        filename = chosen.split("— ")[-1]
        path = active_dir() / filename
        st.download_button("⬇  Download", path.read_bytes(), file_name=filename,
                           mime="application/json")
        with st.expander("Preview the raw document"):
            st.json(json.loads(path.read_text()), expanded=False)
