"""SCuBA Compliance Copilot - Streamlit demo application.

Five views mirroring how a security team actually works a compliance finding:
posture -> risk -> remediation -> evidence -> drift.
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
from scuba_oscal.drift import compare, false_signal_count  # noqa: E402
from scuba_oscal.parsers.mappings import MappingIndex  # noqa: E402
from scuba_oscal.parsers.scubagear import parse_run  # noqa: E402

OSCAL_DIR = ROOT / "data/oscal_out"
SAMPLES = ROOT / "data/scubagear_samples"
CROSSWALK = ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv"
MIGRATIONS = ROOT / "data/mappings/scuba-baseline-policy-migrations.csv"

RESULT_COLOURS = {
    "Pass": "#1a7f37",
    "Fail": "#cf222e",
    "Warning": "#bf8700",
    "N/A": "#6e7781",
}
SEVERITY_COLOURS = {"high": "#cf222e", "moderate": "#bf8700", "low": "#57606a"}

st.set_page_config(page_title="SCuBA Compliance Copilot", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_tools() -> ComplianceTools:
    return ComplianceTools(OSCAL_DIR)


@st.cache_resource
def get_index() -> MappingIndex:
    return MappingIndex(CROSSWALK, MIGRATIONS)


@st.cache_data
def posture() -> dict:
    return json.loads(get_tools().get_posture_summary())


@st.cache_data
def failures() -> list[dict]:
    return json.loads(get_tools().list_failures(limit=500))["failures"]


def artifacts_present() -> bool:
    return (OSCAL_DIR / "scuba-m365-catalog.json").exists()


# --------------------------------------------------------------------- sidebar

st.sidebar.title("🛡️ SCuBA Copilot")
st.sidebar.caption("CISA SCuBA → NIST OSCAL, with Microsoft Foundry")

if not artifacts_present():
    st.error("No OSCAL artifacts found. Run `python scripts/generate.py` first.")
    st.stop()

view = st.sidebar.radio(
    "View",
    ["Posture", "Risk & Remediation", "Ask the Copilot", "Drift", "OSCAL Artifacts"],
)
audience = st.sidebar.selectbox("Audience", ["auditor", "executive", "engineer"])

st.sidebar.divider()
data = posture()
st.sidebar.metric("Policies assessed", data["total_policies_assessed"])
st.sidebar.metric("Compliance (excl. N/A)", data["compliance_rate_excluding_na"])
st.sidebar.caption(
    "Source: CISA's published ScubaGear sample assessment (CC0). "
    "Every figure is read from OSCAL documents that pass NIST validation."
)

# ---------------------------------------------------------------------- views

if view == "Posture":
    st.title("Compliance posture")
    results = data["results"]
    cols = st.columns(4)
    for col, key in zip(cols, ["Pass", "Fail", "Warning", "N/A"], strict=True):
        col.metric(key, results.get(key, 0))

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Results overall")
        frame = pd.DataFrame(
            {"Result": list(results.keys()), "Count": list(results.values())}
        )
        fig = px.pie(
            frame, names="Result", values="Count", hole=0.55,
            color="Result", color_discrete_map=RESULT_COLOURS,
        )
        fig.update_layout(showlegend=True, margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Results by product")
        rows = [
            {"Product": product, "Result": result, "Count": count}
            for product, counts in data["by_product"].items()
            for result, count in counts.items()
        ]
        fig = px.bar(
            pd.DataFrame(rows), x="Product", y="Count", color="Result",
            color_discrete_map=RESULT_COLOURS,
        )
        fig.update_layout(margin=dict(t=10, b=10), barmode="stack")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Open POA&M items by severity")
    sev = data["open_poam_items_by_severity"]
    cols = st.columns(len(sev) or 1)
    for col, (name, count) in zip(cols, sev.items(), strict=False):
        col.metric(name.title(), count)

elif view == "Risk & Remediation":
    st.title("Prioritised remediation")
    items = failures()
    frame = pd.DataFrame(items)
    if frame.empty:
        st.success("No open failures.")
        st.stop()

    order = {"high": 0, "moderate": 1, "low": 2}
    frame["_rank"] = frame["severity"].map(order)
    frame = frame.sort_values(["_rank", "policy_id"]).drop(columns="_rank")

    chosen = st.multiselect(
        "Severity", sorted(frame["severity"].unique()), default=sorted(frame["severity"].unique())
    )
    filtered = frame[frame["severity"].isin(chosen)]

    st.dataframe(
        filtered[["policy_id", "severity", "product", "title", "deadline"]],
        use_container_width=True, hide_index=True,
    )

    st.divider()
    st.subheader("Policy detail")
    selected = st.selectbox("SCuBA policy", filtered["policy_id"].tolist())
    if selected:
        detail = json.loads(get_tools().get_control_details(selected))
        mapping = json.loads(get_tools().get_nist_mapping(selected))

        left, right = st.columns([2, 1])
        with left:
            st.markdown(f"**{detail['title']}**")
            st.caption(
                f"{detail['criticality']} · "
                f"{'Mandatory (BOD 25-01)' if detail['mandatory'] else 'Recommended'} · "
                f"assessed: {detail['assessed_result']}"
            )
            st.markdown("**CISA rationale**")
            st.write(detail["rationale"])
            with st.expander("CISA implementation guidance"):
                st.markdown(detail["implementation_guidance"])
        with right:
            st.markdown("**NIST SP 800-53 Rev 5**")
            if mapping.get("nist_controls"):
                st.code("\n".join(mapping["cisa_published_ids"] or mapping["nist_controls"]))
                provenance = mapping["provenance"]
                if provenance.startswith("cisa"):
                    st.success(f"Provenance: {provenance}")
                else:
                    st.warning(f"Provenance: {provenance}")
            else:
                st.info("CISA has not published a mapping for this policy.")
            st.markdown("**MITRE ATT&CK**")
            st.write(", ".join(detail["mitre_attack"]) or "none listed")

elif view == "Ask the Copilot":
    st.title("Ask the Copilot")
    st.caption(
        "Answers come from tool calls over validated OSCAL documents. The model "
        "cannot state a compliance fact it did not read from an artifact. "
        "Topic questions are resolved by semantic search over CISA's baseline "
        "guidance (Azure AI Search), falling back to keyword search if it is "
        "not configured."
    )

    specialist = st.selectbox(
        "Specialist",
        ["posture", "risk", "remediation", "report"],
        format_func=lambda s: {
            "posture": "Posture analyst",
            "risk": "Risk prioritiser",
            "remediation": "Remediation engineer",
            "report": "Report writer",
        }[s],
    )

    examples = {
        "posture": "What is our overall SCuBA compliance posture?",
        "risk": "What are our top 3 risks and why? Consider MITRE ATT&CK, not just severity.",
        "remediation": "How do we fix MS.AAD.3.1v1?",
        "report": "Write a one-paragraph executive summary of our compliance state.",
    }
    question = st.text_area("Question", value=examples[specialist], height=90)

    if st.button("Ask", type="primary"):
        from scuba_oscal.agents.orchestrator import ComplianceAssistant, FoundryConfig

        try:
            config = FoundryConfig.from_env(ROOT / ".env")
        except RuntimeError as exc:
            st.error(str(exc))
            st.stop()

        async def run() -> str:
            async with ComplianceAssistant(OSCAL_DIR, config, audience=audience) as assistant:
                return await assistant.ask(question, specialist)

        with st.spinner("Querying Microsoft Foundry…"):
            try:
                st.markdown(asyncio.run(run()))
            except Exception as exc:  # surfaced rather than swallowed
                st.error(f"Foundry call failed: {exc}")

elif view == "Drift":
    st.title("Posture drift")
    st.caption(
        "SCuBA policy IDs change between baseline versions. Matching runs by ID "
        "alone reports each renumbered policy twice — once as vanished, once as new."
    )

    followup = SAMPLES / "ScubaResults_followup_30d.json"
    if not followup.exists():
        st.warning("Run `python scripts/make_followup_run.py` to create the follow-up run.")
        st.stop()

    before = parse_run(SAMPLES / "ScubaResults_fa5589b7-d528-4f80.json")
    after = parse_run(followup)
    migrations = get_index().migrations

    naive = compare(before, after, migrations, version_aware=False)
    aware = compare(before, after, migrations, version_aware=True)
    phantom = false_signal_count(naive, aware)

    # Count only *material* events: a renumbering is a change of identifier,
    # not a change of posture, so including it would overstate what each
    # approach actually reports as a finding.
    naive_material = len([d for d in naive.deltas if d.kind.is_material])
    aware_material = len([d for d in aware.deltas if d.kind.is_material])

    left, right = st.columns(2)
    with left:
        st.subheader("Matching by identifier")
        st.metric("Findings reported", naive_material, delta=f"+{naive_material - aware_material} false",
                  delta_color="inverse")
        counts = naive.counts()
        st.json({k: v for k, v in counts.items() if k not in ("unchanged",)})
    with right:
        st.subheader("Version-aware")
        st.metric("Findings reported", aware_material, delta="accurate", delta_color="off")
        counts = aware.counts()
        st.json({k: v for k, v in counts.items() if k not in ("unchanged",)})

    st.error(
        f"Identifier matching manufactures **{phantom['total_false_events']} false events** — "
        f"{phantom.get('added', 0)} phantom new findings and "
        f"{phantom.get('removed', 0)} phantom resolved findings — from "
        f"{len(aware.renumbered)} policies CISA renumbered."
    )

    st.subheader("What actually changed")
    for delta in aware.deltas:
        if delta.kind.is_material:
            icon = "🟢" if delta.kind.value == "improvement" else "🔴"
            st.markdown(f"{icon} **{delta.kind.value}** — {delta.description}")

    with st.expander(f"Renumberings correctly absorbed ({len(aware.renumbered)})"):
        for delta in aware.renumbered:
            st.text(delta.description)

else:  # OSCAL Artifacts
    st.title("Generated OSCAL artifacts")
    st.caption("All documents validate against NIST's OSCAL 1.2.3 validator.")

    rows = []
    for path in sorted(OSCAL_DIR.glob("*.json")):
        doc = json.loads(path.read_text())
        rows.append(
            {
                "Document": path.name,
                "Model": next(iter(doc)),
                "Size (KB)": round(path.stat().st_size / 1024, 1),
            }
        )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    chosen = st.selectbox("Inspect", [r["Document"] for r in rows])
    if chosen:
        path = OSCAL_DIR / chosen
        st.download_button(
            "Download", path.read_bytes(), file_name=chosen, mime="application/json"
        )
        st.json(json.loads(path.read_text()), expanded=False)
