"""Visual theme for the Copilot app.

Streamlit's defaults read as a developer tool. This project is pitched at
security teams, auditors and university IT staff, so the interface has to look
like a product and explain itself to someone who has never heard of SCuBA or
OSCAL.
"""

from __future__ import annotations

NAVY = "#0A1A2F"
TEAL = "#00A896"
AMBER = "#BF8700"
RED = "#CF222E"
GREEN = "#1A7F37"
GREY = "#5A6B7B"

CSS = """
<style>
  /* ---------- base ---------- */
  .main .block-container { padding-top: 2.2rem; max-width: 1180px; }
  h1, h2, h3 { letter-spacing: -0.01em; }

  /* ---------- page header ---------- */
  .page-head {
    background: linear-gradient(135deg, #0A1A2F 0%, #14304F 100%);
    color: #fff; padding: 1.5rem 1.75rem; border-radius: 14px; margin-bottom: 1.1rem;
  }
  .page-head h1 { color:#fff; margin:0 0 .35rem 0; font-size:1.7rem; font-weight:700; }
  .page-head p  { color:#C6D4E0; margin:0; font-size:.97rem; line-height:1.55; }

  /* ---------- plain-language explainer ---------- */
  .explain {
    background:#F0F6FB; border:1px solid #D4E4F0; border-radius:12px;
    padding:1rem 1.15rem; margin:.4rem 0 1.2rem 0;
  }
  .explain b { color:#0A1A2F; }
  .explain .q { font-weight:700; color:#0A1A2F; display:block; margin-bottom:.3rem; }

  /* ---------- metric cards ---------- */
  .cards { display:flex; gap:.8rem; flex-wrap:wrap; margin:.2rem 0 1rem 0; }
  .card {
    flex:1 1 150px; background:#fff; border:1px solid #E2E8EE; border-radius:12px;
    padding:1rem 1.1rem;
  }
  .card .v { font-size:2.1rem; font-weight:700; line-height:1.05; }
  .card .l { font-size:.8rem; color:#5A6B7B; margin-top:.3rem; font-weight:600;
             text-transform:uppercase; letter-spacing:.04em; }
  .card .s { font-size:.79rem; color:#8496A6; margin-top:.25rem; }
  .card.good  { background:#E8F6EF; border-color:#C3E9D7; }
  .card.bad   { background:#FDECEC; border-color:#F7C9C9; }
  .card.warn  { background:#FFF6E0; border-color:#FFE2A8; }
  .card.dark  { background:#0A1A2F; border-color:#0A1A2F; }
  .card.dark .v { color:#FFB700; } .card.dark .l { color:#9FB3C8; } .card.dark .s { color:#7E93A6; }

  /* ---------- jargon chip ---------- */
  .jargon {
    display:inline-block; background:#EEF3F7; border:1px solid #DDE6ED; color:#38495A;
    border-radius:999px; padding:.12rem .6rem; font-size:.76rem; font-weight:600; margin-right:.3rem;
  }

  /* ---------- step badge ---------- */
  .step { display:flex; align-items:center; gap:.65rem; margin:.1rem 0 .55rem 0; }
  .step .n {
    background:#00A896; color:#fff; width:26px; height:26px; border-radius:50%;
    display:flex; align-items:center; justify-content:center; font-weight:700; font-size:.85rem;
    flex-shrink:0;
  }
  .step .t { font-weight:700; color:#0A1A2F; font-size:1.02rem; }

  /* ---------- finding row ---------- */
  .finding { border-left:4px solid #E2E8EE; padding:.5rem .85rem; margin:.4rem 0;
             background:#FAFBFC; border-radius:0 8px 8px 0; }
  .finding.up   { border-left-color:#1A7F37; }
  .finding.down { border-left-color:#CF222E; }
  .finding .pid { font-family:ui-monospace,Menlo,monospace; font-weight:600; color:#0A1A2F; }

  /* ---------- sidebar ---------- */
  section[data-testid="stSidebar"] { background:#F7F9FB; border-right:1px solid #E6ECF1; }
  section[data-testid="stSidebar"] h1 { font-size:1.15rem; }

  /* ---------- misc ---------- */
  div[data-testid="stMetricValue"] { font-size:1.9rem; }
  .footnote { color:#8496A6; font-size:.82rem; line-height:1.5; }
  hr { margin:1.3rem 0; border:none; border-top:1px solid #E6ECF1; }
</style>
"""


def page_head(title: str, subtitle: str) -> str:
    return f'<div class="page-head"><h1>{title}</h1><p>{subtitle}</p></div>'


def explain(question: str, answer: str) -> str:
    """A plain-language box answering 'what am I looking at?'"""
    return f'<div class="explain"><span class="q">{question}</span>{answer}</div>'


def cards(items: list[tuple[str, str, str, str]]) -> str:
    """items: (value, label, sublabel, variant) where variant is ''|good|bad|warn|dark."""
    html = '<div class="cards">'
    for value, label, sub, variant in items:
        html += (
            f'<div class="card {variant}"><div class="v">{value}</div>'
            f'<div class="l">{label}</div>'
            + (f'<div class="s">{sub}</div>' if sub else "")
            + "</div>"
        )
    return html + "</div>"


def step(number: int, text: str) -> str:
    return f'<div class="step"><div class="n">{number}</div><div class="t">{text}</div></div>'


PIPELINE_CSS = """
<style>
  /* The architecture is three bands, not six equal cards: everything above the
     amber band is deterministic, and the agents below it can only reach the data
     through it. That boundary is the point of the diagram, so it is drawn as a
     boundary rather than described in a legend.

     Every rule is prefixed with .pipe. Streamlit's own markdown stylesheet sets
     margins on p/h4 at the same specificity as a bare .node p and lands later in
     the cascade, which silently doubled the height of every card. */
  .pipe { margin:.5rem 0 .4rem 0; }

  .pipe .band { border-radius:12px; padding:.45rem .7rem .7rem .7rem; border:1px solid; }
  .pipe .band-det { background:#FBFDFC; border-color:#CFE7DA; }
  .pipe .band-gate { background:#FFFCF3; border-color:#F0DCA8; }
  .pipe .band-ai { background:#FAFCFE; border-color:#CFE0EE; }

  .pipe .band-head { display:flex; align-items:baseline; gap:.45rem; flex-wrap:wrap;
                     margin:0 0 .45rem 0; padding-bottom:.28rem; border-bottom:1px solid #EDF1F5; }
  .pipe .band-head .bl { font-size:.74rem; font-weight:800; letter-spacing:.1em;
                         text-transform:uppercase; line-height:1.2; }
  .pipe .band-head .bn { font-size:.8rem; color:#8496A6; line-height:1.2; }
  .pipe .band-det  .bl { color:#1A7F37; }
  .pipe .band-gate .bl { color:#8A5A00; }
  .pipe .band-ai   .bl { color:#0B5A8A; }

  /* Row of nodes with labelled arrows in between. The arrow cells are real grid
     tracks so the label sits under the glyph instead of overlapping a card. */
  .pipe .row { display:grid; align-items:stretch; grid-template-columns:1fr 92px 1fr 92px 1fr; }
  .pipe .row.two { grid-template-columns:1fr 104px 1fr; }
  @media (max-width: 900px) {
    .pipe .row.pipe .row.two { grid-template-columns:1fr; }
    .pipe .arrow { padding:.3rem 0; }
    .pipe .arrow .g { transform:rotate(90deg); }
  }

  .pipe .node { background:#fff; border:1px solid #E2E8EE; border-radius:9px;
                padding:.55rem .7rem .6rem .7rem; }
  .pipe .node .kicker { display:block; font-size:.67rem; font-weight:800; letter-spacing:.09em;
                        text-transform:uppercase; color:#98A7B5; line-height:1.2; margin:0; }
  .pipe .node h4 { margin:.16rem 0 .18rem 0; font-size:1rem; font-weight:700;
                   color:#0A1A2F; line-height:1.25; padding:0; }
  .pipe .node p  { margin:0; padding:0; font-size:.86rem; color:#44586B; line-height:1.35; }
  .pipe .node .fine { margin:.22rem 0 0 0; font-size:.76rem; color:#98A7B5; line-height:1.3; }

  /* The two gates are the architectural boundary, so they are the only nodes
     that carry weight: the validator a solid amber edge, the tool layer a
     double wall, because it is a wall. */
  .pipe .node-gate { border:1.5px solid #E5B94F; }
  .pipe .node-wall { border:5px double #BF8700; padding:.6rem .75rem .65rem .75rem; }
  .pipe .node-wall h4 { color:#8A5A00; }
  .pipe .node-wall .only { display:block; margin:.3rem 0 0 0; font-size:.76rem; font-weight:800;
                           letter-spacing:.07em; text-transform:uppercase; color:#8A5A00;
                           line-height:1.2; }

  .pipe .arrow { display:flex; flex-direction:column; align-items:center; justify-content:center;
                 min-width:0; padding:0 .2rem; }
  .pipe .arrow .g { color:#B6C2CD; font-size:1.1rem; line-height:1; }
  .pipe .arrow .l { margin:.18rem 0 0 0; font-size:.72rem; color:#7E8FA0;
                    text-align:center; line-height:1.25; }

  /* Vertical connector carrying what crosses from one band to the next. */
  .pipe .bridge { display:flex; flex-direction:column; align-items:center; gap:0;
                  padding:.18rem 0 .14rem 0; }
  .pipe .bridge .g { color:#B6C2CD; font-size:1rem; line-height:1.1; }
  .pipe .bridge .l { margin:0; font-size:.75rem; color:#7E8FA0; line-height:1.25; }

  .pipe .agents { display:flex; gap:.3rem; flex-wrap:wrap; margin:.3rem 0 0 0; }
  .pipe .agents span { font-size:.76rem; font-weight:600; color:#0B5A8A; background:#EDF5FB;
                       border:1px solid #D3E5F2; border-radius:999px; padding:.05rem .45rem; }
</style>
"""

#: (kicker, title, body, fine-print) for the deterministic band.
_DETERMINISTIC = [
    ("source", "CISA public data",
     "127 SCuBA rules, a published scan, CISA's NIST crosswalk.", ""),
    ("parse", "Parsers",
     "Typed Python to normalised records.", "BOM · HTML in fields · renamed policies"),
    ("generate", "Transformers",
     "Eight linked OSCAL documents.", "no model picks a control ID or a result"),
]

#: Labels on the arrows between the deterministic nodes.
_DETERMINISTIC_FLOW = ["raw files", "typed records"]


def _node(kicker: str, title: str, body: str, fine: str = "", cls: str = "",
          extra: str = "") -> str:
    return (
        f'<div class="node {cls}"><span class="kicker">{kicker}</span>'
        f"<h4>{title}</h4><p>{body}</p>"
        + (f'<div class="fine">{fine}</div>' if fine else "")
        + extra
        + "</div>"
    )


def _arrow(label: str) -> str:
    return f'<div class="arrow"><span class="g">&rarr;</span><span class="l">{label}</span></div>'


def _bridge(label: str) -> str:
    return f'<div class="bridge"><span class="g">&darr;</span><span class="l">{label}</span></div>'


def _band(label: str, note: str, cls: str, body: str) -> str:
    return (
        f'<section class="band {cls}"><div class="band-head">'
        f'<span class="bl">{label}</span><span class="bn">{note}</span></div>'
        f"{body}</section>"
    )


def pipeline_html() -> str:
    """The architecture as three bands divided by the trust boundary."""
    deterministic = '<div class="row">'
    for i, (kicker, title, body, fine) in enumerate(_DETERMINISTIC):
        deterministic += _node(kicker, title, body, fine)
        if i < len(_DETERMINISTIC_FLOW):
            deterministic += _arrow(_DETERMINISTIC_FLOW[i])
    deterministic += "</div>"

    gate = (
        '<div class="row two">'
        + _node(
            "validate", "NIST validator",
            "Nothing reaches disk unless it validates.",
            "oscal-cli Metaschema in CI, 7 of 8 models",
            "node-gate",
        )
        + _arrow("validated OSCAL")
        + _node(
            "access", "Function tools",
            "Pure reads over the validated documents.",
            cls="node-wall",
            extra='<span class="only">the only path to a fact</span>',
        )
        + "</div>"
    )

    agents = _node(
        "reason", "Foundry agents",
        "Four specialists prioritise and explain what the tools return.",
        extra='<div class="agents"><span>posture</span><span>risk</span>'
              "<span>remediation</span><span>report</span></div>",
    )

    return (
        '<div class="pipe">'
        + _band("Deterministic pipeline", "plain Python · same input, same output, every run",
                "band-det", deterministic)
        + _bridge("candidate documents")
        + _band("Validation boundary", "no model reaches past this line",
                "band-gate", gate)
        + _bridge("tool results only")
        + _band("AI layer", "judgement, prioritisation and wording only",
                "band-ai", agents)
        + "</div>"
    )
