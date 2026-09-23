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
  /* Grid rather than flex: a flex row leaves the final wrapped stage stretched
     across the full width, which reads as a different kind of element. A grid
     wraps evenly at every breakpoint. */
  .pipe {
    display:grid; gap:.55rem; margin:.6rem 0 1rem 0;
    grid-template-columns: repeat(6, minmax(0, 1fr));
  }
  @media (max-width: 1500px) { .pipe { grid-template-columns: repeat(3, minmax(0,1fr)); } }
  @media (max-width: 820px)  { .pipe { grid-template-columns: repeat(2, minmax(0,1fr)); } }

  .pipe-stage {
    background:#fff; border:1px solid #E2E8EE; border-radius:12px;
    padding:.8rem .75rem .7rem .75rem; position:relative;
  }
  .pipe-stage .num {
    position:absolute; top:-9px; left:.75rem; background:#0A1A2F; color:#fff;
    width:21px; height:21px; border-radius:50%; font-size:.7rem; font-weight:700;
    display:flex; align-items:center; justify-content:center;
  }
  /* Flow arrow between cards, drawn on the card so it survives wrapping. */
  .pipe-stage:not(:last-child)::after {
    content:"›"; position:absolute; right:-.42rem; top:50%;
    transform:translateY(-50%); color:#C3CED8; font-size:1.05rem; font-weight:700;
  }
  .pipe-stage h4 { margin:.3rem 0 .28rem 0; font-size:.88rem; color:#0A1A2F; font-weight:700; }
  .pipe-stage p  { margin:0; font-size:.75rem; color:#5A6B7B; line-height:1.42; }
  .pipe-stage .tag {
    display:inline-block; margin-top:.45rem; font-size:.64rem; font-weight:700;
    letter-spacing:.04em; text-transform:uppercase; padding:.1rem .4rem; border-radius:4px;
  }
  .tag-det  { background:#E8F6EF; color:#1A7F37; }
  .tag-gate { background:#FFF1CC; color:#8A5A00; }
  .tag-ai   { background:#E3F0FA; color:#0B5A8A; }
  .pipe-legend { display:flex; gap:1.1rem; flex-wrap:wrap; font-size:.79rem;
                 color:#5A6B7B; margin:.1rem 0 1.1rem .1rem; }
  .pipe-legend b { color:#0A1A2F; }
</style>
"""

#: (number, title, body, tag-label, tag-class)
PIPELINE_STAGES = [
    ("1", "CISA's public data",
     "127 SCuBA security rules, a real published scan, and CISA's own NIST crosswalk.",
     "input", "tag-det"),
    ("2", "Parsers",
     "Typed Python reads the scan and the rulebook. Handles the real file's quirks — BOM, HTML in fields, renamed policies.",
     "deterministic", "tag-det"),
    ("3", "Transformers",
     "Builds the eight linked OSCAL documents. No model decides what a control ID is or what a result was.",
     "deterministic", "tag-det"),
    ("4", "NIST validator",
     "Every document must pass oscal-cli with full Metaschema constraints. A failure stops the build.",
     "hard gate", "tag-gate"),
    ("5", "Function tools",
     "Pure functions that read the validated documents. This is the only path to a fact.",
     "the wall", "tag-gate"),
    ("6", "Foundry agents",
     "Four specialists reason, prioritise and explain — grounded in what the tools return.",
     "AI", "tag-ai"),
]


def pipeline_html() -> str:
    parts = ['<div class="pipe">']
    for num, title, body, tag, cls in PIPELINE_STAGES:
        parts.append(
            f'<div class="pipe-stage"><div class="num">{num}</div>'
            f"<h4>{title}</h4><p>{body}</p>"
            f'<span class="tag {cls}">{tag}</span></div>'
        )
    parts.append("</div>")
    return "".join(parts)
