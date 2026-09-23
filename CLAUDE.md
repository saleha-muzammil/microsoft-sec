# CLAUDE.md — project conventions

Project: **SCuBA → OSCAL AI security application**
Contest: Microsoft & CCI Innovation Challenge for Virginia (Sept 21–25, 2026)
Challenge: *"SCuBA Security Application — OSCAL-based representation of SCuBA security baseline
content and/or assessment results."*

**Hard deadline: 11:30 p.m. ET Fri Sept 25, 2026. Internal target: 6:00 p.m. ET Fri.**

---

## Non-negotiables (eligibility — see `docs/RULES_CHECKLIST.md`)

1. **Must use Microsoft Foundry.** Visible in code and in the demo video.
2. **Must solve the SCuBA/OSCAL challenge** — no tangents.
3. **No offensive security code, ever.** No exploits, payloads, malware, credential testing, or attack
   tooling. Rule 6 forbids it and we are a *defensive compliance* tool. Read assessment output → emit
   compliance artifacts. That is the whole product.
4. **No secrets committed.** `.env` is gitignored; `.env.example` documents the shape.
   Auth via `DefaultAzureCredential` (`az login`), never API keys in source.
5. **No real tenant data, no personal data** in the repo, deck, or video. Synthetic data is labeled
   synthetic, prominently and in-band (inside the artifact, not just the README).

---

## Architectural rule: deterministic core, AI on top

This is the single most important design decision in the project, and it is what makes the
**Feasibility** and **Performance** scores defensible.

- **Parsing and OSCAL generation are plain Python.** No LLM decides what a control ID is, what a
  test result was, or what goes in a required schema field. These paths are pure, typed, and unit-tested.
- **The LLM never fabricates compliance facts.** Agents answer *only* by calling function tools that
  query generated OSCAL artifacts. Every substantive answer cites a policy ID and/or OSCAL UUID.
- **AI is used where judgment is genuinely required**: cross-framework control mapping (with a
  confidence score and human approval before anything is written), risk prioritization, remediation
  narrative, and report prose.

If a reviewer asks "how do you know the LLM didn't make this number up?" the answer must be
"it couldn't have — the number came from a deterministic function, and here is the test that proves it."

## Environment

- **Python 3.12** (`uv venv --python 3.12`). Do not use 3.14 — Azure SDK wheels lag.
- **`uv`** for dependency management (fast; matters when iterating under time pressure).
- **Java 21** is installed → NIST `oscal-cli` validation runs locally and in CI.
- Pin every dependency to an exact version. A surprise upgrade the night before the demo is a
  self-inflicted wound.

## Code conventions

- Type hints on every public function; `ruff` for lint+format.
- `pytest` for parsers and transformers. These are the components whose correctness we *claim* on
  stage, so they are the components that get tests.
- Deterministic **UUIDv5** (fixed namespace) for OSCAL identifiers so regenerating artifacts produces
  a byte-stable diff. Random UUIDv4 would make drift detection and git diffs meaningless.
- Module layout:
  - `src/scuba_oscal/parsers/` — SCuBA baseline markdown, ScubaGear results JSON → typed models
  - `src/scuba_oscal/transformers/` — typed models → OSCAL catalog / profile / component-definition /
    assessment-results / POA&M
  - `src/scuba_oscal/agents/` — Microsoft Foundry agents + the function tools they call
  - `src/scuba_oscal/app/` — UI
- Every OSCAL artifact we emit **must validate** before it is written to disk. Validation failure is a
  hard error, not a warning.

## Git conventions

The repo is judged. Treat the commit log as part of the submission.

- Small, frequent, descriptive commits. Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `test:`).
- Never force-push shared branches.
- No commit may introduce a secret, real tenant data, or personal data — check *history*, not just HEAD.
- Commit messages end with the agreed co-author attribution line.

## Demo discipline

- Build the **thin end-to-end slice first** (one product: parse → OSCAL → validate → one grounded agent
  answer), commit it, *then* deepen. A narrow thing that works beats a broad thing that doesn't —
  the judges' own wording for Performance is literally "Does your Solution work?"
- Maintain a **scripted fallback demo mode** with cached model responses, so a slow or throttled API
  on recording day cannot break the video.
- Anything shown in the video must be reproducible from a clean clone in under five commands.
