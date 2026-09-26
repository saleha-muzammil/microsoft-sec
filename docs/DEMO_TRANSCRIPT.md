# Demo transcript + slide notes

Two parts:
1. **The live demo** — what to put on screen, what to say over it (~3 min of screen time).
2. **The deck** — what to say on each of the 16 slides in `microsoft.pptx`.
3. A running order that interleaves the two for a ~5:30 video.

Every number spoken here appears on screen behind it, so a viewer who mishears can still read it.

---

## Part 1 · The live demo

**Before you hit record**
- `python scripts/generate.py` and `python scripts/validate_all.py` once, so the on-camera run is warm.
- Streamlit running on `localhost:8501`, sidebar on **🏠 Start here**.
- `az login` done and the token fresh.
- Record a **backup take of every AI query** — if Foundry is slow on the day, cut to the take rather than waiting on screen.
- Terminal font large, 1080p minimum.

---

### Beat 1 — Generate and validate (terminal, ~40s)

**Show:** a clean terminal, then run

```bash
python scripts/generate.py
python scripts/validate_all.py
```

Let the `8/8 documents valid` block sit on screen for a beat.

**Say:**
> "This is CISA's own published ScubaGear assessment going in. Out comes the complete OSCAL chain — catalog, profile, component-definition, system security plan, assessment plan, assessment results, POA&M, and the control mapping. Three of those are the models CISA marked TODO in their own abandoned exploration branch.
>
> All eight pass NIST's JSON Schema. Seven also pass NIST's own `oscal-cli` with full Metaschema constraints — cardinality and cross-references, not just shape. The eighth is the mapping model, which the CLI has no command for yet, so we print `cli:n/a` rather than implying more than we checked. This runs in CI: the build fails if any document stops validating."

**Show (3 seconds, required for eligibility):** cut to `src/scuba_oscal/agents/orchestrator.py`, the line importing `FoundryChatClient` and `AzureCliCredential`.

**Say:**
> "Microsoft Foundry, keyless auth, no API keys anywhere in the repo."

---

### Beat 2 — Drift (app → **4 · What changed?**, ~30s)

**Show:** the naive comparison next to the version-aware one.

**Say:**
> "SCuBA policy IDs are versioned and CISA revises them. Between these two runs `MS.DEFENDER` became `MS.SECURITYSUITE`. A tool that matches on identifier reports every renumbered policy twice — once vanished, once new. On this data that's **twenty-six fabricated events**, corrupting exactly the numbers a compliance report is built on.
>
> We consume CISA's own migration table. What actually changed: three improvements, one regression, thirteen renumberings absorbed."

Let the comparison sit on screen.

---

### Beat 3 — The two questions the number hides (app → **1 · How are we doing?**, then **2 · What needs fixing?** → threat tab, ~35s)

**Show:** the "Is this number even real?" panel, then the threat-coverage tab.

**Say:**
> "Two things the scanner's report can't tell you. First — is the number even real? ScubaGear lets an organisation omit policies from its own report, and an omitted policy leaves the denominator. Here four are suppressed, all four are SHALL, and two of the exemptions have already expired and are still suppressing. The score effect is nine tenths of a point — we could have quoted something dramatic, but two of the four were passing anyway. The problem isn't the percentage, it's that nothing reviews, approves or expires any of it. Every exemption becomes an OSCAL risk an auditor can query.
>
> Second — what can still happen to us? CISA maps each policy to the ATT&CK techniques it mitigates, so we can count surviving mitigations. Six techniques have none left. And the two rankings disagree: these three findings are SHOULD, so severity ranks them last — but each is the only remaining mitigation for two techniques."

---

### Beat 4 — Ask the Copilot (app → **3 · Ask the AI**, ~45s)

**Show:** specialist = *Risk expert*. Ask:

> **"What are our top 3 risks and why? Consider MITRE ATT&CK, not just severity."**

**Say, while it answers:**
> "Every answer comes from a tool call over the validated OSCAL — the model can read the evidence, it cannot author it. It cites policy IDs and groups failures by theme rather than restating severity.
>
> Now look at the line under the answer. After the model finishes, a deterministic audit re-checks every identifier it produced — every policy ID, NIST control, ATT&CK technique, every UUID — against the evidence corpus. Live, on every answer. Grounding constrains what goes in; this audits what came out."

**Show:** open **"Show me the evidence"**, pick one cited policy ID.

**Say:**
> "Any citation traces to its source node — the requirement in the catalog, the observation in the assessment results, the POA&M item. 'Show me the evidence' is one click, not a grep."

**Show:** ask **"What does MS.FAKE.9.9v9 require?"**

**Say:**
> "Ask for a policy that doesn't exist and it refuses instead of inventing a plausible control. That's a mechanism, not a promise — the tool returns an error, so there's nothing to summarise. And the audit knows that fake ID came from *my question*: quoted to deny it, not asserted as fact."

**Show (optional, 5s):** sidebar → **Use your own scan**.

**Say:**
> "Any tenant's own ScubaResults file runs the same parser, transformers and validator — there's no separate demo path. An uploaded file is untrusted input, so instruction-like text is neutralised before it can reach an agent."

---

### Beat 5 — Provenance (app → **5 · The evidence**, ~15s, cut first if over time)

**Show:** the provenance table and the version-skew line.

**Say:**
> "Every document carries the SHA-256 of each input inside its own metadata — rehash the scan, compare, and you know this evidence came from exactly that file. And CISA's own sample assesses `MS.SHAREPOINT.3.3v1`, a policy their baseline doesn't define. We report that skew instead of silently dropping it."

---

## Part 2 · What to say on each slide

Times are cumulative guides for a 5:30 video. Never narrate a static slide for more than ~30 seconds.

### Slide 1 — Title · SCuBA Compliance Copilot *(0:00–0:10)*
> "SCuBA Compliance Copilot. We turn CISA's SCuBA baselines and ScubaGear assessments into validated OSCAL — with an AI layer that cannot invent a compliance fact. Saleha Muzammil at UVA, Mughees Ur Rehman at Virginia Tech."

### Slide 2 — The problem *(0:10–0:35)*
> "CISA publishes SCuBA, the security baselines for Microsoft 365, and ScubaGear, a scanner that grades a tenant against them. But ScubaGear produces a report for a human to read — not machine-readable compliance evidence. So everything downstream is still done by hand: the System Security Plan in Word, the POA&M in a spreadsheet, the NIST mappings assembled manually for an ATO package, auditor questions answered by re-reading reports. Without a dedicated GRC team, that's weeks between 'we ran the scanner' and 'we have an auditable package.' And under CISA's Binding Operational Directive, none of this is optional for federal civilian agencies — and it's the de facto standard for the universities and school divisions running the same estate."

### Slide 3 — Our goal *(0:35–0:55)*
> "Our goal: take any Virginia public body from a ScubaGear run to a validated, auditor-ready OSCAL package in minutes, not weeks. We set three criteria before writing code. **Complete** — all eight OSCAL models, including the three CISA left TODO, passing NIST validation. **Faithful** — every NIST mapping matches CISA's own crosswalk, proven by a CI test, never guessed by a model. **Grounded** — agents read only validated documents through tools, and every claim cites the node it came from. Everything after this slide is us reporting against those three."

*(If you have the extra seconds, this is where the CISA `oscal-exploration` research point lands: "we checked whether this was already solved — CISA started this bridge and stopped in August 2024, with component-definition, SSP and POA&M marked TODO. That's our opening.")*

### Slide 4 — Architecture *(0:55–1:20)*
> "The decision that matters most is the ordering. Parsing, transformation and OSCAL generation are plain, typed, tested Python — no model decides what a control ID is, what a test result was, or what goes in a required schema field. Microsoft Foundry sits on top, where judgement genuinely helps: prioritisation, explanation, reporting.
>
> So when someone asks 'how do you know the model didn't invent that number?' — it couldn't have. Every figure comes from a pure function over a document that passed the NIST validator, and that function has tests."

→ **cut to demo Beat 1**

### Slide 5 — Result #1 · The complete OSCAL chain *(after Beat 1)*
> "Eight documents, all valid. Catalog with 127 policies, profile, component-definition, SSP, assessment plan, assessment results — 92 observations, 83 findings, 26 risks — a POA&M with 26 prioritised items and deadlines, and the mapping collection. The three marked 'CISA TODO' are models CISA marked unfinished in their own branch. We completed all three."

### Slide 6 — Result #2 · Mappings faithful to CISA *(2:00–2:25)*
> "CISA already publishes the authoritative SCuBA-to-NIST crosswalk. Asking a model to guess what CISA has already stated isn't innovation, it's a correctness regression. Seventy-one entries come straight from the crosswalk, eighteen more resolve through CISA's migration table — 89 of 92, 97%, with zero AI guessing. The other three we report as unmapped, because CISA hasn't published an answer and we won't infer one.
>
> A CI test reads CISA's CSV independently of our own parser — so a parser bug can't make the test agree with itself — and fails the build on any divergence. It pins a case published third-party tooling gets wrong: `MS.AAD.1.1v1` maps to CM-7, least functionality, not to an MFA control. And we emit it as an OSCAL 1.2 mapping-collection, where provenance, confidence and rationale are native fields — so that distinction lives in the standard, not in a convention we invented."

### Slide 7 — Result #3 · Drift *(shown over / right after demo Beat 2)*
> "Twenty-six fabricated events from a single renumbering. Three genuine improvements, one genuine regression, thirteen renumberings correctly absorbed. This corrupts exactly the numbers a compliance report is built on — how many findings opened, how many closed, whether posture improved. CISA publishes the fix themselves; we consume it."

### Slide 8 — Result #4 · Two questions the number hides *(over / after demo Beat 3)*
> "Is the number even real — four policies suppressed, all mandatory SHALL, two exemptions expired but still active, nine tenths of a point added to the score, and every exemption written into OSCAL as a risk an auditor can query. And what can still happen to us — six ATT&CK techniques uncovered, fifteen degraded, thirty-two covered, with three low-severity findings sitting as the last remaining mitigation for two techniques each. A POA&M tells you what's non-compliant. Neither of these questions can be answered from the scanner's own report."

### Slide 9 — Built for the Commonwealth *(3:25–3:50 · cut last if over)*
> "SCuBA is federal guidance. Virginia's public bodies — every public college, university and school division — are governed by SEC530, VITA's standard, which adopts NIST 800-53 and uses its control identifiers directly. So we compose one more hop: SCuBA policy, CISA's crosswalk, NIST control, SEC530. An exact join on identifiers both governments publish — no model anywhere in that chain.
>
> Twenty-three of our twenty-six failures are also Commonwealth obligations, against 1,189 SEC530 controls parsed from VITA's own spreadsheet — and we surface who Virginia says owns each one, from SEC530's IMPLEMENTED BY column. Three are federal-only, because Virginia withdrew the control they map to: 'not applicable to COV'. That's a real divergence between two authorities governing the same institution."

### Slide 10 — Microsoft Foundry · An AI layer that cannot fabricate *(leads into demo Beat 4)*
> "The guardrails are mechanisms, not promises. Every claim the model makes is checked against the evidence — policy IDs, NIST controls, ATT&CK techniques, OSCAL UUIDs. Each verified citation resolves to the exact node in the validated document. An unknown policy ID returns an error, never a plausible-looking control. And an uploaded scan is untrusted input: instruction-like text is neutralised before it reaches an agent. Let me show you all four."

### Slide 11 — Measured, not asserted *(4:25–4:50)*
> "It's easy to claim an architecture is safer, so we measured it. Same fifteen questions, same model, same grader. The only variable: one arm gets tools over validated OSCAL, the other gets the raw scanner output dumped into context — which is what a straightforward implementation looks like.
>
> A hundred percent against eighty. But the pass rate isn't the story — fabrication is. The scanner file contains no NIST control IDs and no MITRE technique IDs; those come from CISA's baselines, which we integrate. Asked anyway, the ungrounded model didn't decline. It asserted six identifiers from memory and called T1110.003 'Credential Stuffing' when MITRE and CISA both say 'Password Spraying'. Fluent, confident, wrong — an analyst would have acted on it.
>
> Ours asserted zero facts it wasn't given, enforced by a test that fails the build if that ever changes. And the detector that produced these numbers is the same code auditing every live answer you just saw. This isn't a lab result — it's the production guardrail, measured."

### Slide 12 — Economic value and societal impact *(4:50–5:10 · shorten to the last two sentences if over)*
> "What's it worth? We won't give a single number, because that implies precision we don't have. So we separate measured from assumed. Measured, counted from the artifacts: 26 POA&M items, 91 SSP requirements, 89 mappings, 26 phantom findings avoided. Assumed, and adjustable by the reader in the app: minutes per POA&M item, per SSP requirement, per mapping lookup, and the BLS Virginia analyst wage loaded at 1.3.
>
> That gives a band — twenty to sixty-nine hours per assessment cycle, sixteen hundred to five and a half thousand dollars of analyst time — against sixty-two cents a month to run. Across Virginia's 326 public institutions on the quarterly cycle SEC530 already requires, that's tens of thousands of analyst hours a year returned to actual security work. Change any assumption on screen and the answer moves. We'd rather you argue with our inputs than trust our output."

### Slide 13 — Feasibility *(5:10–5:20)*
> "This is running today. Real data — CISA's published assessment, a genuine redacted run, CC0; any tenant's own ScubaResults file runs the same path, there's no separate demo mode. Real validation — NIST's oscal-cli in CI, the build fails if a document stops validating. Real deployment — a Foundry project in eastus2 on gpt-5-mini with keyless auth, provisioned and answering. Reproducible — from a clean clone, install plus two commands reproduce every artifact byte-for-byte, fully offline, each one carrying the SHA-256 of its inputs. And honest about limits: oscal-cli has no mapping command yet, so we report `cli:n/a` rather than implying more."

### Slide 14 — Key learnings *(5:20–5:30)*
*(Pick three of the five and say them cleanly — reading all five will rush the ending.)*
> "What it taught us. **Grounding beats prompting** — same model, same questions: tools over validated OSCAL took accuracy from 80 to 100 and invented identifiers from six to zero. Architecture did what no prompt could. **Look it up, don't generate it** — CISA's crosswalk resolved 89 of 92 mappings deterministically; keeping the model for judgement rather than lookup is what made the output auditable. **Schema-valid isn't enough** — JSON Schema checks structure; NIST's Metaschema also enforces cardinality and cross-references, so we made oscal-cli a CI gate."

*(The fourth and fifth, if you have room: "IDs drift, meaning doesn't" — one renumbering, 26 phantom findings. "Research before building" — CISA's abandoned branch showed us where the gap was and what not to rebuild.)*

### Slide 15 — Close *(5:30)*
> "CISA built the scanner. We built everything after it. Eight NIST-validated OSCAL documents, 89 of 92 mappings deterministic, 26 false findings eliminated, 100% evaluation accuracy — and every finding for a Commonwealth institution traced to SEC530. It's Apache-2.0 and runs on CISA's public data, so every number you just saw can be checked."

### Slide 16 — Thank you
> "Thank you. Mughees Ur Rehman, Virginia Tech. Saleha Muzammil, University of Virginia."

---

## Part 3 · Running order

| # | Screen | ~Time |
|---|--------|-------|
| 1 | Slides 1–3 | 0:00–0:55 |
| 2 | Slide 4 (architecture) | 0:55–1:20 |
| 3 | **Demo Beat 1** — generate + validate + Foundry code | 1:20–2:00 |
| 4 | Slide 5 | 2:00–2:10 |
| 5 | Slide 6 (mappings) | 2:10–2:30 |
| 6 | **Demo Beat 2** — drift, then Slide 7 | 2:30–3:00 |
| 7 | **Demo Beat 3** — exemptions + threat coverage, then Slide 8 | 3:00–3:30 |
| 8 | Slide 9 (Virginia / SEC530) | 3:30–3:50 |
| 9 | Slide 10, then **Demo Beat 4** — ask the Copilot | 3:50–4:30 |
| 10 | Slide 11 (grounded vs ungrounded) | 4:30–4:55 |
| 11 | Slides 12–13 | 4:55–5:15 |
| 12 | Slides 14–16 | 5:15–5:35 |

**If you run long, cut in this order:** Beat 5 (provenance) → the "use your own scan" aside → Slide 12 down to its last two sentences → Slide 9. Keep Slide 9 if at all possible; it is the Commonwealth relevance the challenge asks for.

**Never cut:** the Foundry import on screen (eligibility), the `8/8 documents valid` block, and the fake-policy refusal.
