# Demo video script

**Target: 5:30.** Rule 6 caps the video at 15 minutes; the organisers suggest 3–5.
Two blocks are marked **[CUT IF OVER]** — dropping both lands at ~4:40.

Rule 6 also requires the video be **solely the team's own work** — our own filming,
editing and graphics. No outsourced editing, no purchased templates.

**Must cover** (Rule 5.3e): project goals · solution components and architecture ·
how we thought through our approach · key learnings — **and the PowerPoint must be
on screen inside the video**, not merely uploaded beside it.

Deck: `docs/presentation.pptx`, 14 slides. Slide numbers below refer to it.

**Setup before recording**
- `python scripts/generate.py` and `python scripts/validate_all.py` once, so the
  run on camera is warm and fast.
- Streamlit already running on `localhost:8501`, sidebar on **🏠 Start here**.
- `evals/results.json` and `evals/comparison.json` open in tabs.
- `az login` done, token fresh — a failed auth on camera is avoidable.
- Terminal font large enough to read on a laptop. 1080p minimum.
- **Record a backup take of every live AI query.** If Foundry is slow on the day,
  cut to the recorded take rather than waiting on screen.

---

## 0:00 – 0:25 · The problem *(Slides 1 → 2)*

> "CISA publishes SCuBA — the security baselines every federal agency must meet
> for Microsoft 365 — and ScubaGear, a scanner that grades a tenant against them.
>
> But ScubaGear produces a report for a human to read. It is not machine-readable
> compliance evidence. So everything downstream — the System Security Plan, the
> Plan of Action and Milestones, the NIST 800-53 mappings an auditor needs — is
> still built by hand, in Word and spreadsheets. And under Binding Operational
> Directive 25-01, none of it is optional."

## 0:25 – 0:50 · How we chose the scope *(Slide 3)*

> "Before building anything we checked whether this was already solved. CISA
> started exactly this bridge — and stopped. Their `oscal-exploration` branch
> hasn't been touched since August 2024, was never merged, and its own README
> says" *(read the quote on screen)* **"'you can't have an assessment plan model
> without implementing all the preceding layers'"** *(then)* "leaving
> component-definition, SSP and POA&M marked TODO.
>
> That's our opening. We finished it — and we make precise claims rather than
> 'first ever' claims, because several of those are already taken."

## 0:50 – 1:20 · Architecture *(Slide 4)*

> "The design decision that matters most is this ordering.
>
> Parsing, transformation and OSCAL generation are plain, typed, tested Python —
> 175 tests. No model decides what a control ID is, what a test result was, or
> what goes in a required schema field. Microsoft Foundry sits on top, where
> judgement genuinely helps: prioritisation, explanation, reporting.
>
> So when someone asks 'how do you know the model didn't invent that number?',
> the answer is: it couldn't have. Every figure comes from a pure function over a
> document that passed the NIST validator."

*(While saying "Microsoft Foundry", cut for ~3 seconds to `src/scuba_oscal/agents/orchestrator.py`
showing `from agent_framework.foundry import FoundryChatClient` and `AzureCliCredential` —
this is the Rule 5.1(a) eligibility gate and it must be visible in the video.)*

## 1:20 – 2:00 · Live: generate and validate *(terminal, then Slide 5)*

```bash
python scripts/generate.py
python scripts/validate_all.py
```

> "From CISA's own published assessment, we generate the complete OSCAL chain —
> catalog, profile, component-definition, SSP, assessment plan, assessment
> results, POA&M, and the control mapping. Three of those are the ones CISA
> marked TODO.
>
> All eight pass NIST's JSON Schema. Seven of the eight also pass NIST's own
> `oscal-cli` with full Metaschema constraints — cardinality and cross-reference
> resolution, not just shape. The eighth is the mapping model, which the CLI has
> no command for yet, so we print `cli:n/a` rather than implying more than we
> checked. This runs in CI: the build fails if any document stops validating."

*(Let the `8/8 documents valid` block sit on screen for a beat.)*

*(Optional, ~10 seconds: app → "5 · The evidence" — scroll to the provenance
table and the version-skew line.)*

> "Every document carries the SHA-256 of each input inside its own metadata —
> rehash the scan and compare, and you know this evidence came from exactly that
> file. And reading the data critically pays off: CISA's own published sample
> assesses `MS.SHAREPOINT.3.3v1`, a policy their baseline catalog doesn't
> define. We report that skew instead of silently dropping it."

## 2:00 – 2:25 · Mapping provenance *(Slide 6)*

> "CISA already publishes the authoritative SCuBA-to-NIST crosswalk, so we bind
> to it rather than asking a model to guess — a mapping that contradicts the
> source of truth is a defect, not a feature.
>
> Eighty-nine of ninety-two resolve deterministically, and not one mapping in
> this system was written by a model. The other three we report as unmapped,
> because CISA hasn't published an answer and we won't invent one.
>
> A CI test reads CISA's CSV independently of our own parser and fails the build
> on any divergence. It pins a case other published tooling gets wrong: this
> policy maps to CM-7, least functionality — not to an MFA control."

## 2:25 – 2:55 · Drift *(app → "4 · What changed?", Slide 7)*

> "SCuBA policy IDs are versioned, and CISA revises them. Between these two runs,
> `MS.DEFENDER` became `MS.SECURITYSUITE`. A tool that matches runs by identifier
> reports each renumbered policy twice — once as vanished, once as new.
>
> On this data that's **twenty-six fabricated events** — thirteen phantom new
> findings and thirteen phantom resolved findings — corrupting exactly the
> numbers a compliance report is built on.
>
> We consume CISA's own migration table. Four real changes: three improvements,
> one regression. That's the truth."

## 2:55 – 3:25 · Auditing the compliance number itself *(app → "1 · How are we doing?" and "2 · What needs fixing?" → threat tab, Slide 8)*

> "Two questions the scanner's own report cannot answer.
>
> First: is the number even real? ScubaGear lets an organisation omit policies
> from its own report, and omitted policies leave the denominator — so the
> compliance rate can be raised by editing a YAML file. On this config, four
> policies are suppressed and all four are SHALL. Two of the exemptions have
> already expired and are still suppressing their policies. We could have quoted
> a dramatic number here; we don't, because two of the four were actually
> passing. The honest figure is nine tenths of a point. The distortion that
> matters isn't the percentage — it's that nothing reviews, approves or expires
> any of it. We write every exemption into the POA&M as an OSCAL risk with a
> `risk-status`, so an auditor can query it.
>
> Second: what can still happen to us? CISA maps each policy to the MITRE ATT&CK
> techniques it mitigates, so we can count surviving mitigations. Six techniques
> have none. And the two rankings disagree: these three policies are SHOULD, so
> severity ranks them last — but each is the only remaining mitigation for two
> techniques."

## 3:25 – 3:50 · Virginia *(app → SEC530 section, Slide 9)* **[CUT IF OVER — keep if at all possible]**

> "SCuBA is federal guidance. Virginia's public bodies — every public college,
> university and school division — are governed by SEC530, VITA's standard,
> which adopts NIST 800-53 and uses its control IDs. So we compose one more hop:
> SCuBA policy, CISA's crosswalk, NIST control, SEC530.
>
> Twenty-three of these twenty-six failures are also Commonwealth obligations,
> with the owner Virginia itself assigns. Three are federal-only, because
> Virginia has withdrawn the control they map to — 'not applicable to COV'.
> That's a real divergence between two authorities governing the same
> institution, and it's an exact join on published identifiers. No model."

## 3:50 – 4:25 · Live: ask the Copilot *(app → "3 · Ask the AI", Slide 10)*

Ask: **"What are our top 3 risks and why? Consider MITRE ATT&CK, not just severity."**

> "Every answer comes from a tool call over the validated OSCAL. It cites policy
> IDs, and it groups related failures by theme rather than restating severity.
>
> And notice the line under the answer: after the model finishes, a
> deterministic audit re-checks every identifier it produced — every policy ID,
> NIST control, ATT&CK technique, every UUID — against the evidence corpus,
> live, on every answer. Grounding constrains what goes in; this audits what
> came out." *(point at the ✅ output-audit caption)*

Open the **"Show me the evidence"** expander, pick one cited policy ID:

> "And any citation traces to its source: the requirement in the catalog, the
> observed result, the POA&M item — the exact nodes in the validated documents.
> That's the auditor's question — 'show me' — answered in one click."

Then ask: **"What does MS.FAKE.9.9v9 require?"**

> "Ask about a policy that doesn't exist and it refuses, rather than inventing a
> plausible-looking control. That's the guardrail working — and it's a mechanism,
> not a promise: the tool returns an error, so there is nothing to summarise.
> The audit even knows the fake ID came from *my question* — quoted to deny it,
> not asserted as fact."

*(Optional, 5 seconds: open the sidebar "Use your own scan" expander.)*

> "Any tenant's own ScubaResults file runs the same parser, transformers and
> validator — no separate demo path. And an uploaded file is untrusted input, so
> instruction-like text is neutralised before it can reach an agent."

## 4:25 – 4:50 · The comparison that makes the point *(Slide 11)*

> "It's easy to claim an architecture is safer, so we measured it. Same fifteen
> questions, same model, same grader — but one arm gets tools over validated
> OSCAL, and the other gets the raw scanner output dumped into context. That
> second arm is what a straightforward implementation looks like.
>
> It scored eighty percent to our hundred. But the pass rate isn't the story.
> The scanner file contains no NIST control IDs and no MITRE technique IDs —
> those come from CISA's baselines, which we integrate. Asked anyway, the
> ungrounded model didn't decline. It invented six security identifiers, and
> called T1110.003 'Credential Stuffing' when MITRE says 'Password Spraying'.
>
> Fluent, confident, wrong. An analyst would have acted on it. Our agents
> asserted zero facts they weren't given — and a test fails the build if that
> ever changes.
>
> One more thing: the detector that produced these numbers is the same code
> that audits every live answer you saw a minute ago. The eval isn't a lab
> result — it's the production guardrail, measured."

## 4:50 – 5:10 · Impact *(Slide 12)* **[CUT IF OVER — shorten to the last two sentences]**

> "What is it worth? We refuse to give a single number, because that implies
> precision we don't have. Here is what we measured — 26 POA&M items, 91 SSP
> requirements, 89 mappings, 26 phantom findings avoided. Here is what we
> assumed, every input visible and adjustable in the app. And here is the band:
> twenty to sixty-nine analyst hours per assessment cycle, roughly sixteen
> hundred to five and a half thousand dollars of time. It costs sixty-two cents
> a month to run.
>
> Virginia has three hundred and twenty-six public institutions on the same
> Microsoft 365 estate as a federal agency, with a fraction of the compliance
> staff, and SEC530 already requires quarterly reporting. Change any assumption
> on screen and the answer moves. We'd rather you argue with our inputs than
> trust our output."

## 5:10 – 5:30 · Feasibility, learnings and close *(Slides 13 → 14)*

> "This runs today: real CISA data, NIST validation in CI, a provisioned Foundry
> project with keyless auth — and from a clean clone, install plus two commands
> reproduce every artifact byte-for-byte, offline. Every document carries the
> SHA-256 of each input inside its own metadata, so an artifact can be tied back
> to the exact scan that produced it — the claim travels with the document, not
> with our repository.
>
> Three things we learned. First, research before building — CISA's abandoned
> branch shaped our entire scope. Second, the standard is stricter than the
> schema; NIST's validator caught four classes of error JSON Schema accepts.
> Third, and most useful: **a grounding rule that only says 'don't make things
> up' teaches a model to say nothing.** Our report agent started writing 'a
> substantial set of policies passed', with no numbers — we had to tell it to go
> and *get* the facts, not merely avoid inventing them. That took us from 14 out
> of 15 to 15 out of 15.
>
> CISA built the scanner. We built everything after it. It's Apache-2.0 and runs
> on CISA's public data, so every number you just saw can be checked."

---

## Recording notes

- Slides for framing, live app for proof. Never narrate a static slide for more
  than ~30 seconds.
- Let two things **sit on screen**: the `8/8 documents valid` block, and the
  drift comparison. Those are the beats a judge needs a moment to absorb.
- Say plainly that the input is **CISA's published sample assessment** and that
  the follow-up run is derived from it. Disclose it rather than let it be found.
- Do **not** claim any "first ever". A subject-matter judge will know better.
- Every number spoken here is reproduced on the slide behind it, so a viewer who
  mishears can still read it.
