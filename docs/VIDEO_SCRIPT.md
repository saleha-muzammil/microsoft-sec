# Demo video script

**Target: 5:00.** Rule 6 caps the video at 15 minutes; the organisers suggest 3–5.
Rule 6 also requires the video be **solely the team's own work** — our own filming,
editing and graphics. No outsourced editing, no purchased templates.

**Must cover** (Rule 5.3e): project goals · solution components and architecture ·
how we thought through our approach · key learnings.

**Setup before recording**
- Run `python scripts/generate.py` and `python scripts/validate_all.py` once so
  output is warm and fast.
- Have the Streamlit app already running on `localhost:8501`.
- Have `evals/results.json` open in a tab.
- `az login` done, token fresh — a failed auth on camera is avoidable.
- **Record a backup take of every live AI query.** If Foundry is slow on the day,
  cut to the recorded take rather than waiting on screen.

---

## 0:00 – 0:30 · The problem *(Slide 1 → 2)*

> "CISA publishes SCuBA — the security baselines every federal agency must meet
> for Microsoft 365 — and ScubaGear, a scanner that grades a tenant against them.
>
> But ScubaGear produces a report for a human to read. It is not machine-readable
> compliance evidence. So everything downstream — the System Security Plan, the
> Plan of Action and Milestones, the NIST 800-53 mappings an auditor needs — is
> still built by hand, in Word and spreadsheets.
>
> And under Binding Operational Directive 25-01, this isn't optional."

## 0:30 – 1:00 · The opening *(Slide 3)*

> "Before building anything, we checked whether this was already solved. It turns
> out CISA started exactly this bridge — and stopped. Their `oscal-exploration`
> branch hasn't been touched since August 2024, was never merged, and its own
> README says" *(read the quote on screen)* **"'you can't have an assessment plan
> model without implementing all the preceding layers'"** *(then)* "leaving
> component-definition, SSP and POA&M marked TODO.
>
> That's our opening. We finished it."

## 1:00 – 1:35 · Architecture *(Slide 4)*

> "The design decision that matters most is this ordering.
>
> Parsing and OSCAL generation are plain, typed, tested Python. No model decides
> what a control ID is, what a test result was, or what goes in a required schema
> field. Microsoft Foundry sits on top, where judgement genuinely helps —
> prioritisation, explanation, reporting.
>
> That means when someone asks 'how do you know the model didn't invent that
> number?', the answer is: it couldn't have. Every figure comes from a pure
> function over a document that passed the NIST validator."

## 1:35 – 2:20 · Live: generate and validate *(terminal)*

```bash
python scripts/generate.py
python scripts/validate_all.py
```

> "From CISA's own published assessment, we generate the complete OSCAL chain —
> catalog, profile, component-definition, SSP, assessment plan, assessment
> results, POA&M, and the control mapping.
>
> And here's the part that matters for correctness: every one of them validates
> against NIST's own `oscal-cli`, with full Metaschema constraints — not just JSON
> Schema. Eight for eight. This runs in CI, so the build fails if any document
> stops validating."

*(Let the 8/8 PASS output sit on screen for a beat.)*

## 2:20 – 2:55 · Mapping provenance *(Slide 6 → app)*

> "CISA already publishes the authoritative SCuBA-to-NIST crosswalk. So we bind to
> it rather than asking a model to guess — because a mapping that contradicts the
> source of truth is a defect, not a feature.
>
> Eighty-nine of ninety-two policies resolve deterministically — and not one
> mapping in this system was written by a model. The remaining three we report as
> unmapped, because CISA hasn't published an answer and we're not going to invent
> one.
>
> We have a CI test that reads CISA's CSV independently of our own parser and
> fails the build on any divergence. It pins a case other published tooling gets
> wrong: this policy maps to CM-7, least functionality — not to an MFA control."

## 2:55 – 3:30 · Drift — the strongest moment *(app → Drift view)*

> "Now the part we're most proud of.
>
> SCuBA policy IDs are versioned, and CISA revises them. Between these two runs,
> `MS.DEFENDER` became `MS.SECURITYSUITE`. A tool that matches runs by identifier
> reports each renumbered policy twice — once as vanished, once as new.
>
> On this data that's **twenty-six fabricated events** — thirteen phantom new
> findings and thirteen phantom resolved findings — corrupting exactly the numbers
> a compliance report is built on.
>
> We consume CISA's own migration table. Four real changes: three improvements,
> one regression. That's the truth."

## 3:30 – 4:10 · Live: ask the Copilot *(app → Ask the Copilot)*

Ask: **"What are our top 3 risks and why? Consider MITRE ATT&CK, not just severity."**

> "Every answer comes from a tool call over the validated OSCAL. Notice it cites
> policy IDs, and it groups related failures by theme rather than just restating
> severity."

Then ask: **"What does MS.FAKE.9.9v9 require?"**

> "And when we ask about a policy that doesn't exist, it refuses — rather than
> inventing a plausible-looking control. That's the guardrail working."

## 4:10 – 4:35 · Measured quality *(Slide 9)*

> "We didn't just assert this works. Fifteen golden questions whose ground truth
> is derived from the artifacts themselves: 100% accuracy, 100% citation rate on
> every question that requires one, and a ten-second median response.
>
> And the evaluation earned its place — it caught a real bug in our own prompt
> design. Our report agent was writing 'a substantial set of policies passed',
> with no numbers. The cause was our own grounding rule: telling a model never to
> state an ungrounded fact made vagueness feel like the safe option. We named that
> failure mode explicitly and went from 14 out of 15 to 15 out of 15."

## 4:35 – 5:00 · Impact and learnings *(Slide 10 → 12)*

> "Who is this for? Virginia's public universities, school divisions and county
> governments run the same Microsoft 365 estate as a federal agency, with a
> fraction of the compliance staff. OSCAL is the format FedRAMP assessors already
> consume, so this output is immediately useful.
>
> Three things we learned. First, research before building — CISA's abandoned
> branch shaped our entire scope. Second, the standard is stricter than the schema;
> the NIST validator caught four classes of error JSON Schema accepts. Third, and
> most useful: **a grounding rule that only says 'don't make things up' teaches a
> model to say nothing.** You have to tell it to go and get the facts.
>
> It's open source, Apache-2.0, and it runs on CISA's public data — so anyone can
> check every number we just showed you."

---

## Recording notes

- **Screen-record at 1080p minimum.** Terminal font large enough to read on a laptop.
- Slides for framing, live app for proof. Don't narrate over a static slide for
  more than ~30 seconds.
- Let validation output and the drift comparison **sit on screen** — those are the
  two moments a judge needs a beat to absorb.
- Say plainly that the input is **CISA's published sample assessment** and that the
  follow-up run is derived from it. Disclose it rather than let it be discovered.
- Do **not** claim any "first ever". Every such claim in this space is already taken,
  and a subject-matter judge will know.
