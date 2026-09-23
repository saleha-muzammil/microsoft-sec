# Strategic core — what we build and why it wins

Derived from prior-art research (`D_PRIOR_ART.md`), with the load-bearing claims **independently
re-verified** against GitHub rather than taken on trust.

---

## Verified facts (checked directly, 2026-09-22)

| Claim | Status | Evidence |
|---|---|---|
| ScubaGear is **CC0-1.0** (public domain dedication) | ✅ **Verified** | GitHub license API → `CC0-1.0`, "Creative Commons Zero v1.0 Universal" |
| CISA prototyped SCuBA→OSCAL and **abandoned it** | ✅ **Verified** | Branch `cisagov/ScubaGear:oscal-exploration` exists; last commit **2024-08-27**, never merged |
| CISA publishes an **authoritative SCuBA→NIST 800-53 crosswalk** | ✅ **Verified & downloaded** | `PowerShell/ScubaGear/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv` — **106 mappings** |
| CISA publishes a **policy-ID migration table** | ✅ **Verified & downloaded** | `PowerShell/ScubaGear/mappings/scuba-baseline-policy-migrations.csv` |
| "Judging has a 40% Azure weight" | ❌ **False — do not repeat** | The official rules PDF in this repo states **25% × 4** (Performance, Innovation, Economic Value & Societal Impact, Feasibility). No Azure weighting exists. A research agent asserted this; the primary source contradicts it. |

> Methodology note worth keeping: one research claim turned out to be wrong and two had wrong file
> paths. Every strategically load-bearing fact in this project gets verified against the primary
> source before we build on it. That habit is also what makes our *compliance* claims trustworthy.

---

## The two CISA artifacts that change our design

### 1. `scuba-to-nist-sp-800-53-r5-fedramp-high.csv` — 106 authoritative mappings

```csv
scuba-control-id,nist-800-53-control-id
MS.AAD.1.1v1,CM-7
MS.AAD.2.1v1,"AC-2(12), AC-2(13)"
MS.AAD.3.1v1,"IA-2(1), IA-2(2), IA-5c, IA-5g, IA-2(8)"
```

Coverage by product: `AAD` 31 · `SECURITYSUITE` 25 · `TEAMS` 14 · `EXO` 12 · `SHAREPOINT` 8 ·
`POWERPLATFORM` 8 · `POWERBI` 8.

**This kills the weakest part of our original plan.** We had proposed "AI proposes SCuBA→800-53
mappings with confidence scores." But CISA *already published the authoritative answer*, and prior art
shows competing tools silently disagree with it (e.g. `uiao` maps `MS.AAD.1.1v1`→`IA-2(1)` where CISA
says **`CM-7`**). An LLM guessing mappings that a CC0 CSV already states authoritatively is not
innovation — it is a correctness regression, and a judge who knows the domain would spot it.

**Revised design — strictly better:**

| Layer | Source | Provenance tag | Trust |
|---|---|---|---|
| Authoritative mappings | CISA's CSV, parsed deterministically | `cisa-authoritative` | Ground truth. Never overridden, never AI-touched. |
| Gap mappings | AI-proposed for policies CISA left unmapped | `ai-proposed` | Confidence-scored, rationale attached, **requires human approval** before entering any OSCAL artifact |

And the demo moment: **a CI test that fails the build if any mapping in our OSCAL output contradicts
CISA's published CSV.** That is a concrete, verifiable correctness guarantee, it is trivially
demonstrable on camera, and it is something the existing tools provably do not do.

### 2. `scuba-baseline-policy-migrations.csv` — the drift problem nobody solved

```csv
Old ID,Old Description,New ID,Shall or Should,Removal Rationale
MS.AAD.3.2v1,...MFA...,MS.AAD.3.2v2,Shall,N/A
MS.EXO.2.2v2,An SPF policy SHALL be published...,MS.EXO.2.2v3,SHALL,Relax hard-fail -all to accept ~all. Bumped to v3
```

**Why this is the sharpest idea available to us.** Naive drift detection diffs two ScubaGear runs by
policy ID. But SCuBA policy IDs *change between baseline versions* — `MS.EXO.2.2v2` becomes
`MS.EXO.2.2v3`. A naive differ reports that as **one control disappearing and an unrelated one
appearing**: a false "new finding" plus a false "resolved finding." Every drift tool we found compares
run-to-run and would get this wrong.

We consume CISA's migration table so drift survives baseline version changes, and we can *show* the
naive answer being wrong next to ours. That is a real, technical, domain-specific insight — exactly
the kind of thing the Innovation criterion ("overcome obstacles in a creative way") rewards.

---

## Our positioning in one sentence

> **CISA started the SCuBA→OSCAL bridge and left it unfinished in an abandoned branch. We finish it —
> the complete chain from baseline to POA&M, with mappings provably faithful to CISA's own crosswalk,
> drift that survives baseline version changes, and an AI layer that reasons over the artifacts
> without ever inventing a compliance fact.**

## Differentiators we can defend (ranked)

1. **Complete the OSCAL chain CISA explicitly marked TODO** — component-definition, SSP, and POA&M were
   never built in `oscal-exploration`. Highest value, directly evidenced by CISA's own README.
2. **Provenance-correct mapping + CI that fails on divergence from CISA's CSV.** Demonstrable in 10
   seconds on camera; proves incumbents wrong.
3. **Version-aware drift** using CISA's migration table. Genuinely novel; solves a real false-positive class.
4. **AI as confidence-scored gap-filler over a deterministic spine**, with human-in-the-loop approval —
   never as the source of a compliance fact.
5. **A maintained, correctly-licensed, current-OSCAL M365 catalog** carrying SHALL/SHOULD criticality
   and MITRE ATT&CK props.

## Claims we must NOT make (they are false, and a judge may know it)

- ❌ "First SCuBA→OSCAL catalog" — `buidav/scubaTest` (2024) and the CISA branch predate us.
- ❌ "First OSCAL assessment-results from ScubaGear" — the CISA branch did exactly this.
- ❌ "First drift detection for SCuBA" — `WhalerMike/uiao` ships `scubadrift`; Qualys sells it.
- ❌ "First AI for OSCAL" — awslabs `mcp-server-for-oscal`, MapOSCAL, RegScale all exist.
- ❌ Any implication of CISA endorsement. No CISA logos.

Overclaiming is the single fastest way to lose credibility with a subject-matter-expert judge.
Precise, verifiable claims beat grand vague ones.

## Licensing conclusion

- ScubaGear + baselines: **CC0-1.0** → we may freely redistribute derived content. Attribute anyway.
- NIST OSCAL: US Government work, public domain, **but NIST asks for acknowledgement and a note of
  changes and dates**. We will comply in `NOTICE`.
- Our repo: **Apache-2.0** (permissive, explicit patent grant, NOTICE convention).
- ⚠️ Do **not** copy from `buidav/scubaTest` — it has **no license**, so no rights are granted.

## Competitive watch

`RashadSafir/scuba-oscal` — created 2026-09-23, currently empty. Possibly another team in this same
hackathon. Not a reason to rush; it is a reason to be **more correct**, since correctness is what
differentiates when two teams pick the same obvious framing.
