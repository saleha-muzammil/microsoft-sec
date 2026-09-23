# Official Rules Checklist — Microsoft & CCI Innovation Challenge for Virginia

**Source:** `Microsoft and CCI Innovation Challenge for Virginia Contest Official Rules.pdf` (in repo root),
also published at
<https://github.com/MatthewCalder-msft/Microsoft-and-CCI-Innovation-Challenge-for-Virginia>

Extracted 2026-09-22. **This file is the compliance contract for our submission.** Every box must be
checked before we submit.

---

## 1. Hard deadline (Rule 3)

| Event | Time |
|---|---|
| Entry period opens | 8:00 a.m. **ET**, Sept 21, 2026 |
| **ENTRY PERIOD CLOSES** | **11:30 p.m. ET, Friday Sept 25, 2026** |
| Judging | within 7 days after close |
| Winner notification | within 7 days after judging |

> **Team rule: we treat 6:00 p.m. ET Fri Sept 25 as our internal deadline.** A 5.5-hour buffer for
> video upload failures, Innovation Studio outages, and last-minute repo fixes. Nothing ships after that.

---

## 2. Eligibility (Rule 4) — verify for EVERY team member before we invest more time

- [ ] Team has **between 2 and 5 members** (inclusive). A solo entry is **ineligible**.
- [ ] Every member is a **currently enrolled student at a college or university in the Commonwealth of Virginia**.
- [ ] Every member **received an invitation** to participate (i.e. registered via
      <https://msevents.microsoft.com/event?id=2438707534> and got the Microsoft invite email).
- [ ] Every member is **18 years of age or older**.
- [ ] Any member 18+ but under the age of majority in their place of residence has **parent/guardian consent**.
- [ ] **No member is a government or public-sector employee.** Microsoft explicitly excludes them for
      gift/ethics compliance. ⚠️ This catches student workers at state agencies, public university *staff*
      positions, and co-ops at government labs. Check this explicitly — it is a silent disqualifier.
- [ ] No member is a Microsoft employee/director (or of subsidiaries, affiliates, ad agencies, Contest Parties),
      nor a family member or household member of one.
- [ ] No member resides in Cuba, Iran, North Korea, Sudan, Syria, Region of Crimea, or Russia.
- [ ] The registering member has **written consent from each team member** to register them.

---

## 3. What we must build (Rule 5.1)

- [ ] **(a) The Solution leverages Microsoft Foundry.** Rules link directly to
      <https://learn.microsoft.com/en-us/azure/foundry/what-is-foundry>.
      → Non-negotiable eligibility gate. Must be **visible in the code** and **shown in the video**.
- [ ] **(b) The Solution solves exactly one (1) published Hackathon Challenge.**
      → Ours: **"SCuBA Security Application — OSCAL-based representation of SCuBA security baseline
      content and/or assessment results."** State this verbatim on the project page and in the README.

---

## 4. Submission artifacts (Rules 5.2, 5.3)

- [ ] **5.2** Solution uploaded to an **online GitHub repository** (public, so judges can open it).
- [ ] **5.3** Innovation Studio project page contains **all six** items:
  - [ ] (a) Names of all Team Members
  - [ ] (b) The Executive Challenge we chose
  - [ ] (c) A short description of the Solution → `docs/PROJECT_DESCRIPTION.md`
  - [ ] (d) A link to the repository
  - [ ] (e) A **video demonstration** of the Solution, *including a PowerPoint presentation* describing:
        goals · components and architecture · how we thought through our approach · key learnings
  - [ ] (f) The **PowerPoint file itself**, uploaded separately → `docs/presentation.pptx`
- [ ] **One entry per team, total.** No second account, no second project page. Doing so voids the entry.

---

## 5. Eligible-entry content rules (Rule 6) — the ones that can actually bite us

- [ ] **Entry is our own original work.**
- [ ] ⚠️ **The video must be SOLELY the work of the team** — "including but not limited to, the actual
      filming, editing, graphic design, etc." → **We cannot outsource or buy video production.**
      Practical reading: no hired editor, no purchased stock-footage-based template edit, no third-party
      animator. Record and edit it ourselves. *(Using ordinary editing software is fine; hiring a person is not.)*
- [ ] Entry has **not been selected as a winner in any other contest**.
- [ ] We have obtained **all consents, approvals, or licenses** required for everything we submit.
- [ ] Nothing in the entry violates the privacy or IP rights of any person or entity.
- [ ] **Microsoft trademarks/logos/designs may be used** — Rule 6 grants a limited license for the sole
      purpose of submitting an entry. (So Azure/Foundry logos in the deck are explicitly OK.)
- [ ] No obscene, offensive, violent, defamatory, disparaging, or illegal content; nothing promoting
      alcohol, illegal drugs, tobacco, or a political agenda; nothing reflecting negatively on Microsoft's goodwill.
- [ ] ⚠️ **"Contain any computer viruses, malware, spyware, or other malicious or illicit code that will
      degrade or infect any products, services, or any other software or Microsoft's network or systems."**
      → **Critical for us, because we are building a *security* application.** Our repo must contain
      **no exploit code, no payloads, no offensive tooling, no live credential-testing scripts, no
      attack simulation binaries.** We are strictly **defensive/assessment/reporting**. We read
      configuration assessment output and produce compliance documents. Say this explicitly in the README.
- [ ] **Video is ≤ 15 minutes.** (Organizer guidance suggests 3–5 min; the *rule* cap is 15. We target 4–5 min.)

---

## 6. IP, licensing and rights (Rule 7) — read this before choosing a repo license

- Microsoft does **not** claim ownership of our Submission. **We keep ownership.**
- **But** we grant Microsoft an *irrevocable, royalty-free, worldwide* license to use, review, assess, test,
  analyze, and use the entry **in any media, for any non-commercial or commercial purpose**, including
  marketing and sale of Microsoft products, with no compensation or credit to us.
- We **waive claims** arising from similarities to Microsoft's own existing/commissioned work, and agree
  Microsoft will not restrict work assignments of representatives who saw our entry ("unaided memory" clause).
- Our entry **may be posted on a public website**; Microsoft is not responsible for unauthorized use by visitors.

**Implications for us:**
- [ ] Do **not** put anything in this repo we intend to commercialize exclusively or patent later.
- [ ] Choose a **permissive open-source license** (MIT or Apache-2.0). This is consistent with the license we
      already grant Microsoft, signals good open-source citizenship to judges, and avoids any conflict
      between a copyleft license and the broad license grant in Rule 7. **Recommendation: Apache-2.0**
      (adds an explicit patent grant and NOTICE handling, which reads as more mature for a security tool).
- [ ] Add a `NOTICE` / attribution section for third-party content we derive from.

### Third-party content we plan to derive from — license diligence

| Source | What we use | License status | Action |
|---|---|---|---|
| CISA SCuBA M365 secure configuration baselines (`cisagov`) | Policy text, IDs, rationale | U.S. Government work / CC0-style public domain (**verify exact LICENSE in repo — research task A**) | Attribute clearly; do not claim authorship of baseline text |
| CISA ScubaGear | Output **format** only; possibly sample output files | (**verify — research task A**) | Prefer to consume the format, not vendor the code |
| NIST OSCAL schemas & models (`usnistgov/OSCAL`) | JSON schemas, model structure | U.S. Government work, not subject to domestic copyright | Attribute; safe to reference and validate against |
| NIST SP 800-53 Rev 5 control text | Control IDs/titles for mapping | U.S. Government work | Attribute |
| Python dependencies | Libraries | Must all be permissive (MIT/BSD/Apache) | Pin versions; run a license check before submit |

- [ ] Run a dependency license audit before submission; no GPL/AGPL in the dependency tree.
- [ ] Every third-party file we vendor keeps its original license header and is listed in `NOTICE`.

---

## 7. Privacy (Rule 13) — subtle but real

> "Teams will not include any individual Team Member's personal data in the information or submissions
> they provide to Microsoft in connection with the Contest."

Section 5.3(a) *does* require team member **names** on the project page, so names are explicitly requested
and fine. Everything beyond that is not.

- [ ] **No emails, phone numbers, addresses, student IDs, or resumes** in the GitHub repo, the deck, or the video.
- [ ] No personal data of anyone outside the team.
- [ ] ⚠️ **No real tenant data.** If we ever run ScubaGear against a real M365 tenant, we must scrub
      tenant IDs, domain names, display names, and user principal names before committing output.
      **Default plan: use synthetic/sample data, clearly labeled as such.** This is both a privacy control
      and a credibility signal to judges.
- [ ] No secrets, keys, connection strings, or tokens committed — ever. `.env` is gitignored; ship `.env.example`.

---

## 8. Judging criteria (Rule 8) — 25% each, verbatim from the PDF

| Weight | Criterion | Rule's own wording | What we must show |
|---|---|---|---|
| 25% | **Solution Performance** | *"Does your Solution work?"* | It runs live, end to end, without failing. OSCAL output **validates against NIST schemas**. Measured AI quality numbers. |
| 25% | **Innovation** | *"Does your Solution enable a new scenario, take a new approach, or overcome obstacles in a creative way?"* | Multi-agent reasoning over OSCAL; AI-proposed control mappings with confidence + human approval; posture drift; auto-generated POA&M. Not "a chatbot over docs." |
| 25% | **Economic Value & Societal Impact** | *"What measurable benefit could the solution create for communities, citizens, institutions, or economy?"* | **Quantified** hours/dollars saved; named Virginia beneficiaries (local gov, school districts, small agencies, public universities). Judges asked for *measurable* — give them a number with a defensible assumption. |
| 25% | **Feasibility** | *"Can the solution realistically be implemented, adopted, and scaled?"* | Deterministic core, real ScubaGear input, clear Azure deployment path, cost model, Responsible AI docs, tests + CI. |

Note the judges' own phrasing of Performance is **"Does your Solution work?"** — a *working demo* outranks a
clever idea that breaks on stage. This justifies the "thin end-to-end slice first, then deepen" plan and the
cached-response fallback demo mode.

Tie-breaker: an additional judge re-scores on the same criteria. Decisions are final and binding.

---

## 9. Things the rules do **not** say (so we don't over-constrain ourselves)

- The rules do **not** require code to be written exclusively during the entry window. They require it to be
  **our own original work** and not a prior contest winner. *Best practice anyway: build fresh in the window
  and let the git history show it — an honest, dense commit log is itself evidence for judges.*
- The rules do **not** prohibit AI-assisted development. The one "automated system" prohibition (Rule 5) is
  about **obtaining multiple entries** via bots/multiple accounts — not about development tooling.
  ⚠️ The explicit "solely the work of the team" constraint is attached **only to the video** — treat that one
  strictly (see §5).
- The rules do **not** mandate a specific license, cloud region, or programming language.
- The rules do **not** require a deployed public URL — a working local demo satisfies "Does your Solution work?"
  (Deployment still helps Feasibility. Nice-to-have, not a gate.)

---

## 10. Pre-submission final gate — run this list on Friday

- [ ] Team size 2–5, all eligibility boxes in §2 confirmed in writing
- [ ] Solution demonstrably uses Microsoft Foundry (shown in video + visible in code)
- [ ] Solves the SCuBA/OSCAL challenge, stated verbatim
- [ ] GitHub repo **public** and loads for a logged-out visitor
- [ ] No secrets, no personal data, no real tenant data, no offensive security code in repo history
      (check history, not just HEAD — a deleted secret is still in the log)
- [ ] `LICENSE` (Apache-2.0) + `NOTICE` with third-party attribution present
- [ ] Video ≤ 15 min, made solely by the team, includes the PowerPoint content and covers goals /
      architecture / approach / learnings
- [ ] `presentation.pptx` uploaded separately to the project page
- [ ] Project page has all six 5.3 items
- [ ] Exactly one entry submitted
- [ ] Submitted before **11:30 p.m. ET Sept 25, 2026** (internal target: 6:00 p.m. ET)

---

## 11. Open questions to resolve with the team

1. **Who is on the team?** Need 2–5 confirmed VA students, all invited and 18+. *(Blocking for eligibility.)*
2. Does any member hold a government/public-sector job? *(Silent disqualifier.)*
3. Whose GitHub account hosts the repo, and is it public?
4. Who records/edits the video? *(Must be a team member.)*
