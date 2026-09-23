# Confirmed project decisions (2026-09-22)

| Decision | Value | Notes |
|---|---|---|
| **Team size** | **2 confirmed** | Meets Rule 4 minimum (2–5). ✅ Eligible. See risk below. |
| **Submission repo** | `saleha-muzammil/microsoft-sec` | Already created, empty, wired as `origin`. Push access needed for `mughees-urrehman`. |
| **ScubaGear data source** | **Synthetic (primary)** | No M365 tenant available. See rationale below. |
| **Azure region** | `eastus2` | Quota verified. |
| **Primary model** | `gpt-5-mini` (GlobalStandard) | 500K TPM available. |

---

## Why synthetic ScubaGear data is the right call (not a compromise)

**Constraint:** we have no M365 tenant. The available Entra tenant is a personal directory with no
Exchange/Teams/SharePoint/Defender workloads, so a real scan would return almost entirely `N/A`.
ScubaGear additionally requires **Windows + PowerShell + OPA**, and this is a macOS team.
The free M365 Developer Program tenant now generally requires a Visual Studio subscription plus
approval — too slow and too uncertain to bet a 2.5-day deadline on.

**Decision: generate realistic synthetic ScubaGear output, conforming exactly to the real schema.**

This is defensible on the merits, and we should say so out loud in the video rather than hide it:

1. **The contribution is the transformation and reasoning layer, not the scanner.** CISA already built
   the scanner. What does not exist is the SCuBA→OSCAL pipeline. Synthetic input exercises that
   pipeline completely.
2. **Privacy and rules compliance.** Rule 13 forbids personal data in submissions. Real tenant output
   contains tenant IDs, domains, display names, and user principal names. Synthetic data has zero
   scrub burden and zero leak risk.
3. **Reproducibility for judges.** A judge can clone the repo and get identical results. Real tenant
   output would be unreproducible and unverifiable by them.
4. **It enables the drift demo.** We author a second "30 days later" run with deliberate regressions
   and improvements. With a single real tenant we could not show drift at all inside the window.

**Non-negotiable honesty requirements:**
- Synthetic data is labeled synthetic **inside the artifacts themselves** (OSCAL metadata props and
  remarks), not merely in a README line a judge might not read.
- Fake tenant identifiers are obviously fake (e.g. `contoso-synthetic.onmicrosoft.com`).
- We state plainly in the video that input is synthetic and explain why. Judges respect a clearly
  reasoned scoping decision; they penalize discovering an undisclosed one.

**Design requirement that keeps this credible:** the parser is written against the **real** ScubaGear
`ScubaResults*.json` schema, so genuine output drops in with no code change. We demonstrate this by
validating our synthetic files against the same parser and types. The synthetic generator is a
*fixture factory*, not a special code path — there is no "synthetic mode" branch in the pipeline.

---

## Open risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Team is at the bare minimum of 2.** If one member becomes ineligible or drops, the entry is void. | **High** | Verify both members against every Rule 4 criterion *now* (VA enrollment, received invitation, 18+, not a government/public-sector employee). Consider recruiting a 3rd as insurance. |
| Push access to `saleha-muzammil/microsoft-sec` not yet confirmed for `mughees-urrehman` | Medium | Confirm collaborator access early; fallback is a repo under `mughees-urrehman` transferred later. |
| Neither member's eligibility has been documented | Medium | Fill in `docs/RULES_CHECKLIST.md` §2 explicitly. |
