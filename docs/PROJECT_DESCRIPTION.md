# SCuBA Compliance Copilot

**Challenge:** SCuBA Security Application — OSCAL-based representation of SCuBA
security baseline content and/or assessment results.

CISA's SCuBA baselines are mandatory for federal agencies under BOD 25-01, but
ScubaGear produces a report for humans, not machine-readable compliance
evidence — so SSPs, POA&Ms and NIST mappings are still built by hand. CISA began
an OSCAL bridge and abandoned it in August 2024, leaving component-definition,
SSP and POA&M explicitly marked TODO.

We finished it. From CISA's own published assessment, our pipeline generates
**eight OSCAL 1.2.3 documents — the complete chain from catalog to POA&M — all
validating against NIST's validator with full Metaschema constraints.**
SCuBA→NIST 800-53 mappings bind to CISA's authoritative crosswalk (89 of 92
resolved deterministically, none model-generated), with CI that fails on any divergence. Our drift
detection consumes CISA's baseline migration table, eliminating **26 phantom
findings** that identifier-matching tools fabricate when policies are renumbered.

On top sits a **Microsoft Foundry** multi-agent layer — posture, risk,
remediation and reporting — that answers in natural language but *cannot* state
a compliance fact it didn't read from a validated artifact.

Impact is measured, not asserted: one assessment cycle replaces **20–69 analyst
hours** ($1,584–$5,544) and costs **$0.62/month** to run — with every assumption
exposed in the app so a reader can substitute their own. Across Virginia's 326
public institutions on quarterly cycles, that is tens of thousands of hours
returned to security work.

Deterministic core. AI where judgement helps. Provenance never lost.
