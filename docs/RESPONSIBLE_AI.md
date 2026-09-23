# Responsible AI

Compliance artifacts are used to make security decisions and to answer auditors.
A confidently wrong answer here is worse than no answer, because it will be
believed and acted on. Our approach is therefore **architectural rather than
aspirational**: the model is *structurally prevented* from asserting compliance
facts, instead of merely instructed not to.

---

## 1. The model cannot fabricate a compliance fact

**Mechanism, not policy.** Agents have no access to the underlying data. They
have access to *tools*, and every tool is a pure function over an OSCAL document
that has passed NIST validation.

```
question → agent → tool call → validated OSCAL document → data → answer
                      ↑
             the only path to a fact
```

- There is no code path by which a model-generated number reaches a report.
- Unknown policy IDs return an explicit error, never a plausible-looking control.
  ([`test_unknown_policy_returns_an_error_not_a_guess`](../tests/test_agent_tools.py))
- Tool outputs carry the policy ID and OSCAL UUID needed to verify any claim.
- [`tests/test_agent_tools.py`](../tests/test_agent_tools.py) asserts the tools
  return exactly what the artifacts contain.

**Observed in practice:** asked for overall posture, the agent reported the
figures *and volunteered* that an aggregate summary cannot support policy-level
citation, offering to run per-policy queries instead. That is the behaviour the
design is for.

## 2. Provenance is never lost

An auditor must be able to tell CISA's judgement from a machine's.

| Provenance | Meaning | Confidence |
|---|---|---|
| `cisa-authoritative` | Direct entry in CISA's published crosswalk | `category: authoritative` |
| `cisa-authoritative-migrated` | CISA's mapping, reached via CISA's own migration table | `category: authoritative` |
| `ai-proposed` | No CISA mapping exists; a model proposed one | numeric percentage |
| `unmapped` | No mapping, and none proposed | — |

- **84 of 92 mappings are deterministic.** AI is confined to the 8 CISA has not published.
- An AI proposal can **never** override a CISA mapping — resolution order forbids it,
  and a test pins that.
- CI fails the build if any emitted mapping diverges from CISA's CSV, read
  independently of our own parser.
- AI-authored remediation prose is tagged `generated-by=ai-assistant` **inside the
  POA&M**, so provenance survives export.

## 3. The artifacts never overstate evidence

- Policies ScubaGear cannot automate are recorded with method **`EXAMINE`**, not
  `TEST`. Reporting a human-assessed policy as machine-verified would be a false
  evidentiary claim.
- **`N/A` policies produce an observation but no finding** — they are evidence of
  neither compliance nor deficiency.
- Failures ScubaGear could not actually assess are **excluded from the POA&M**,
  because we have no evidence they are deficient.
- A fully compliant tenant produces **no POA&M at all**, rather than an empty one.
- `SHALL` (mandatory under CISA BOD 25-01) and `SHOULD` (recommended) are never
  conflated; agents are explicitly instructed not to imply a SHOULD is mandatory.

## 4. Data minimisation and privacy

- Input is CISA's **published, redacted sample assessment** (CC0). No live tenant
  was scanned.
- **No personal data, no real tenant data, no secrets** in the repository —
  verified against history, not just the working tree.
- Authentication is **keyless**, via `AzureCliCredential`. No API keys are stored
  or committed; `.env` is gitignored and `.env.example` documents the shape.
- The derived follow-up run is labelled as derived **inside the file**, so the
  disclosure travels with the data rather than living only in a README.

## 5. Human oversight

- AI-proposed mappings are **proposals**. They require human approval before
  entering the authoritative set, and are visually distinguished in the UI —
  "CISA published this" and "a model suggested this" must not look alike.
- Severity and remediation deadlines are **deterministic**, derived from SCuBA
  criticality and federal POA&M convention (high 30 days / moderate 90 / low 180),
  not assigned by a model.
- The tool layer is **read-only**. Nothing in this system can change a tenant's
  configuration. It produces documents; humans act on them.

## 6. Known limitations, stated plainly

- Model-generated *narrative* (risk explanations, remediation prose, report text)
  can still be imprecise even when grounded in correct data. It is drafting
  assistance for a professional, not a substitute for one.
- 8 of 92 policies have no CISA-published NIST mapping. We surface them as
  unmapped rather than guessing.
- The `mapping-collection` document is JSON-Schema validated only, because
  `oscal-cli` 3.2.0 does not yet support OSCAL 1.2's Control Mapping model. The
  validator reports `cli:n/a` rather than implying full validation.
- Risk prioritisation reflects SCuBA criticality, MITRE ATT&CK breadth and blast
  radius. It does not know your organisation's specific threat model.

## 7. Security posture of the project itself

This is a **defensive** tool. The repository contains no exploit code, no
offensive tooling, no credential testing, and no attack simulation. It reads
assessment output and produces compliance documents. Contest Rule 6 prohibits
malicious code, and the scope discipline is also simply correct for a compliance
product.
