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

| Provenance | Meaning |
|---|---|
| `cisa-authoritative` | Direct entry in CISA's published crosswalk |
| `cisa-authoritative-migrated` | CISA's mapping, reached through CISA's own migration table |
| `unmapped` | No resolvable CISA mapping. Nothing is inferred. |
| `unknown-policy` | The policy is not in the catalog at all — a different answer to a different question |

- **89 of 92 mappings are deterministic (97%).** The remaining 3 are reported as
  unmapped.
- **No mapping in the shipped artifacts is model-generated.** The data model
  reserves an `ai-proposed` provenance and a numeric confidence score for a
  future human-in-the-loop workflow, and the code path is exercised only in
  tests. Nothing in `data/oscal_out/` carries it, and the mapping document's own
  metadata records `ai-proposed-mappings = 0`. If that ever changes, the count in
  the artifact changes with it.
- CI fails the build if any emitted mapping diverges from CISA's CSV, read
  independently of our own parser.
- The POA&M generator accepts optional AI-authored remediation prose and tags any
  item using it `generated-by=ai-assistant` **inside the document**, so provenance
  would survive export. **The default pipeline does not pass it**, so every
  artifact we ship contains only CISA-derived and deterministically-computed
  prose — verifiable by grepping `data/oscal_out/` for `generated-by`, which
  returns nothing.

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

## 4b. Untrusted input

The app accepts user-supplied ScubaGear files, whose free-text fields
(`Requirement`, `Details`) end up in an agent's context. That is a prompt
injection surface, and it is handled at two levels:

- **Architecturally (the control that matters).** Agents cannot state a
  compliance fact except through a tool reading a validated artifact. Injected
  prose can appear *as data* in an answer, but it cannot become a compliance
  claim, change a result, or alter a mapping.
- **By sanitisation (defence in depth).** Instruction-like text is replaced with
  a visible `[redacted: instruction-like text in scan data]` marker. It is
  neutralised rather than deleted, because a compliance artifact should record
  what the input actually said, and the marker makes tampering obvious to a
  human reader. The count is surfaced in the UI when a file triggers it.

The filter is deliberately narrow and we state its limit plainly: natural
language cannot be perfectly disambiguated. An earlier, broader version flagged
the legitimate baseline sentence *"The system prompts the user for MFA"*.
Mangling real compliance text is a correctness failure, so we accept that some
hostile phrasings pass the filter and rely on the architectural control instead.

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
- 3 of 92 policies have no resolvable CISA mapping. We surface them as unmapped
  rather than inferring one.
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
