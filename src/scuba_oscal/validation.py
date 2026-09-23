"""OSCAL validation, in two tiers.

**Tier 1 - JSON Schema (fast).** Vendored NIST 1.2.3 schemas checked with
``jsonschema``. Runs in milliseconds, needs no JVM, and is what the inner
development loop and the unit tests use.

**Tier 2 - oscal-cli (authoritative).** The NIST-compatible Java validator,
which additionally enforces Metaschema constraints that the JSON Schema does
not express -- cardinality rules, cross-reference resolution, and allowed-value
sets. This is the gate in CI.

Both tiers matter: passing JSON Schema is necessary but *not sufficient*.

One non-obvious fix lives here. OSCAL's ``TokenDatatype`` pattern uses the
Unicode property escape ``\\p{L}``, which Python's built-in ``re`` does not
support. Validating OSCAL with stock ``jsonschema`` therefore raises
``re.PatternError: bad escape \\p`` -- an uncaught exception on essentially
every control id, not a validation failure. We swap in the ``regex`` module,
which does support ``\\p{L}``.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import regex as _regex
from jsonschema import Draft7Validator, validators

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "vendor" / "oscal-schemas"
OSCAL_CLI = Path(__file__).resolve().parents[2] / "tools" / "oscal-cli" / "bin" / "oscal-cli"

#: Root key -> schema filename.
MODEL_SCHEMAS = {
    "catalog": "oscal_catalog_schema.json",
    "profile": "oscal_profile_schema.json",
    "component-definition": "oscal_component_schema.json",
    "system-security-plan": "oscal_ssp_schema.json",
    "assessment-plan": "oscal_assessment-plan_schema.json",
    "assessment-results": "oscal_assessment-results_schema.json",
    "plan-of-action-and-milestones": "oscal_poam_schema.json",
    "mapping-collection": "oscal_mapping_schema.json",
}

#: oscal-cli 3.2.0 has no `mapping` command: the Control Mapping model is new
#: in OSCAL 1.2 and the CLI has not caught up. Those documents are validated
#: by JSON Schema only, and we say so rather than quietly claiming otherwise.
CLI_UNSUPPORTED = {"mapping-collection"}


def _unicode_pattern(validator, patrn, instance, schema):
    """`pattern` keyword backed by `regex`, so \\p{L} works."""
    if isinstance(instance, str) and _regex.search(patrn, instance) is None:
        yield __import__("jsonschema").exceptions.ValidationError(
            f"{instance!r} does not match {patrn!r}"
        )


OscalValidator = validators.extend(Draft7Validator, {"pattern": _unicode_pattern})


@dataclass
class ValidationReport:
    path: Path
    model: str
    schema_valid: bool
    cli_valid: bool | None          # None when the CLI cannot check this model
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.schema_valid and self.cli_valid is not False

    def __str__(self) -> str:
        mark = "PASS" if self.ok else "FAIL"
        cli = {True: "cli:ok", False: "cli:FAIL", None: "cli:n/a"}[self.cli_valid]
        return f"[{mark}] {self.path.name:<34} {self.model:<30} schema:ok {cli}"


def detect_model(doc: dict) -> str:
    for key in doc:
        if key in MODEL_SCHEMAS:
            return key
    raise ValueError(f"unrecognised OSCAL document; root keys: {sorted(doc)}")


def validate_schema(doc: dict, model: str | None = None) -> list[str]:
    """Validate against the vendored NIST JSON Schema. Returns error strings."""
    model = model or detect_model(doc)
    schema = json.loads((SCHEMA_DIR / MODEL_SCHEMAS[model]).read_text())
    validator = OscalValidator(schema)
    return [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    ]


def validate_cli(path: Path) -> tuple[bool, list[str]]:
    """Validate with oscal-cli. Returns (ok, error lines)."""
    if not OSCAL_CLI.exists():
        raise FileNotFoundError(
            f"oscal-cli not installed at {OSCAL_CLI}. Run scripts/install_tools.sh"
        )
    proc = subprocess.run(
        [str(OSCAL_CLI), "validate", "--as=json", str(path)],
        capture_output=True,
        text=True,
    )
    combined = proc.stdout + proc.stderr
    if "is valid" in combined:
        return True, []
    errors = [ln.strip() for ln in combined.splitlines() if "ERROR" in ln or "FATAL" in ln]
    return False, errors[:10]


def validate_file(path: str | Path, use_cli: bool = True) -> ValidationReport:
    path = Path(path)
    doc = json.loads(path.read_text())
    model = detect_model(doc)

    schema_errors = validate_schema(doc, model)
    cli_valid: bool | None = None
    cli_errors: list[str] = []
    if use_cli and model not in CLI_UNSUPPORTED:
        cli_valid, cli_errors = validate_cli(path)

    return ValidationReport(
        path=path,
        model=model,
        schema_valid=not schema_errors,
        cli_valid=cli_valid,
        errors=schema_errors[:10] + cli_errors,
    )
