"""End-to-end pipeline: SCuBA baselines + ScubaGear run -> validated OSCAL set."""

from __future__ import annotations

import json
from pathlib import Path

from .grounding import sha256_of
from .parsers.baselines import parse_baselines
from .parsers.mappings import MappingIndex
from .parsers.scubagear import parse_run
from .transformers.assessment_results import build_assessment_results
from .transformers.catalog import build_catalog
from .transformers.chain import (
    build_assessment_plan,
    build_component_definition,
    build_profile,
    build_ssp,
)
from .transformers.mapping import build_from_index
from .transformers.poam import build_poam
from .validation import validate_schema


class InvalidArtifactError(ValueError):
    """Raised when a generated document fails OSCAL schema validation.

    Deliberately fatal. An artifact that does not validate is not a degraded
    artifact, it is a wrong one, and writing it would let an invalid document
    be cited as evidence downstream.
    """

    def __init__(self, model: str, errors: list[str]):
        self.model = model
        self.errors = errors
        detail = "\n  ".join(errors[:10])
        super().__init__(f"generated {model} failed OSCAL schema validation:\n  {detail}")

# Written in dependency order: each document's import target must already exist
# on disk before the validator can resolve the one that references it.
FILENAMES = {
    "catalog": "scuba-m365-catalog.json",
    "profile": "scuba-m365-profile.json",
    "component-definition": "scuba-m365-components.json",
    "ssp": "scuba-m365-ssp.json",
    "assessment-plan": "scuba-assessment-plan.json",
    "assessment-results": "scuba-assessment-results.json",
    "poam": "scuba-poam.json",
    "mapping": "scuba-nist-mapping.json",
}

DEFAULT_CROSSWALK = "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv"
DEFAULT_MIGRATIONS = "data/mappings/scuba-baseline-policy-migrations.csv"


def generate(
    baselines_path: str,
    run_path: str,
    out_dir: str,
    synthetic: bool = False,
    crosswalk_path: str = DEFAULT_CROSSWALK,
    migrations_path: str = DEFAULT_MIGRATIONS,
    validate: bool = True,
    config_path: str | None = None,
) -> dict[str, Path]:
    """Generate the full OSCAL document chain. Returns model -> written path.

    :param validate: schema-validate each document *before* it is written.
        Leave this on: :class:`InvalidArtifactError` is the intended outcome of
        a defect, not a silently malformed file on disk.
    :param config_path: optional ScubaGear YAML configuration. Policies it omits
        are emitted into the POA&M as risks carrying a deviation status, so the
        exclusions live in a reviewable artifact instead of only in a config
        file nobody audits.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    baselines = parse_baselines(baselines_path)
    run = parse_run(run_path)

    # Every document's `last-modified` is the assessment timestamp rather than
    # wall-clock time. The documents are a pure function of the run, so they
    # should change only when the run does -- which is what makes regenerating
    # from unchanged input a byte-for-byte no-op, and therefore what makes a
    # git diff of these artifacts mean something.
    stamp = run.timestamp

    # Only include controls the run actually assessed AND the catalog defines;
    # a profile referencing an id absent from the catalog fails resolution.
    catalog = build_catalog(baselines, last_modified=stamp)
    catalog_ids = {
        c["id"]
        for g in catalog["catalog"]["groups"]
        for sg in g.get("groups", [])
        for c in sg.get("controls", [])
    }
    assessed = sorted({p.policy_id.lower() for p in run.policies} & catalog_ids)

    products = sorted({p.product for p in run.policies})

    docs = {
        "catalog": catalog,
        "profile": build_profile(
            assessed, FILENAMES["catalog"], baselines.version, last_modified=stamp
        ),
        "component-definition": build_component_definition(
            products, FILENAMES["catalog"], baselines.version, last_modified=stamp
        ),
        "ssp": build_ssp(run, assessed, FILENAMES["profile"], last_modified=stamp),
        "assessment-plan": build_assessment_plan(
            run, assessed, FILENAMES["ssp"], last_modified=stamp
        ),
        "assessment-results": build_assessment_results(
            run, FILENAMES["assessment-plan"], synthetic=synthetic, last_modified=stamp
        ),
    }

    # A fully-compliant tenant legitimately has no POA&M: OSCAL requires at
    # least one poam-item, so an empty plan is not a valid document.
    exemptions = None
    if config_path and Path(config_path).exists():
        from .exemptions import parse_config

        exemptions = parse_config(config_path)

    poam = build_poam(
        run,
        FILENAMES["ssp"],
        synthetic=synthetic,
        last_modified=stamp,
        exemptions=exemptions,
    )
    if poam is not None:
        docs["poam"] = poam

    # SCuBA -> NIST 800-53 mapping, bound to CISA's published crosswalk.
    if Path(crosswalk_path).exists():
        index = MappingIndex(crosswalk_path, migrations_path)
        docs["mapping"] = build_from_index(
            index, [p.policy_id for p in run.policies], FILENAMES["catalog"], last_modified=stamp
        )

    # In-band provenance: every document carries the SHA-256 of the inputs it
    # was generated from, in its own metadata rather than a sidecar a reviewer
    # might never see. "This artifact came from exactly that scan" becomes a
    # checkable claim -- rehash the input and compare -- and because the hash
    # is a pure function of the input, byte-stable regeneration is preserved.
    from .transformers.catalog import SCUBA_NS

    sources = [("scubagear-results", run_path), ("scuba-baselines", baselines_path)]
    if Path(crosswalk_path).exists():
        sources.append(("nist-crosswalk", crosswalk_path))
    if config_path and Path(config_path).exists():
        sources.append(("scubagear-config", config_path))
    provenance = [
        {"name": "source-sha256", "ns": SCUBA_NS, "class": cls, "value": sha256_of(src)}
        for cls, src in sources
    ]
    for doc in docs.values():
        root = next(iter(doc.values()))
        root["metadata"].setdefault("props", []).extend(provenance)

    written: dict[str, Path] = {}
    for model, doc in docs.items():
        if validate:
            # A hard gate, not a warning: an invalid artifact must never reach
            # disk, because everything downstream -- the agent tools, the app,
            # the auditor -- treats what is on disk as evidence. This is the
            # fast JSON Schema tier; CI additionally runs oscal-cli, which
            # enforces Metaschema constraints the JSON Schema cannot express.
            errors = validate_schema(doc)
            if errors:
                raise InvalidArtifactError(model, errors)
        path = out / FILENAMES[model]
        path.write_text(json.dumps(doc, indent=2))
        written[model] = path
    return written
