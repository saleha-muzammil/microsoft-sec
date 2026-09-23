"""End-to-end pipeline: SCuBA baselines + ScubaGear run -> validated OSCAL set."""

from __future__ import annotations

import json
from pathlib import Path

from .parsers.baselines import parse_baselines
from .parsers.scubagear import parse_run
from .transformers.assessment_results import build_assessment_results
from .transformers.catalog import build_catalog
from .transformers.chain import (
    build_assessment_plan,
    build_component_definition,
    build_profile,
    build_ssp,
)

# Written in dependency order: each document's import target must already exist
# on disk before the validator can resolve the one that references it.
FILENAMES = {
    "catalog": "scuba-m365-catalog.json",
    "profile": "scuba-m365-profile.json",
    "component-definition": "scuba-m365-components.json",
    "ssp": "scuba-m365-ssp.json",
    "assessment-plan": "scuba-assessment-plan.json",
    "assessment-results": "scuba-assessment-results.json",
}


def generate(
    baselines_path: str,
    run_path: str,
    out_dir: str,
    synthetic: bool = False,
) -> dict[str, Path]:
    """Generate the full OSCAL document chain. Returns model -> written path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    baselines = parse_baselines(baselines_path)
    run = parse_run(run_path)

    # Only include controls the run actually assessed AND the catalog defines;
    # a profile referencing an id absent from the catalog fails resolution.
    catalog = build_catalog(baselines)
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
        "profile": build_profile(assessed, FILENAMES["catalog"], baselines.version),
        "component-definition": build_component_definition(
            products, FILENAMES["catalog"], baselines.version
        ),
        "ssp": build_ssp(run, assessed, FILENAMES["profile"]),
        "assessment-plan": build_assessment_plan(run, assessed, FILENAMES["ssp"]),
        "assessment-results": build_assessment_results(
            run, FILENAMES["assessment-plan"], synthetic=synthetic
        ),
    }

    written: dict[str, Path] = {}
    for model, doc in docs.items():
        path = out / FILENAMES[model]
        path.write_text(json.dumps(doc, indent=2))
        written[model] = path
    return written
