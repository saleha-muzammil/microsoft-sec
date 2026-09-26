#!/usr/bin/env python
"""Generate the full OSCAL document set from CISA's published sample run."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scuba_oscal.pipeline import generate  # noqa: E402

DEFAULT_RUN = "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"

#: ScubaGear configuration whose OmitPolicy entries become deviation-status
#: risks in the POA&M. Pass "none" to generate without it.
DEFAULT_CONFIG = "data/scubagear_samples/scuba_config_example.yaml"


def main(
    run_path: str = DEFAULT_RUN,
    out_dir: str = "data/oscal_out",
    config_path: str = DEFAULT_CONFIG,
) -> int:
    config = None if config_path.lower() in {"none", ""} else str(ROOT / config_path)
    written = generate(
        baselines_path=str(ROOT / "data/baselines/ScubaBaselines.json"),
        run_path=str(ROOT / run_path),
        out_dir=str(ROOT / out_dir),
        crosswalk_path=str(ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv"),
        migrations_path=str(ROOT / "data/mappings/scuba-baseline-policy-migrations.csv"),
        config_path=config,
    )
    for model, path in written.items():
        print(f"  {model:<24} {path.stat().st_size:>9,} bytes  {path.name}")
    print(f"\n{len(written)} OSCAL documents written to {out_dir}")
    if config:
        print(f"Exemptions compiled from {config_path} into the POA&M as deviation risks.")
    else:
        print("No ScubaGear config supplied; POA&M contains no exemption risks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
