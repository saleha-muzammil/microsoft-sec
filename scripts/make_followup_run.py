#!/usr/bin/env python
"""Derive a second, later ScubaGear run from CISA's published sample.

Purpose: demonstrate posture drift, which needs two runs of the same tenant.
We have exactly one real assessment, so the follow-up is derived from it and
**labelled as derived inside the file itself**, not merely in a README.

Three kinds of change are applied, chosen to exercise the drift engine:

1. **A baseline upgrade.** Policies with an unambiguous 1:1 migration in CISA's
   own table are renumbered (MS.DEFENDER.* -> MS.SECURITYSUITE.*). This is the
   scenario naive drift tooling gets wrong: results are unchanged, only the
   identifiers moved.
2. **Genuine improvements.** A few failures are fixed, as a tenant would after
   working its POA&M.
3. **A genuine regression.** A passing control lapses, as happens when
   configuration drifts.

A correct drift report must separate (1) from (2) and (3). That is the point.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scuba_oscal.parsers.mappings import MappingIndex  # noqa: E402
from scuba_oscal.parsers.scubagear import load_json  # noqa: E402

SOURCE = ROOT / "data/scubagear_samples/ScubaResults_fa5589b7-d528-4f80.json"
TARGET = ROOT / "data/scubagear_samples/ScubaResults_followup_30d.json"

#: Failures the tenant remediated. Chosen as the highest-severity AAD items,
#: i.e. what our own risk agent would tell them to fix first.
IMPROVED = {
    "MS.AAD.3.1v1": "Pass",   # phishing-resistant MFA enforced
    "MS.AAD.3.4v1": "Pass",   # authentication methods migration completed
    "MS.AAD.5.1v1": "Pass",   # app registration restricted
}

#: A control that lapsed between runs.
REGRESSED = {
    "MS.EXO.6.1v1": "Fail",
}


def main() -> int:
    doc = load_json(SOURCE)
    index = MappingIndex(
        ROOT / "data/mappings/scuba-to-nist-sp-800-53-r5-fedramp-high.csv",
        ROOT / "data/mappings/scuba-baseline-policy-migrations.csv",
    )
    renames = index.migrations          # 1:1 only; splits/retirements excluded

    stats = {"renamed": 0, "improved": 0, "regressed": 0}

    for _product, groups in doc["Results"].items():
        for group in groups:
            for control in group.get("Controls", []):
                policy_id = (control.get("Control ID") or "").strip()

                if policy_id in IMPROVED:
                    control["Result"] = IMPROVED[policy_id]
                    control["Details"] = (
                        "Remediated since the previous assessment; the control now "
                        "meets the SCuBA requirement."
                    )
                    stats["improved"] += 1
                elif policy_id in REGRESSED:
                    control["Result"] = REGRESSED[policy_id]
                    control["Details"] = (
                        "Configuration drifted since the previous assessment; the "
                        "control no longer meets the SCuBA requirement."
                    )
                    stats["regressed"] += 1

                # Apply the baseline upgrade last, so the lookups above still
                # operate on the original identifiers.
                if policy_id in renames:
                    control["Control ID"] = renames[policy_id]
                    stats["renamed"] += 1

    meta = doc["MetaData"]
    # Capture the source UUID BEFORE overwriting it. Reading it afterwards made
    # DerivedFrom point at the new run's own identifier -- a self-referential
    # provenance record, which is worse than none at all.
    meta["DerivedFrom"] = meta.get("ReportUUID", "")
    meta["TimestampZulu"] = "2026-06-03T09:00:00.000Z"      # ~30 days later
    meta["ReportUUID"] = "b7e41f28-9c3d-4a15-8f62-1d4e7a0b5c93"
    meta["DataClassification"] = (
        "DERIVED FIXTURE - not a real second assessment. Generated from CISA's "
        "published sample report by scripts/make_followup_run.py to demonstrate "
        "posture drift across a baseline version change."
    )

    TARGET.write_text(json.dumps(doc, indent=2))
    print(f"wrote {TARGET.name}")
    print(f"  renumbered : {stats['renamed']} (CISA 1:1 migrations)")
    print(f"  improved   : {stats['improved']}")
    print(f"  regressed  : {stats['regressed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
