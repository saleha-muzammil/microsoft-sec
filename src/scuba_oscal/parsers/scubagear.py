"""Parse ScubaGear ``ScubaResults*.json`` into typed domain models.

Written against the real CISA-published sample report (ScubaGear v1.8.0), not
against documentation, because the two disagree in several places. Each
workaround below is for a defect verified in the actual file.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import Criticality, PolicyResult, Result, ScubaRun

# ScubaGear appends an HTML badge block to the human-readable requirement text:
#   "Legacy authentication SHALL be blocked.<div class='policy-indicators'>...</div>"
# It is presentation markup for the HTML report and must not leak into OSCAL
# control titles, so we cut the requirement at the first tag.
_HTML_TAIL = re.compile(r"<\s*(div|br|a|span|p)\b.*", re.IGNORECASE | re.DOTALL)

# SCuBA policy identifier: MS.<PRODUCT>.<group>.<policy>v<version>
POLICY_ID_RE = re.compile(r"^MS\.[A-Z0-9]+\.\d+\.\d+v\d+$")


def clean_requirement(raw: str) -> str:
    """Strip ScubaGear's HTML badge markup and collapse whitespace."""
    text = _HTML_TAIL.sub("", raw or "")
    text = re.sub(r"<[^>]+>", "", text)          # any stragglers
    return re.sub(r"\s+", " ", text).strip()


def clean_details(raw: Any) -> str:
    """Details may contain ``<br/>`` separators and nested markup."""
    if raw is None:
        return ""
    text = str(raw)
    text = re.sub(r"<\s*br\s*/?\s*>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def load_json(path: str | Path) -> dict[str, Any]:
    """Load a ScubaGear JSON file.

    ScubaGear writes UTF-8 **with a BOM**. ``encoding="utf-8"`` raises
    ``JSONDecodeError`` on the leading U+FEFF, so ``utf-8-sig`` is required.
    (The per-product ``IndividualReports/*.json`` files are UTF-16 LE instead;
    this loader sniffs for that case too.)
    """
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return json.loads(raw.decode("utf-16"))
    return json.loads(raw.decode("utf-8-sig"))


def _parse_timestamp(value: str) -> datetime:
    # e.g. "2026-05-04T17:15:48.307Z" -- fromisoformat rejects the trailing Z
    # on older Pythons, so normalise it to an explicit offset.
    return datetime.fromisoformat((value or "").replace("Z", "+00:00"))


def parse_run(path: str | Path) -> ScubaRun:
    """Parse a ``ScubaResults*.json`` file into a :class:`ScubaRun`."""
    doc = load_json(path)

    missing = {"MetaData", "Results"} - doc.keys()
    if missing:
        raise ValueError(
            f"{path}: not a ScubaGear results file (missing {sorted(missing)}). "
            f"Found top-level keys: {sorted(doc.keys())}"
        )

    meta = doc["MetaData"]
    policies: list[PolicyResult] = []

    # Results is product -> [group] -> Controls[], and group numbers are NOT
    # contiguous (e.g. EXO jumps from 7 to 13), so never infer them by index.
    for product, groups in doc["Results"].items():
        for group in groups:
            for control in group.get("Controls", []):
                # The field is "Control ID" WITH A SPACE. `PolicyId` exists only
                # in the intermediate TestResults.json, not here.
                policy_id = (control.get("Control ID") or "").strip()
                if not policy_id:
                    continue
                policies.append(
                    PolicyResult(
                        policy_id=policy_id,
                        requirement=clean_requirement(control.get("Requirement", "")),
                        result=Result.parse(control.get("Result", "")),
                        criticality=Criticality.parse(control.get("Criticality", "")),
                        details=clean_details(control.get("Details")),
                        product=product,
                        group_number=str(group.get("GroupNumber", "")),
                        group_name=group.get("GroupName", ""),
                    )
                )

    return ScubaRun(
        report_uuid=meta.get("ReportUUID", ""),
        tenant_id=meta.get("TenantId", ""),
        tenant_display_name=meta.get("DisplayName", ""),
        tenant_domain=meta.get("DomainName", ""),
        tool_version=meta.get("ToolVersion", ""),
        timestamp=_parse_timestamp(meta.get("TimestampZulu", "")),
        products_assessed=list(meta.get("ProductsAssessed", [])),
        policies=policies,
    )
