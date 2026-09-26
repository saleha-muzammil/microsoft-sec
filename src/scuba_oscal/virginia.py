"""Virginia SEC530: what a SCuBA failure means for a Commonwealth institution.

CISA's SCuBA baselines are federal guidance. Virginia's public bodies —
including every public college, university and school division — are governed
by **SEC530**, VITA's Information Security Standard, which adopts NIST SP
800-53 Rev 5 and uses its control identifiers directly.

That shared identifier is the whole opportunity. We already map every SCuBA
policy to NIST controls using CISA's published crosswalk, so composing one more
hop answers a question no existing tool does:

    SCuBA policy -> (CISA crosswalk) -> NIST 800-53 -> SEC530

*"This ScubaGear failure is also a Virginia SEC530 obligation, and here is who
the Commonwealth says owns it."*

VITA publishes ``SEC530_Control_Summaries.xlsx``, whose ``IMPLEMENTED BY``
column assigns each control to the **Organization**, the **System**, both, or
records it as **withdrawn**. Withdrawal matters: where Virginia has withdrawn a
control the federal mapping points at, a SCuBA finding carries no corresponding
state obligation — a real divergence between two authorities governing the same
institution.

Parsed with the standard library only (``zipfile`` + ``ElementTree``), so this
adds no dependency. Nothing here is inferred by a model: it is an exact join on
control identifiers published by CISA and VITA respectively.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"

SOURCE_URL = (
    "https://www.vita.virginia.gov/media/vitavirginiagov/it-governance/psgs/"
    "docs/SEC530_Control_Summaries.xlsx"
)
STANDARD = "Virginia ITRM Standard SEC530, Information Security Standard"


class Ownership(str, Enum):
    ORGANIZATION = "organization"
    SYSTEM = "system"
    BOTH = "organization-and-system"
    WITHDRAWN = "withdrawn"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            Ownership.ORGANIZATION: "Organization",
            Ownership.SYSTEM: "System owner",
            Ownership.BOTH: "Organization and system owner",
            Ownership.WITHDRAWN: "Withdrawn by the Commonwealth",
            Ownership.UNKNOWN: "Not stated",
        }[self]


@dataclass(frozen=True)
class Sec530Control:
    control_id: str          # normalised, e.g. "ac-2.12"
    published_id: str        # as VITA writes it, e.g. "AC-2(12)"
    name: str
    ownership: Ownership
    withdrawal_note: str = ""

    @property
    def is_withdrawn(self) -> bool:
        return self.ownership is Ownership.WITHDRAWN


def _normalise(control_id: str) -> str:
    """"AC-2(12)" -> "ac-2.12". Matches parsers.mappings.normalise_control_id."""
    text = (control_id or "").strip()
    match = re.match(r"^([A-Za-z]{2})-(\d+)((?:\(\d+\))*)", text)
    if not match:
        return text.lower()
    family, number, enhancements = match.groups()
    out = f"{family.lower()}-{number}"
    for enh in re.findall(r"\((\d+)\)", enhancements or ""):
        out += f".{enh}"
    return out


def _classify(implemented_by: str) -> tuple[Ownership, str]:
    value = (implemented_by or "").strip()
    upper = value.upper()
    if upper.startswith("W:") or upper.startswith("W "):
        return Ownership.WITHDRAWN, value.split(":", 1)[-1].strip()
    if upper in {"O/S", "S/O", "O,S", "O AND S"}:
        return Ownership.BOTH, ""
    if upper == "O":
        return Ownership.ORGANIZATION, ""
    if upper == "S":
        return Ownership.SYSTEM, ""
    return Ownership.UNKNOWN, value


def _sheet_rows(archive: zipfile.ZipFile, target: str, shared: list[str]):
    candidates = [
        "xl/" + target.lstrip("/"),
        "xl/worksheets/" + target.split("/")[-1],
        target.lstrip("/"),
    ]
    path = next((c for c in candidates if c in archive.namelist()), None)
    if path is None:
        return
    root = ET.fromstring(archive.read(path))
    for row in root.iter(NS + "row"):
        cells = []
        for cell in row.iter(NS + "c"):
            value = cell.find(NS + "v")
            if value is not None:
                text = shared[int(value.text)] if cell.get("t") == "s" else (value.text or "")
            else:
                inline = cell.find(NS + "is")
                text = "".join(t.text or "" for t in inline.iter(NS + "t")) if inline is not None else ""
            cells.append(text.strip())
        yield cells


def parse_sec530(path: str | Path) -> dict[str, Sec530Control]:
    """Parse VITA's control-summary workbook into normalised control records."""
    archive = zipfile.ZipFile(Path(path))

    shared: list[str] = []
    if "xl/sharedStrings.xml" in archive.namelist():
        for si in ET.fromstring(archive.read("xl/sharedStrings.xml")).iter(NS + "si"):
            shared.append("".join(t.text or "" for t in si.iter(NS + "t")))

    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    targets = {r.get("Id"): r.get("Target") for r in rels}

    controls: dict[str, Sec530Control] = {}
    for sheet in workbook.iter(NS + "sheet"):
        name = sheet.get("name") or ""
        # Family tabs are two-letter codes; 'Info' is documentation.
        if not re.fullmatch(r"[A-Z]{2}", name):
            continue
        target = targets.get(sheet.get(REL_NS + "id"))
        if not target:
            continue
        for row in _sheet_rows(archive, target, shared):
            if len(row) < 3 or not row[0] or row[0].upper() == "CONTROL NUMBER":
                continue
            ownership, note = _classify(row[2])
            control_id = _normalise(row[0])
            # Base controls appear once; keep the first (most general) statement.
            controls.setdefault(
                control_id,
                Sec530Control(
                    control_id=control_id,
                    published_id=row[0],
                    name=row[1],
                    ownership=ownership,
                    withdrawal_note=note,
                ),
            )
    return controls


@dataclass(frozen=True)
class VirginiaObligation:
    """What one SCuBA policy means under Virginia's standard."""

    policy_id: str
    nist_controls: tuple[str, ...]
    sec530: tuple[Sec530Control, ...]

    @property
    def in_scope(self) -> tuple[Sec530Control, ...]:
        return tuple(c for c in self.sec530 if not c.is_withdrawn)

    @property
    def withdrawn(self) -> tuple[Sec530Control, ...]:
        return tuple(c for c in self.sec530 if c.is_withdrawn)

    @property
    def is_state_obligation(self) -> bool:
        """True when at least one mapped control is still in force in Virginia."""
        return bool(self.in_scope)

    @property
    def owners(self) -> tuple[str, ...]:
        seen: list[str] = []
        for control in self.in_scope:
            if control.ownership.label not in seen:
                seen.append(control.ownership.label)
        return tuple(seen)


def map_to_virginia(
    policy_ids: list[str],
    index,                              # parsers.mappings.MappingIndex
    sec530: dict[str, Sec530Control],
) -> list[VirginiaObligation]:
    """Compose SCuBA -> NIST -> SEC530 for the given policies."""
    out = []
    for policy_id in policy_ids:
        mapping = index.resolve(policy_id)
        # CISA's crosswalk cites statement-level ids (IA-5c, IA-5g) that both
        # normalise to the same control, so de-duplicate rather than listing a
        # control twice.
        seen: set[str] = set()
        controls = tuple(
            sec530[cid]
            for cid in mapping.nist_controls
            if cid in sec530 and not (cid in seen or seen.add(cid))
        )
        out.append(
            VirginiaObligation(
                policy_id=policy_id,
                nist_controls=mapping.nist_controls,
                sec530=controls,
            )
        )
    return out
