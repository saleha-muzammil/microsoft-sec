"""Deterministic OSCAL identifiers.

OSCAL requires a UUID on nearly every object. The obvious choice, ``uuid4``, is
wrong for this project: regenerating artifacts from identical input would
produce a completely different document every run, which would make git diffs
meaningless and posture-drift comparison impossible.

We use UUIDv5 (SHA-1 over a fixed namespace + a stable name) so that the same
logical object always receives the same UUID. Re-running the pipeline on
unchanged input is a byte-for-byte no-op.

This is safe against the OSCAL schema: the ``uuid`` datatype regex accepts
version nibble ``[45]``, i.e. both v4 and v5::

    ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$

v1/v3/v7 and the nil UUID are rejected by that regex, so v5 is the only
deterministic option available to us.
"""

from __future__ import annotations

import uuid

# Fixed project namespace. Derived once from a DNS name we control the meaning
# of, then hard-coded so it can never drift between runs or machines.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "scuba-oscal.cci-va.dev")


def det_uuid(*parts: str) -> str:
    """Return a stable UUIDv5 for the given logical identity.

    Parts are joined with a separator that cannot appear in a SCuBA policy ID,
    so ``det_uuid("control", "MS.AAD.1.1v1")`` can never collide with
    ``det_uuid("control.MS", "AAD.1.1v1")``.
    """
    if not parts:
        raise ValueError("det_uuid requires at least one part")
    name = "\x1f".join(parts)
    return str(uuid.uuid5(NAMESPACE, name))


def control_uuid(policy_id: str) -> str:
    return det_uuid("control", policy_id)


def observation_uuid(run_id: str, policy_id: str) -> str:
    return det_uuid("observation", run_id, policy_id)


def finding_uuid(run_id: str, policy_id: str) -> str:
    return det_uuid("finding", run_id, policy_id)


def risk_uuid(run_id: str, policy_id: str) -> str:
    return det_uuid("risk", run_id, policy_id)


def poam_item_uuid(run_id: str, policy_id: str) -> str:
    return det_uuid("poam-item", run_id, policy_id)
