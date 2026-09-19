"""Optional composition checks against a cited-fields receipt.

Not mint, not legitimacy, not on the default verify path. A foreign proof
is an *input*. Mismatch is a refuse. A pass does not mean the effect ran
and does not override a legitimacy DENY or empty-set DEFER.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .kernel import action_fingerprint

_PREIMAGE_FIELDS = (
    "artifact_hash",
    "artifact_type",
    "policy_version",
    "verdict",
    "source_class",
    "vantage_limitation",
)


class ReceiptRefused(ValueError):
    """The cited-fields proof is not a usable grant input."""


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cited_preimage(proof: dict[str, Any]) -> dict[str, Any]:
    missing = [k for k in _PREIMAGE_FIELDS if k not in proof]
    if missing:
        raise ReceiptRefused(f"proof missing cited fields: {missing}")
    return {k: proof[k] for k in _PREIMAGE_FIELDS}


def recompute_decision_ref(proof: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(cited_preimage(proof))).hexdigest()


def check_receipt_as_grant_input(
    proof: dict[str, Any],
    action: dict[str, Any],
) -> None:
    """Refuse unless the proof is self-consistent and names this effect.

    Does not verify a foreign signature (no trust in a live key server from
    this module). Signature verification belongs at the integrator, against a
    published key they pin.
    """
    claimed = proof.get("decision_ref")
    if not isinstance(claimed, str) or not claimed:
        raise ReceiptRefused("decision_ref missing")
    recomputed = recompute_decision_ref(proof)
    if claimed != recomputed:
        raise ReceiptRefused("decision_ref does not recompute from cited fields")
    artifact_hash = proof.get("artifact_hash")
    live = action_fingerprint(action)
    if artifact_hash != live:
        raise ReceiptRefused("artifact_hash does not match the effect being minted")
