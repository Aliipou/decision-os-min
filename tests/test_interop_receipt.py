"""Interop shape: a cited-fields receipt is an input, not a mint.

Passing ≠ the effect ran. These fixtures do not call a foreign HTTP API.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from decision_os_min.interop_receipt import (
    ReceiptRefused,
    check_receipt_as_grant_input,
    cited_preimage,
    recompute_decision_ref,
)
from decision_os_min.kernel import action_fingerprint


def _action():
    return {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {"to": "a@b.c"},
        "nonce": "n-1",
    }


def _proof_for(action: dict, **overlay):
    pre = {
        "artifact_hash": action_fingerprint(action),
        "artifact_type": "tool_call",
        "policy_version": "test-1",
        "verdict": "ALLOW",
        "source_class": "unit",
        "vantage_limitation": "external",
    }
    pre.update(overlay)
    body = json.dumps(pre, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**pre, "decision_ref": hashlib.sha256(body).hexdigest()}


def test_matching_receipt_is_accepted_as_input():
    action = _action()
    check_receipt_as_grant_input(_proof_for(action), action)


def test_tampered_decision_ref_is_refused():
    action = _action()
    proof = _proof_for(action)
    proof["decision_ref"] = "0" * 64
    with pytest.raises(ReceiptRefused, match="does not recompute"):
        check_receipt_as_grant_input(proof, action)


def test_receipt_for_other_effect_is_refused():
    action = _action()
    other = dict(action)
    other["payload"] = {"to": "evil@b.c"}
    with pytest.raises(ReceiptRefused, match="does not match the effect"):
        check_receipt_as_grant_input(_proof_for(action), other)


def test_recompute_is_from_cited_fields_not_the_wrapper():
    action = _action()
    proof = _proof_for(action)
    proof["noise"] = "ignored"
    assert recompute_decision_ref(proof) == proof["decision_ref"]
    assert "noise" not in cited_preimage(proof)
