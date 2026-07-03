"""The kernel: the single authority. Sign decisions, mint one-time tokens.

This is the distilled core of the multi-repo Decision OS — the ~30% that carries
the real security value, in one file with no cross-repo machinery. Deterministic;
stdlib + cryptography only.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# An advisor is an OPTIONAL plugin: given an action, it may suggest a threat
# class (e.g. "malicious"). It is advice, never authority — the kernel decides.
Advisor = Callable[[dict[str, Any]], "str | None"]

KERNEL_IDENTITY = "decision-os-min-kernel"

# Verdicts. ALLOW=as-is, DENY=refuse, LIMIT=minimized payload, CONTAIN=sandbox
# (advisory-driven), DEFER=escalate. PERMITTING mint a token.
ALLOW, DENY, LIMIT, CONTAIN, DEFER = "ALLOW", "DENY", "LIMIT", "CONTAIN", "DEFER"
PERMITTING = {ALLOW, LIMIT, CONTAIN}

_CONTAINMENT = {"sandbox": True, "network": "none", "allowed_tools": [], "time_limit_seconds": 5}


def _canonical(obj: dict[str, Any]) -> bytes:
    payload = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def action_fingerprint(action: dict[str, Any]) -> str:
    """sha256 committing a decision/token to the security-relevant action content
    (actor, capability, purpose, labels, payload) — so a signed authorization
    cannot be re-attached to a different action. Closes the confused-deputy gap."""
    normalized = {
        "actor": action.get("actor", ""),
        "capability": action.get("capability") or f"tool:{action.get('tool', '')}",
        "action_purpose": action.get("action_purpose", ""),
        "data_labels": sorted(action.get("data_labels") or []),
        "payload": action.get("payload") or {},
    }
    return hashlib.sha256(_canonical(normalized)).hexdigest()


def verify(obj: dict[str, Any], signature_hex: str, public_key_hex: str) -> bool:
    """True iff `obj` carries the kernel identity AND a valid kernel signature."""
    if obj.get("issued_by") != KERNEL_IDENTITY:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), _canonical(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


class Kernel:
    """The sole decision authority: holds the signing key and the policy."""

    def __init__(self, policy: dict[str, Any], _key: Ed25519PrivateKey | None = None) -> None:
        self._key = _key or Ed25519PrivateKey.generate()
        self._pub = self._key.public_key().public_bytes_raw().hex()
        self._grants: dict[str, list[str]] = policy.get("grants", {})
        self._bindings: dict[str, list[str]] = policy.get("purpose_bindings", {})
        self._redactions: list[dict[str, Any]] = policy.get("redactions", [])
        self._contain: set[str] = set(policy.get("contain_threat_classes", ["malicious"]))
        self._default_deny: bool = policy.get("default", "deny") == "deny"

    def public_key_hex(self) -> str:
        return self._pub

    def _sign(self, obj: dict[str, Any]) -> str:
        return self._key.sign(_canonical(obj)).hex()

    def _evaluate(self, action: dict[str, Any], threat_class: str | None) -> dict[str, Any]:
        actor = action.get("actor", "")
        ref = action.get("nonce") or action.get("action_ref") or ""
        cap = action.get("capability") or f"tool:{action.get('tool', '')}"
        tool = action.get("tool")

        def d(verdict: str, reason: str, **extra: Any) -> dict[str, Any]:
            return {"verdict": verdict, "reason": reason, "action_ref": ref, **extra}

        # ambiguity: capability and tool must agree if both are given.
        if action.get("capability") and tool and action["capability"] != f"tool:{tool}":
            return d(DENY, f"ambiguous: capability '{action['capability']}' != tool '{tool}'")
        # capability gate.
        grants = self._grants.get(actor, [])
        if "*" not in grants and cap not in grants:
            return d(DENY, f"actor '{actor}' lacks capability '{cap}'")
        # purpose binding — a hard DENY here DOMINATES containment (advisory never
        # loosens a verdict).
        for label in action.get("data_labels", []):
            allowed = self._bindings.get(label)
            if allowed is None:
                if self._default_deny:
                    return d(DENY, f"unknown data purpose '{label}' -> default-deny")
                continue
            if action.get("action_purpose") not in allowed:
                return d(DENY, f"purpose mismatch: '{label}' != '{action.get('action_purpose')}'")
        # containment — only for otherwise-permitted actions.
        if threat_class in self._contain:
            return d(CONTAIN, f"threat '{threat_class}' -> sandbox", containment=dict(_CONTAINMENT))
        # data minimization -> LIMIT.
        payload = dict(action.get("payload") or {})
        for rule in self._redactions:
            if rule.get("action_purpose") != action.get("action_purpose"):
                continue
            hit = [f for f in rule.get("redact_fields", []) if payload.get(f) not in (None, "")]
            if hit:
                for f in hit:
                    payload[f] = "[REDACTED]"
                return d(LIMIT, f"redacted {sorted(hit)}", transformed_payload=payload)
        return d(ALLOW, "all checks passed")

    def decide(
        self,
        action: dict[str, Any],
        threat_class: str | None = None,
        *,
        advisor: Advisor | None = None,
    ) -> dict[str, Any]:
        """Return {decision, signature, token}. The decision and token both bind
        the action fingerprint; token is None for non-permitting verdicts.

        `advisor` is an OPTIONAL plugin (e.g. an FDK threat classifier). Without
        it the kernel works fully; with it the kernel CONSULTS its suggestion but
        still makes the call. `advisor` takes precedence over an explicit
        `threat_class` when both are given."""
        if advisor is not None:
            threat_class = advisor(action)
        decision = self._evaluate(action, threat_class)
        decision["issued_by"] = KERNEL_IDENTITY
        decision["action_binding"] = action_fingerprint(action)
        token = None
        if decision["verdict"] in PERMITTING:
            # Fold the one-time capability grant INTO the decision so a SINGLE
            # signature authenticates both the ruling and the token. Previously the
            # token was signed separately -> two Ed25519 signs per decide() and two
            # verifies per execute(); the benchmark showed crypto dominates, so this
            # halves it with no loss of guarantees (token_id/capability/expiry are
            # all still signed).
            decision["capability"] = action.get("capability") or f"tool:{action.get('tool', '')}"
            decision["token_id"] = f"tok-{uuid.uuid4().hex[:12]}"
            decision["token_expires_at"] = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
        signature = self._sign(decision)  # ONE signature covers ruling + token
        if decision["verdict"] in PERMITTING:
            token = {  # convenience view only; its authority IS the signed decision
                "token_id": decision["token_id"],
                "actor": action.get("actor", ""),
                "capability": decision["capability"],
                "action_ref": decision["action_ref"],
                "action_binding": decision["action_binding"],
                "issued_by": KERNEL_IDENTITY,
                "expires_at": decision["token_expires_at"],
            }
        return {"decision": decision, "signature": signature, "token": token}
