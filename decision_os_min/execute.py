"""The Policy Enforcement Point: run an effect ONLY against a signed, action-bound
decision AND a valid, one-time token. No token -> no execution.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .kernel import CONTAIN, DEFER, DENY, LIMIT, action_fingerprint, verify


class ExecutionRefused(RuntimeError):
    pass


class Executor:
    def __init__(self, kernel_public_key: str) -> None:
        self._pub = kernel_public_key
        self._spent: set[str] = set()

    def execute(
        self,
        action: dict[str, Any],
        result: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
    ) -> Any:
        decision = result["decision"]

        # ONE verification authenticates BOTH the ruling and the folded-in token
        # (token_id / capability / expiry live inside the signed decision now).
        if not verify(decision, result.get("signature", ""), self._pub):
            raise ExecutionRefused("decision not authenticated by the kernel")

        # Mandatory mediation: the action handed to us must be the one authorized.
        if decision.get("action_binding") != action_fingerprint(action):
            raise ExecutionRefused(
                "action does not match the authorized decision (binding mismatch)"
            )

        verdict = decision["verdict"]
        if verdict in (DENY, DEFER) or not decision.get("token_id"):
            raise ExecutionRefused(f"verdict {verdict}: no execution")

        # Token semantics enforced from the SIGNED decision fields: expiry + a
        # one-time spend of the signed token_id (which an attacker cannot re-mint
        # without breaking the decision signature).
        try:
            if datetime.now(UTC) >= datetime.fromisoformat(decision["token_expires_at"]):
                raise ExecutionRefused("token expired")
        except (KeyError, ValueError):
            raise ExecutionRefused("token missing/invalid expiry") from None
        tid = decision["token_id"]
        if tid in self._spent:
            raise ExecutionRefused("token already spent (replay)")
        self._spent.add(tid)

        tool_name = decision["capability"].split("tool:")[-1]
        if verdict == CONTAIN:
            allowed = (decision.get("containment") or {}).get("allowed_tools", [])
            if tool_name not in allowed:
                raise ExecutionRefused(f"contained: '{tool_name}' not in allowlist {allowed}")

        fn = tools.get(tool_name)
        if fn is None:
            raise ExecutionRefused(f"no executor registered for tool '{tool_name}'")
        payload = decision.get("transformed_payload") if verdict == LIMIT else action.get("payload")
        return fn(payload or {})
