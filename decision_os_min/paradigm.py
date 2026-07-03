"""Legitimacy ⊥ Authority — the two-question pipeline, in the neutral kernel.

    Request → LEGITIMACY ("should this happen at all?") → AUTHORITY ("does this
    actor hold the capability?") → Execution → Audit

Two *different* questions, two layers, one invariant:

    LEGITIMACY may only DENY — it can never GRANT authority.
    AUTHORITY may never OVERRIDE a legitimacy DENY.

This is enforced by *structure*, not convention: the legitimacy check returns only
`(ok, reason)`. A `False` refuses before the kernel is ever consulted; a `True`
merely *permits the question to proceed* — it grants nothing. The kernel (authority)
runs only after legitimacy passes, so it cannot resurrect a denied action.

Value-neutral: the legitimacy *rule* is injected policy (FDK, a regulation, a
research theory) — never baked into the kernel. The kernel supplies the seam.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# A legitimacy policy: (action) -> (is_legitimate, reason). It may ONLY deny.
LegitimacyPolicy = Callable[[dict[str, Any]], "tuple[bool, str]"]


class LegitimacyAuthorityPipeline:
    def __init__(
        self,
        policy: dict[str, Any],
        *,
        audit_path: str,
        legitimacy: LegitimacyPolicy | None = None,
    ) -> None:
        from decision_os_min import DecisionOS  # lazy: defined in __init__

        self._authority = DecisionOS(policy, audit_path=audit_path)  # AuthGate role
        self._legitimacy = legitimacy

    @property
    def kernel_public_key(self) -> str:
        return self._authority.kernel.public_key_hex()

    def handle(
        self,
        action: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
    ) -> Any:
        from decision_os_min import Outcome  # lazy: defined in __init__

        # STAGE 1 — LEGITIMACY: "should this action happen at all?"  (may only DENY)
        if self._legitimacy is not None:
            ok, reason = self._legitimacy(action)
            if not ok:
                # A legitimacy denial is final. Authority is never consulted, so it
                # cannot override it. Recorded as a decision.
                cap = action.get("capability") or f"tool:{action.get('tool', '')}"
                self._authority.log.record(
                    action.get("actor", ""), cap.split("tool:")[-1],
                    "DENY", f"illegitimate: {reason}",
                )
                return Outcome(verdict="DENY", executed=False,
                               refused_reason=f"illegitimate: {reason}")

        # STAGE 2 — AUTHORITY: "does this actor hold the capability?"  (+ PEP + audit)
        # Legitimacy passing does NOT grant anything; the kernel still decides.
        return self._authority.handle(action, tools)
