"""Legitimacy ⊥ Authority — the two-question pipeline, in the neutral kernel.

    Request → LEGITIMACY ("should this happen at all?") → AUTHORITY ("does this
    actor hold the capability?") → Execution → Audit

Two *different* questions, two layers, one invariant:

    LEGITIMACY may only DENY — it can never GRANT authority.
    AUTHORITY may never OVERRIDE a legitimacy DENY.

Structurally this pipeline is now a thin convenience over co-equal composition:
legitimacy is adapted via ``evaluators.legitimacy`` and folded by lattice meet
inside ``DecisionOS.handle``. Exceptions and veto reasons match the composed form.
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
        from decision_os_min.evaluators import legitimacy as adapt

        evaluators = [adapt(self._legitimacy)] if self._legitimacy is not None else None
        return self._authority.handle(action, tools, evaluators=evaluators)
