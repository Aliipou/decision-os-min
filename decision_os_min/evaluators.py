"""Co-equal evaluator adapters — turn a governance policy into an `Evaluator`.

An `Evaluator` (see `compose.py`) is `(action) -> verdict`, composed with the
authority verdict by deny-dominant meet. These adapters are the **plugin** side of
the ADR-0001 boundary: untrusted, veto-only, fail-closed. The canonical one wraps a
**legitimacy** policy (FDK, a regulation, a research theory) — the same role
`paradigm.LegitimacyPolicy` played *sequentially*, now expressed as a co-equal
plugin so authority and legitimacy compose in ONE kernel instead of two stacked
engines. See `../../contracts-spec/COMPOSITION.md` and ADR-0001.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .compose import ALLOW, DENY, Evaluator

# "Should this happen at all?" -> (is_legitimate, reason). It may ONLY deny: a
# True grants nothing (authority still decides); a False is an authoritative veto.
LegitimacyPolicy = Callable[[dict[str, Any]], "tuple[bool, str]"]


def legitimacy(policy: LegitimacyPolicy) -> Evaluator:
    """Adapt a boolean legitimacy policy into a **veto-only** `Evaluator`.

    Veto-only by construction: it returns `ALLOW` (which grants nothing beyond
    authority) or `DENY` (an authoritative veto) — never a permitting verdict that
    could widen authority. **Fail-closed:** if the policy raises, the action is
    DENIED, never silently permitted (a broken plugin can only restrict)."""

    def evaluate(action: dict[str, Any]) -> dict[str, Any]:
        try:
            ok, reason = policy(action)
        except Exception as exc:  # fail closed
            return {"verdict": DENY, "reason": f"legitimacy error (fail-closed): {exc}"}
        return {
            "verdict": ALLOW if ok else DENY,
            "reason": reason or ("legitimate" if ok else "illegitimate"),
        }

    return evaluate
