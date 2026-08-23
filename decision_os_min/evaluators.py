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

from .compose import ALLOW, DENY, VERDICTS, Evaluator

# "Should this happen at all?" -> (is_legitimate, reason). It may ONLY deny: a
# True grants nothing (authority still decides); a False is an authoritative veto.
LegitimacyPolicy = Callable[[dict[str, Any]], "tuple[bool, str]"]


def legitimacy(policy: LegitimacyPolicy) -> Evaluator:
    """Adapt a boolean legitimacy policy into a **veto-only** `Evaluator`.

    Veto-only by construction: it returns `ALLOW` (which grants nothing beyond
    authority) or `DENY` (an authoritative veto) — never a permitting verdict that
    could widen authority. **Fail-closed:** if the policy raises (including
    ``SystemExit`` / ``KeyboardInterrupt`` from a misbehaving plugin), the action
    is DENIED, never silently permitted.
    """

    def evaluate(action: dict[str, Any]) -> dict[str, Any]:
        try:
            ok, reason = policy(action)
        except Exception as exc:  # fail closed
            return {"verdict": DENY, "reason": f"legitimacy error (fail-closed): {exc}"}
        except BaseException as exc:
            if isinstance(exc, GeneratorExit):
                raise
            return {
                "verdict": DENY,
                "reason": f"legitimacy BaseException (fail-closed): {type(exc).__name__}: {exc}",
            }
        return {
            "verdict": ALLOW if ok else DENY,
            "reason": reason or ("legitimate" if ok else "illegitimate"),
        }

    return evaluate


# "Does this actor hold the right to do this?" -> (verdict, reason). The verdict
# uses the lattice vocabulary of `compose.py` (ALLOW/LIMIT/CONTAIN/DEFER/DENY);
# an engine speaking another dialect (e.g. AuthGate's allow/deny/transform) is
# mapped by its own thin bridge, so this module stays dependency-free.
AuthorityEngine = Callable[[dict[str, Any]], "tuple[str, str]"]


def authority(engine: AuthorityEngine) -> Evaluator:
    """Adapt a **second, external authority engine** into a co-equal `Evaluator`.

    Convergence brick #2. Today an AuthGate deployment is a whole separate engine
    *stacked* after this one: engine A rules and MINTS A ONE-TIME TOKEN, then
    engine B is asked. If B refuses, A's capability has already been minted (and,
    in the stacked-PEP form, the effect already run) — the capability-leakage the
    token-mint-is-terminal-commit invariant forbids. Passed here instead, the
    external authority is folded in by `meet` BEFORE any mint, so its DENY costs
    nothing.

    It is **veto-only like every other evaluator**: composition is deny-dominant,
    so a permitting verdict from `engine` grants nothing this kernel's own
    authority ruling did not already grant — only this kernel mints. **Fail-closed
    twice over:** if the engine raises, DENY; if it returns a verdict outside the
    lattice, DENY rather than let an unrecognized string be treated as permission.
    """

    def evaluate(action: dict[str, Any]) -> dict[str, Any]:
        try:
            verdict, reason = engine(action)
        except Exception as exc:  # fail closed
            return {"verdict": DENY, "reason": f"authority error (fail-closed): {exc}"}
        except BaseException as exc:
            if isinstance(exc, GeneratorExit):
                raise
            return {
                "verdict": DENY,
                "reason": f"authority BaseException (fail-closed): {type(exc).__name__}: {exc}",
            }
        if verdict not in VERDICTS:
            return {
                "verdict": DENY,
                "reason": f"unknown authority verdict {verdict!r} (fail-closed)",
            }
        return {"verdict": verdict, "reason": reason or f"external authority: {verdict}"}

    return evaluate
