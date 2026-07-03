"""Advisors — the FDK layer, shrunk to an OPTIONAL plugin.

In the full system, fdk-research is a whole repo. Here it is what it should be at
the core: a plain function `(action) -> threat_class | None`. Pass one to
`kernel.decide(action, advisor=...)` or `DecisionOS.handle(action, tools,
advisor=...)`. Omit it and the system works fully. This one is a trivial
deterministic example; a real advisor (ML, heuristics, whatever) is a drop-in
replacement — and can NEVER exert authority, because the kernel decides.
"""

from __future__ import annotations

from typing import Any

# Actors known to be bad -> "malicious" (the kernel maps that to CONTAIN).
_KNOWN_BAD = {"agent:evil", "agent:known-bad"}


def simple_threat_advisor(action: dict[str, Any]) -> str | None:
    """Suggest a threat class from cheap signals. Advisory ONLY."""
    actor = action.get("actor", "")
    if actor in _KNOWN_BAD:
        return "malicious"
    # crude probing heuristic: asking for a capability the name doesn't match
    cap = action.get("capability", "")
    if cap and action.get("tool") and cap != f"tool:{action['tool']}":
        return "suspicious"
    return None
