"""Verdict composition — the meet of a bounded lattice, deny-dominant.

This is the concrete, minimal realization of the composition contract in
``contracts-spec/COMPOSITION.md``. Several independent evaluators (authority,
legitimacy, and — in future — safety/privacy/cost/...) each return a verdict; we
fold them into ONE verdict by the lattice **meet** (most-restrictive-wins), with
``DENY`` as the absorbing bottom. This runs BEFORE any capability token is minted,
so a ``DENY`` from any evaluator vetoes execution and no evaluator's ``ALLOW`` can
resurrect another's ``DENY``.

PRIOR ART — this module claims **no novelty**. Composing independent policy
verdicts by deny-overrides / lattice meet is long-established: XACML combining
algorithms; Bonatti, di Vimercati & Samarati, "An Algebra for Composing Access
Control Policies" (ACM TISSEC, 2002); Bruns & Huth, "Access control via Belnap
logic" (ACM TISSEC, 2011); Crampton & Morisset, PTaCL (POST, 2012). See
``COMPOSITION.md`` for the non-claims. This file is the base module of the
package: it imports nothing internal, and ``kernel.py`` builds on it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

# Verdicts. ALLOW=as-is, LIMIT=minimized payload, CONTAIN=sandbox, DEFER=escalate
# to a human, DENY=refuse. PERMITTING verdicts mint a one-time token.
ALLOW, DENY, LIMIT, CONTAIN, DEFER = "ALLOW", "DENY", "LIMIT", "CONTAIN", "DEFER"
PERMITTING = {ALLOW, LIMIT, CONTAIN}

# Restrictiveness lattice, least → most restrictive:
#     ALLOW ≺ LIMIT ≺ CONTAIN ≺ DEFER ≺ DENY
# `meet` returns the more-restrictive of two verdicts, so DENY is the absorbing
# bottom and ALLOW is the identity. An UNKNOWN verdict ranks as DENY (fail-closed):
# a malformed evaluator can only ever make the outcome more restrictive, never
# less. NOTE (documented non-claim): collapsing LIMIT ∧ CONTAIN to CONTAIN loses
# the redaction obligation; true obligation *union* is future work — see
# COMPOSITION.md §"Obligations".
_RANK = {ALLOW: 0, LIMIT: 1, CONTAIN: 2, DEFER: 3, DENY: 4}

# The lattice vocabulary. An adapter wrapping a foreign engine uses this to reject
# a verdict the lattice does not know, instead of letting an unrecognized string
# ride through as if it were permission.
VERDICTS = frozenset(_RANK)

# An Evaluator maps an action to a verdict. It may return a bare verdict string,
# or a decision dict ({"verdict", "reason", ...}) so its reason/obligations are
# carried through when it is the governing (most-restrictive) evaluator.
Evaluator = Callable[[dict[str, Any]], "dict[str, Any] | str"]


def _rank(verdict: str) -> int:
    return _RANK.get(verdict, _RANK[DENY])


def meet(a: str, b: str) -> str:
    """The lattice meet: the more restrictive of two verdicts (DENY absorbing)."""
    return a if _rank(a) >= _rank(b) else b


def compose(verdicts: Iterable[str]) -> str:
    """Fold ``meet`` over any number of verdicts. ``compose([]) == ALLOW`` (the
    identity), so an action with no evaluators is unconstrained by composition."""
    out = ALLOW
    for v in verdicts:
        out = meet(out, v)
    return out


def as_decision(out: dict[str, Any] | str, action: dict[str, Any]) -> dict[str, Any]:
    """Normalize an evaluator's return value into a decision dict. A bare string
    becomes a reasonless verdict; a dict missing ``verdict`` fails closed to DENY."""
    ref = action.get("nonce") or action.get("action_ref") or ""
    if isinstance(out, str):
        return {"verdict": out, "reason": "", "action_ref": ref}
    d = dict(out)
    d.setdefault("verdict", DENY)  # malformed evaluator output -> fail closed
    d.setdefault("reason", "")
    d.setdefault("action_ref", ref)
    return d


def more_restrictive(d1: dict[str, Any], d2: dict[str, Any]) -> dict[str, Any]:
    """Return whichever decision dict carries the more-restrictive verdict; ties
    keep ``d1`` (so the authority verdict and its obligations win a tie)."""
    return d2 if _rank(d2.get("verdict", DENY)) > _rank(d1.get("verdict", DENY)) else d1
