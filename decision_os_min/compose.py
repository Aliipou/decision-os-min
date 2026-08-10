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


def normalize(verdict: str) -> str:
    """Map anything outside the lattice onto ``DENY``.

    R2 fix. Previously an unknown verdict *ranked* as DENY but was *returned
    verbatim*, with two consequences: (a) ``meet`` was not commutative off-lattice
    (``meet(DENY, "x") == "DENY"`` but ``meet("x", DENY) == "x"``), breaking the
    order-independence the whole design rests on; and (b) a consumer testing
    ``verdict == DENY`` — rather than ``verdict not in PERMITTING`` — read an
    off-lattice string as "not a denial". Normalizing at the boundary means the
    composed verdict is ALWAYS a member of ``VERDICTS``."""
    return verdict if verdict in _RANK else DENY


def meet(a: str, b: str) -> str:
    """The lattice meet: the more restrictive of two verdicts (DENY absorbing).

    Both operands are normalized first, so the result is always in the lattice and
    the operation is commutative for arbitrary input, not just well-formed input."""
    a, b = normalize(a), normalize(b)
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
        return {"verdict": normalize(out), "reason": "", "action_ref": ref}
    if not isinstance(out, dict):
        # An evaluator that returns None/42/[...] is malformed. Previously
        # ``dict(out)`` raised out of ``decide()`` with an unstable exception type,
        # so a caller could not reliably catch-and-deny (Invariant 4 was enforced
        # only inside the evaluators.py wrappers, not at the kernel boundary).
        return {
            "verdict": DENY,
            "reason": f"malformed evaluator output of type {type(out).__name__} (fail-closed)",
            "action_ref": ref,
        }
    d = dict(out)
    verdict = d.get("verdict", DENY)  # malformed evaluator output -> fail closed
    d["verdict"] = normalize(verdict) if isinstance(verdict, str) else DENY
    d.setdefault("reason", "")
    # R1/F4: `action_ref` is the kernel's to state, never the evaluator's. It was
    # `setdefault`, so a governing evaluator could write an identity field of a
    # signed decision (and silently render a permitting decision unexecutable).
    d["action_ref"] = ref
    return d


# The ONLY keys an evaluator may contribute to the composed decision. Everything
# else — token_id, capability, token_expires_at, action_binding, issued_by,
# transformed_payload, containment — is the kernel's to state, and is stripped.
EVALUATOR_CONTRIBUTABLE = frozenset({"verdict", "reason", "action_ref"})


def sanitize(d: dict[str, Any]) -> dict[str, Any]:
    """Strip an evaluator's decision down to what it is allowed to say.

    R1 fix, and the core of the antitone argument. ``more_restrictive`` used to
    adopt an evaluator's ENTIRE dict when it governed, so an untrusted, veto-only
    plugin could inject fields that never enter the meet at all: a forged
    ``token_id``/``capability`` (which the kernel then SIGNED), its own
    ``containment`` allowlist, or a ``transformed_payload`` that became the
    executed payload while ``action_binding`` still committed to the original.
    The meet was antitone; the decision dict was not. It is now: an evaluator
    contributes a verdict and a reason, and nothing else.

    Consequence, stated plainly: an evaluator therefore CANNOT carry an obligation
    (a redaction, a sandbox spec). That is deliberate — obligations do not yet
    compose (COMPOSITION.md §7, and the design in OBLIGATIONS.md). Silently
    honouring an unverified obligation is worse than refusing to carry one."""
    return {k: v for k, v in d.items() if k in EVALUATOR_CONTRIBUTABLE}


def more_restrictive(d1: dict[str, Any], d2: dict[str, Any]) -> dict[str, Any]:
    """Return whichever decision dict carries the more-restrictive verdict; ties
    keep ``d1`` (so the authority verdict and its obligations win a tie)."""
    r1 = _rank(normalize(str(d1.get("verdict", DENY))))
    r2 = _rank(normalize(str(d2.get("verdict", DENY))))
    return d2 if r2 > r1 else d1
