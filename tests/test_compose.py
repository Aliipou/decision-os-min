"""Co-equal evaluator composition — the veto invariant, made executable.

    "You can't do a bad act even if authorized; you can't do an authorized-good
     act if you lack authority."

Formally: ALLOW = authority ∧ legitimacy ∧ … . These tests pin (1) the lattice
meet, (2) the full authority×legitimacy truth table on the default handle() path,
and (3) the commit invariant: no token is minted before the composed verdict.
"""

from __future__ import annotations

from decision_os_min import DecisionOS
from decision_os_min.compose import (
    ALLOW,
    CONTAIN,
    DEFER,
    DENY,
    LIMIT,
    PERMITTING,
    compose,
    meet,
)

POLICY = {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"}


def _dos(tmp_path):
    return DecisionOS(POLICY, audit_path=str(tmp_path / "audit.jsonl"))


def _action(**kw):
    base = {
        "actor": "agent:bot", "tool": "send_email",
        "capability": "tool:send_email", "payload": {}, "nonce": "n-1",
    }
    base.update(kw)
    return base


def _tools():
    return {"send_email": lambda p: "sent", "wire_money": lambda p: "wired"}


def _legit(verdict: str):
    """A stand-in co-equal evaluator (an FDK legitimacy check would look like this)."""
    return lambda action: {"verdict": verdict, "reason": f"legitimacy:{verdict}"}


# --- the lattice ------------------------------------------------------------
def test_meet_deny_absorbs():
    assert meet(ALLOW, DENY) == DENY
    assert meet(DENY, ALLOW) == DENY
    assert meet(ALLOW, ALLOW) == ALLOW


def test_meet_restrictiveness_order():
    assert meet(ALLOW, LIMIT) == LIMIT
    assert meet(LIMIT, CONTAIN) == CONTAIN
    assert meet(CONTAIN, DEFER) == DEFER
    assert meet(DEFER, DENY) == DENY


def test_compose_identity_commutative_associative():
    assert compose([]) == ALLOW                       # identity
    assert compose([ALLOW, ALLOW]) == ALLOW
    assert compose([ALLOW, DENY, ALLOW]) == DENY
    assert compose([ALLOW, DENY]) == compose([DENY, ALLOW])            # commutative
    assert compose([compose([ALLOW, LIMIT]), CONTAIN]) == compose(
        [ALLOW, compose([LIMIT, CONTAIN])]
    )                                                                  # associative


def test_unknown_verdict_fails_closed():
    # A malformed evaluator verdict can only make the outcome MORE restrictive.
    assert compose(["ALLOW", "WAT"]) not in PERMITTING


# --- authority × legitimacy truth table (default handle() path) -------------
def test_allow_allow_executes(tmp_path):
    out = _dos(tmp_path).handle(_action(), _tools(), evaluators=[_legit(ALLOW)])
    assert out.verdict == ALLOW and out.executed and out.output == "sent"


def test_allow_authority_but_legitimacy_deny_is_vetoed(tmp_path):
    # THE fix: an authorized action a legitimacy evaluator forbids must NOT run.
    out = _dos(tmp_path).handle(_action(), _tools(), evaluators=[_legit(DENY)])
    assert out.verdict == DENY and not out.executed


def test_unauthorized_but_legitimate_is_denied(tmp_path):
    # Legitimacy ALLOW cannot grant an authority the actor does not hold.
    out = _dos(tmp_path).handle(
        _action(tool="wire_money", capability="tool:wire_money"),
        _tools(),
        evaluators=[_legit(ALLOW)],
    )
    assert out.verdict == DENY and not out.executed


def test_deny_deny_is_denied(tmp_path):
    out = _dos(tmp_path).handle(
        _action(tool="wire_money", capability="tool:wire_money"),
        _tools(),
        evaluators=[_legit(DENY)],
    )
    assert out.verdict == DENY and not out.executed


def test_defer_beats_permit(tmp_path):
    out = _dos(tmp_path).handle(_action(), _tools(), evaluators=[_legit(DEFER)])
    assert out.verdict == DEFER and not out.executed


# --- the commit invariant ---------------------------------------------------
def test_no_token_minted_on_legitimacy_deny(tmp_path):
    # Invariant: no capability token exists before the composed verdict permits.
    result = _dos(tmp_path).kernel.decide(_action(), evaluators=[_legit(DENY)])
    assert result["token"] is None
    assert "token_id" not in result["decision"]


def test_bare_string_evaluator_verdict(tmp_path):
    # An evaluator may return a bare verdict string, not just a decision dict.
    out = _dos(tmp_path).handle(_action(), _tools(), evaluators=[lambda a: DENY])
    assert out.verdict == DENY and not out.executed


def test_malformed_evaluator_fails_closed(tmp_path):
    # A dict with no "verdict" is treated as DENY, never silently permitted.
    out = _dos(tmp_path).handle(
        _action(), _tools(), evaluators=[lambda a: {"reason": "oops, no verdict"}]
    )
    assert out.verdict == DENY and not out.executed


def test_authority_only_still_works_without_evaluators(tmp_path):
    # Backward compatibility: the seam is default-off.
    out = _dos(tmp_path).handle(_action(), _tools())
    assert out.verdict == ALLOW and out.executed


def test_extra_evaluator_can_be_added_n_ary(tmp_path):
    # compose(V1..Vn): three evaluators, one DENY dominates.
    out = _dos(tmp_path).handle(
        _action(), _tools(),
        evaluators=[_legit(ALLOW), _legit(ALLOW), _legit(DENY)],
    )
    assert out.verdict == DENY and not out.executed
