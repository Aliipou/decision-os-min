"""Convergence brick #2 — a SECOND authority engine belongs inside the composer,
not stacked behind the first.

Brick #1 (`test_evaluators.py`) retired the sequential *legitimacy* stage. This one
takes the harder case: two **authority** engines (this kernel + an external AuthGate
deployment). Stacked, engine A rules and mints a one-time capability before engine B
is ever asked, so B's refusal arrives after the mint — capability leakage. Composed
via `authority(...)`, both verdicts meet BEFORE the mint.

What is proved here:
  1. EQUIVALENCE  — composed verdict == the stacked pair's verdict, whole truth table.
  2. COMMUTATIVITY — evaluator order carries no semantic content (only latency).
  3. NON-LEAK     — the stacked form mints a token the second engine then vetoes;
                    the composed form mints nothing. This is the strict improvement.
  4. FAIL-CLOSED  — a raising engine, and an off-lattice verdict, both DENY.
  5. VETO-ONLY    — an external ALLOW cannot resurrect this kernel's own DENY.
  6. REAL PARITY  — the same, against the actual `authgate_gate.PolicyEngine`
                    (skipped when that sibling repo is not importable).
"""

from __future__ import annotations

import pytest

from decision_os_min import DecisionOS, Kernel
from decision_os_min.compose import ALLOW, CONTAIN, DEFER, DENY, LIMIT, PERMITTING, meet
from decision_os_min.evaluators import authority

# This kernel's own authority: the bot may send email, nothing else.
POLICY = {"grants": {"agent:bot": ["tool:send_email"]}, "default": "allow"}


def _action(**kw):
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "payload": {"to": "x@ok.test"},
        "nonce": "n-1",
    }
    base.update(kw)
    return base


HOST_ALLOWS = _action()
HOST_DENIES = _action(tool="wire_money", capability="tool:wire_money", nonce="n-2")


def _external(verdict):
    """An external authority engine that always returns `verdict`."""
    return lambda action: (verdict, f"external says {verdict}")


def _stacked(kernel, action, verdict):
    """The status quo: engine A decides (and mints), THEN engine B is consulted.
    Returns (composed_verdict, token_minted_by_A)."""
    a = kernel.decide(action)
    return meet(a["decision"]["verdict"], verdict), a["token"]


@pytest.mark.parametrize("external", [ALLOW, LIMIT, CONTAIN, DEFER, DENY])
@pytest.mark.parametrize("action", [HOST_ALLOWS, HOST_DENIES], ids=["host_allows", "host_denies"])
def test_composed_matches_stacked_verdict(action, external):
    """1. EQUIVALENCE — one engine composing two evaluators agrees with two
    stacked engines on every cell of the truth table."""
    kernel = Kernel(POLICY)
    stacked_verdict, _ = _stacked(kernel, action, external)
    composed = kernel.decide(action, evaluators=[authority(_external(external))])
    assert composed["decision"]["verdict"] == stacked_verdict


@pytest.mark.parametrize("action", [HOST_ALLOWS, HOST_DENIES], ids=["host_allows", "host_denies"])
def test_evaluator_order_is_semantically_empty(action):
    """2. COMMUTATIVITY — `meet` is commutative, so no evaluator is 'the final
    word'. Any ordering claim about the pipeline is a performance claim only."""
    kernel = Kernel(POLICY)
    a, b = authority(_external(DEFER)), authority(_external(LIMIT))
    assert (
        kernel.decide(action, evaluators=[a, b])["decision"]["verdict"]
        == kernel.decide(action, evaluators=[b, a])["decision"]["verdict"]
    )


def test_stacking_leaks_a_capability_that_composition_never_mints():
    """3. NON-LEAK — the security argument for converging, not just a tidiness
    argument. Stacked: engine A mints a live one-time capability for an action
    engine B then refuses. Composed: the veto lands before the mint."""
    kernel = Kernel(POLICY)
    stacked_verdict, leaked = _stacked(kernel, HOST_ALLOWS, DENY)
    assert stacked_verdict == DENY
    assert leaked is not None and leaked["token_id"]  # minted for a refused action

    composed = kernel.decide(HOST_ALLOWS, evaluators=[authority(_external(DENY))])
    assert composed["decision"]["verdict"] == DENY
    assert composed["token"] is None
    assert "token_id" not in composed["decision"]


def test_permitting_external_verdict_still_mints_exactly_one_token():
    """The converse of the non-leak test: composition must not become so cautious
    that a genuinely permitted action loses its capability."""
    kernel = Kernel(POLICY)
    composed = kernel.decide(HOST_ALLOWS, evaluators=[authority(_external(ALLOW))])
    assert composed["decision"]["verdict"] in PERMITTING
    assert composed["token"]["action_binding"] == composed["decision"]["action_binding"]


def test_fail_closed_on_raising_engine():
    """4a. A broken external authority DENIES; it never falls open."""

    def boom(action):
        raise RuntimeError("gate unreachable")

    out = authority(boom)(HOST_ALLOWS)
    assert out["verdict"] == DENY and "fail-closed" in out["reason"]
    assert Kernel(POLICY).decide(HOST_ALLOWS, evaluators=[authority(boom)])["token"] is None


@pytest.mark.parametrize("bogus", ["allow", "PERMIT", "", "ALLOW ", "yes"])
def test_fail_closed_on_off_lattice_verdict(bogus):
    """4b. A verdict outside the lattice is DENY — including `"allow"`, the
    lowercase dialect of a real neighbouring engine. Vocabulary drift between two
    engines must not be silently read as permission."""
    out = authority(_external(bogus))(HOST_ALLOWS)
    assert out["verdict"] == DENY and "unknown authority verdict" in out["reason"]


def test_external_allow_cannot_resurrect_a_host_deny():
    """5. VETO-ONLY / antitone — no evaluator can widen authority."""
    kernel = Kernel(POLICY)
    out = kernel.decide(HOST_DENIES, evaluators=[authority(_external(ALLOW))])
    assert out["decision"]["verdict"] == DENY
    assert out["token"] is None
    assert "lacks capability" in out["decision"]["reason"]  # the HOST's reason survives


def test_contain_from_an_external_engine_is_honoured(tmp_path):
    """A restricting-but-permitting external verdict must survive composition."""
    kernel = Kernel(POLICY)
    out = kernel.decide(HOST_ALLOWS, evaluators=[authority(_external(CONTAIN))])
    assert out["decision"]["verdict"] == CONTAIN
    assert out["token"] is not None  # CONTAIN permits, in a sandbox


def test_composed_engine_refuses_execution_end_to_end(tmp_path):
    """The full host path (kernel + PEP + audit), not just the kernel verdict."""
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "audit.jsonl"))
    tools = {"send_email": lambda p: "sent"}
    ok = dos.handle(_action(nonce="n-ok"), tools, evaluators=[authority(_external(ALLOW))])
    no = dos.handle(_action(nonce="n-no"), tools, evaluators=[authority(_external(DENY))])
    assert ok.executed and ok.verdict in PERMITTING
    assert not no.executed and no.verdict == DENY


# --- 6. Parity against the REAL neighbouring engine -------------------------
# Skipped rather than vendored: decision-os-min must keep depending on nothing but
# stdlib + cryptography, so this runs only where the sibling repo is importable.

_AG_POLICY = {
    "default": "deny",
    "purpose_bindings": {"support_data": ["support_reply"], "marketing_data": ["marketing"]},
}


def _authgate_bridge():
    """Map AuthGate's dialect (allow/deny/transform) onto the lattice. TRANSFORM
    is a minimized-but-permitted call, i.e. LIMIT."""
    ag = pytest.importorskip("authgate_gate", reason="sibling repo authgate-gate not importable")
    engine = ag.PolicyEngine(_AG_POLICY)
    mapping = {ag.Verdict.ALLOW: ALLOW, ag.Verdict.DENY: DENY, ag.Verdict.TRANSFORM: LIMIT}

    def evaluate(action):
        d = engine.evaluate(
            ag.Intent(
                actor=action.get("actor", ""),
                tool=action.get("tool", ""),
                action_purpose=action.get("action_purpose", ""),
                data_labels=tuple(action.get("data_labels") or ()),
                payload=dict(action.get("payload") or {}),
            )
        )
        return mapping[d.verdict], d.reason

    return evaluate


@pytest.mark.parametrize(
    "labels,purpose,expect_permitted",
    [
        (["support_data"], "support_reply", True),  # AuthGate allows, host allows
        (["marketing_data"], "support_reply", False),  # purpose mismatch -> AuthGate DENY
        (["unknown_data"], "support_reply", False),  # AuthGate default-deny
    ],
)
def test_real_authgate_composes_as_a_veto_only_evaluator(labels, purpose, expect_permitted):
    """6. The real AuthGate policy engine, adapted, yields the same verdict it
    would standing alone — and when it refuses, no token is minted."""
    bridge = _authgate_bridge()
    action = _action(data_labels=labels, action_purpose=purpose)
    standalone = bridge(action)
    out = Kernel(POLICY).decide(action, evaluators=[authority(bridge)])

    assert (out["decision"]["verdict"] in PERMITTING) is expect_permitted
    assert (out["token"] is not None) is expect_permitted
    if not expect_permitted:
        assert standalone[0] == DENY
        assert out["decision"]["reason"] == standalone[1]  # AuthGate's own reason survives
