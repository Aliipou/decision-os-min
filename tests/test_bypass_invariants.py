"""BYPASS INVARIANT PACK — deliberately try to execute without the constitution.

Claim under test (security boundary, not policy preference):

    ¬PEP(e)  ⇒  ¬Execute(e)
    Execute(e) ⇒ PEP(e) ∧ Legitimate(e) ∧ Authorized(e)

Scope honesty:
  * MEDIATED path (kernel.decide → Executor / Governor wrapper): many attacks CLOSED.
  * PROCESS / OS path (raw callable, unwrapped tool, side channel): OPEN — FAIL.
    Holding a reference to the underlying tool still runs effects. That is adoption
    friction, not a non-bypassable infrastructure primitive.

Do NOT call this pack green evidence for "non-bypassable AI infrastructure".
"""

from __future__ import annotations

import copy

import pytest

from decision_os_min import (
    DecisionOS,
    ExecutionRefused,
    GovernanceRefused,
    Governor,
    set_actor,
)
from decision_os_min.compose import DENY
from decision_os_min.evaluators import legitimacy
from decision_os_min.spentstore import InMemorySpentStore

POLICY = {
    "grants": {
        "agent:bot": ["tool:send_email"],
        "agent:deputy": ["tool:send_email"],
    },
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "default": "deny",
}


def _dos(tmp_path, name="audit.jsonl"):
    return DecisionOS(POLICY, audit_path=str(tmp_path / name))


def _action(**kw):
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {"to": "ok@example.com", "body": "hi"},
        "nonce": "n-1",
    }
    base.update(kw)
    return base


def _legit_block_blocked_domain(action):
    to = str(action.get("payload", {}).get("to", ""))
    if to.endswith("@blocked.test"):
        return (False, "LEGITIMACY: recipient domain blocked")
    return (True, "ok")


# ---------------------------------------------------------------------------
# BI-1 Direct invocation (PROCESS scope) — expected FAIL of OS-level claim
# ---------------------------------------------------------------------------
def test_bi1_raw_tool_call_bypasses_constitution():
    """ATTACK: Agent → Tool (no PEP/FDK/AuthGate).

    RESULT: effect runs. Documents Non-bypassability(process): FAIL.
    Governor only protects the wrapped callable the host chooses to expose.
    """
    effects: list[str] = []

    def raw_send_email(**payload):
        effects.append(payload.get("to", ""))
        return "sent"

    # No DecisionOS, no PEP, no legitimacy — direct invocation.
    assert raw_send_email(to="evil@blocked.test", body="exfil") == "sent"
    assert effects == ["evil@blocked.test"]


def test_bi1b_unwrapped_reference_survives_governor(tmp_path):
    """ATTACK: keep __wrapped__ / original fn after Governor.tool().

    RESULT: unwrapped call executes without kernel. Adoption-scoped only.
    """
    effects: list[str] = []

    def impl(to: str, body: str) -> str:
        effects.append(to)
        return f"sent:{to}"

    gov = Governor(
        POLICY,
        audit_path=str(tmp_path / "gov.jsonl"),
        evaluators=[legitimacy(_legit_block_blocked_domain)],
    )
    governed = gov.tool(
        "send_email",
        capability="tool:send_email",
        purpose="support_reply",
        data_labels=["customer_support"],
    )(impl)

    set_actor("agent:bot")
    with pytest.raises(GovernanceRefused):
        governed(to="x@blocked.test", body="no")

    # Bypass: call the original implementation directly.
    assert impl(to="x@blocked.test", body="yes") == "sent:x@blocked.test"
    assert "x@blocked.test" in effects


# ---------------------------------------------------------------------------
# BI-2 Mediated path: legitimacy DENY ⇒ no token, no effect
# ---------------------------------------------------------------------------
def test_bi2_legitimacy_deny_blocks_even_when_authorized(tmp_path):
    dos = _dos(tmp_path)
    ran: list[dict] = []
    tools = {"send_email": lambda p: ran.append(p) or "sent"}
    out = dos.handle(
        _action(payload={"to": "x@blocked.test", "body": "hi"}),
        tools,
        evaluators=[legitimacy(_legit_block_blocked_domain)],
    )
    assert out.verdict == DENY
    assert out.executed is False
    assert ran == []
    # No live token on a composed DENY.
    result = dos.kernel.decide(
        _action(nonce="n-2", payload={"to": "x@blocked.test", "body": "hi"}),
        evaluators=[legitimacy(_legit_block_blocked_domain)],
    )
    assert result["token"] is None
    assert result["decision"]["verdict"] == DENY


# ---------------------------------------------------------------------------
# BI-3 Replay — one-time token must make second execute impossible
# ---------------------------------------------------------------------------
def test_bi3_replay_old_authorization_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISION_OS_SPENT_DIR", str(tmp_path / "spent"))
    dos = _dos(tmp_path)
    tools = {"send_email": lambda p: "sent"}
    action = _action()
    result = dos.kernel.decide(action)
    assert result["token"] is not None
    assert dos.executor.execute(action, result, tools) == "sent"
    with pytest.raises(ExecutionRefused, match="spent|replay"):
        dos.executor.execute(action, result, tools)


# ---------------------------------------------------------------------------
# BI-4 Capability / action substitution (confused deputy at PEP)
# ---------------------------------------------------------------------------
def test_bi4_cap_for_A_cannot_execute_action_B(tmp_path):
    """cap(A) ⇏ execute(B). Binding mismatch must refuse — not 'would have DENY'."""
    dos = _dos(tmp_path)
    action_a = _action(nonce="same", payload={"to": "a@ok.test", "body": "A"})
    action_b = _action(nonce="same", payload={"to": "b@ok.test", "body": "B"})
    result = dos.kernel.decide(action_a)
    assert result["decision"]["verdict"] in ("ALLOW", "LIMIT")
    with pytest.raises(ExecutionRefused, match="binding mismatch"):
        dos.executor.execute(action_b, result, {"send_email": lambda p: "sent"})


def test_bi4b_legitimacy_reevaluated_per_action_not_cached_cap(tmp_path):
    """After ALLOW for A, B with same actor/tool but illegitimate payload must re-gate."""
    dos = _dos(tmp_path)
    tools = {"send_email": lambda p: "sent"}
    evals = [legitimacy(_legit_block_blocked_domain)]
    ok = dos.handle(_action(nonce="a1", payload={"to": "ok@ex.com", "body": "A"}), tools, evaluators=evals)
    assert ok.executed is True
    bad = dos.handle(
        _action(nonce="a2", payload={"to": "x@blocked.test", "body": "B"}),
        tools,
        evaluators=evals,
    )
    assert bad.verdict == DENY and bad.executed is False


# ---------------------------------------------------------------------------
# BI-5 Privilege escalation — low grant must not unlock high tool
# ---------------------------------------------------------------------------
def test_bi5_privilege_escalation_refused(tmp_path):
    dos = _dos(tmp_path)
    ran: list[str] = []
    tools = {
        "send_email": lambda p: ran.append("email") or "sent",
        "wire_money": lambda p: ran.append("wire") or "wired",
    }
    out = dos.handle(
        _action(tool="wire_money", capability="tool:wire_money", nonce="esc-1"),
        tools,
        evaluators=[legitimacy(lambda a: (True, "fine"))],
    )
    assert out.verdict == DENY and not out.executed
    assert ran == []


# ---------------------------------------------------------------------------
# BI-6 Confused deputy — privileged component must not run ghost actor's will
# ---------------------------------------------------------------------------
def test_bi6_confused_deputy_ghost_actor_denied(tmp_path):
    dos = _dos(tmp_path)
    out = dos.handle(
        _action(actor="agent:ghost", nonce="cd-1"),
        {"send_email": lambda p: "sent"},
        evaluators=[legitimacy(lambda a: (True, "ok"))],
    )
    assert out.verdict == DENY and not out.executed


# ---------------------------------------------------------------------------
# BI-7 Forged / unsigned path — execute without authentic PEP decision
# ---------------------------------------------------------------------------
def test_bi7_execute_without_valid_signature_impossible(tmp_path):
    dos = _dos(tmp_path)
    result = dos.kernel.decide(_action())
    forged = copy.deepcopy(result)
    forged["signature"] = "ab" * 64
    with pytest.raises(ExecutionRefused, match="not authenticated"):
        dos.executor.execute(_action(), forged, {"send_email": lambda p: "sent"})


def test_bi7b_execute_without_token_impossible_on_deny(tmp_path):
    dos = _dos(tmp_path)
    result = dos.kernel.decide(_action(capability="tool:wire_money"))
    assert result["token"] is None
    with pytest.raises(ExecutionRefused):
        dos.executor.execute(
            _action(capability="tool:wire_money"),
            result,
            {"wire_money": lambda p: "wired"},
        )


# ---------------------------------------------------------------------------
# BI-8 Internal bypass class — second DecisionOS without shared spent store
#     can still spend the SAME signed token if stores diverge (replica gap).
#     With shared store: CLOSED. Document both.
# ---------------------------------------------------------------------------
def test_bi8_shared_spent_store_blocks_cross_executor_replay(tmp_path):
    store = InMemorySpentStore()
    dos = _dos(tmp_path)
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import Executor

    pub = dos.kernel.public_key_hex()
    ex1 = Executor(pub, HashLog(tmp_path / "a1.jsonl"), spent_store=store)
    ex2 = Executor(pub, HashLog(tmp_path / "a2.jsonl"), spent_store=store)
    action = _action(nonce="cross-1")
    result = dos.kernel.decide(action)
    tools = {"send_email": lambda p: "sent"}
    assert ex1.execute(action, result, tools) == "sent"
    with pytest.raises(ExecutionRefused, match="spent|replay"):
        ex2.execute(action, result, tools)


def test_bi8b_divergent_spent_stores_allow_double_spend(tmp_path):
    """ATTACK: Internal service A and B each with private spent stores.

    RESULT: same signed token executes twice — Non-bypassability(distributed): FAIL
    unless operators share spent-store / use a single PEP front door.
    """
    dos = _dos(tmp_path)
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import Executor

    pub = dos.kernel.public_key_hex()
    ex1 = Executor(pub, HashLog(tmp_path / "d1.jsonl"), spent_store=InMemorySpentStore())
    ex2 = Executor(pub, HashLog(tmp_path / "d2.jsonl"), spent_store=InMemorySpentStore())
    action = _action(nonce="div-1")
    result = dos.kernel.decide(action)
    tools = {"send_email": lambda p: "sent"}
    assert ex1.execute(action, result, tools) == "sent"
    # Second replica does NOT see the spend → effect runs again.
    assert ex2.execute(action, result, tools) == "sent"


# ---------------------------------------------------------------------------
# BI-9 Optional evaluators — without legitimacy plugin, authority-only path
#     still executes. Constitution is optional unless host wires it.
# ---------------------------------------------------------------------------
def test_bi9_constitution_optional_unless_wired(tmp_path):
    """Without evaluators, illegitimate payload still executes if authorized.

    Documents: FDK is not a mandatory security boundary of DecisionOS alone —
    it is a plugin. Infrastructure claim requires mandatory composition at the
    deployment PEP, not library availability.
    """
    dos = _dos(tmp_path)
    ran: list[str] = []
    out = dos.handle(
        _action(payload={"to": "x@blocked.test", "body": "hi"}),
        {"send_email": lambda p: ran.append("ran") or "sent"},
    )
    assert out.executed is True
    assert ran == ["ran"]


# ---------------------------------------------------------------------------
# Verdict summary (machine-readable for docs / CI narrative)
# ---------------------------------------------------------------------------
BYPASS_VERDICT = {
    "BI-1_direct_invocation_process": "FAIL",
    "BI-1b_unwrapped_after_governor": "FAIL",
    "BI-2_legitimacy_deny_mediated": "PASS",
    "BI-3_replay_shared_pep": "PASS",
    "BI-4_action_substitution": "PASS",
    "BI-4b_per_action_legitimacy": "PASS",
    "BI-5_privilege_escalation": "PASS",
    "BI-6_confused_deputy_actor": "PASS",
    "BI-7_forged_signature": "PASS",
    "BI-8_shared_spent_store": "PASS",
    "BI-8b_divergent_spent_stores": "FAIL",
    "BI-9_optional_constitution": "FAIL",
    "infrastructure_grade_non_bypassable_claim": "FAIL — do not claim",
}


def test_bi_verdict_table_is_honest():
    assert BYPASS_VERDICT["infrastructure_grade_non_bypassable_claim"].startswith("FAIL")
    fails = [k for k, v in BYPASS_VERDICT.items() if v == "FAIL"]
    assert "BI-1_direct_invocation_process" in fails
    assert "BI-9_optional_constitution" in fails
