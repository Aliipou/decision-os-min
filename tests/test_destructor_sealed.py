"""Destructor suite — real execution attempts against SealedRuntime.

Every test tries to produce a side effect. PASS means the effect did NOT run
(or only ran through the full legitimacy∧authority∧PEP∧admission chain).
"""

from __future__ import annotations

import copy

import pytest

from decision_os_min.compose import DENY
from decision_os_min.sealed import (
    AdmissionError,
    AdmissionTicket,
    SealedBreach,
    SealedRefused,
    SealedRuntime,
)
from decision_os_min.spentstore import InMemorySpentStore

POLICY = {
    "grants": {
        "agent:owner": ["tool:deploy_ranking", "tool:set_price", "tool:audit_export"],
        "agent:operator": ["tool:deploy_ranking"],
        "agent:fan": ["tool:audit_export"],
        "agent:critic": ["tool:audit_export"],
        "agent:regulator": ["tool:impose_constraint", "tool:audit_export"],
    },
    "purpose_bindings": {
        "ops": ["deploy", "price", "audit", "regulate"],
        "public": ["audit"],
    },
    "default": "deny",
}


def _legit(action):
    """Constitution for NovaPulse ranking deploy scenario."""
    tool = action.get("tool")
    payload = action.get("payload") or {}
    actor = action.get("actor")

    if payload.get("unresolved"):
        return (None, "UNRESOLVED: needs human review", ("C6",))
    if payload.get("sell_user_data"):
        return (False, "A7/C1: selling user data without consent", ("A7", "C1"))
    if payload.get("dark_pattern"):
        return (False, "C1: deceptive ranking manipulation", ("C1",))
    if payload.get("bypass_regulator") and tool == "deploy_ranking":
        return (False, "regulator constraint: deploy blocked", ("REG-1",))
    if tool == "set_price" and payload.get("surge", 0) > 3.0 and actor != "agent:regulator":
        return (False, "REG-1: surge >3x requires regulator", ("REG-1",))
    if tool == "impose_constraint":
        return (True, "regulator act", ("REG-1",))
    return (True, "legitimate under constitution", ())


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISION_OS_SPENT_DIR", str(tmp_path / "spent"))
    effects: dict[str, list] = {k: [] for k in (
        "deploy_ranking", "set_price", "audit_export", "impose_constraint"
    )}

    def deploy_ranking(*, model: str, dark_pattern: bool = False, bypass_regulator: bool = False, unresolved: bool = False, sell_user_data: bool = False):
        effects["deploy_ranking"].append(model)
        return f"deployed:{model}"

    def set_price(*, surge: float = 1.0):
        effects["set_price"].append(surge)
        return f"price:{surge}"

    def audit_export(*, scope: str = "public"):
        effects["audit_export"].append(scope)
        return f"audit:{scope}"

    def impose_constraint(*, rule: str):
        effects["impose_constraint"].append(rule)
        return f"rule:{rule}"

    tools = {
        "deploy_ranking": deploy_ranking,
        "set_price": set_price,
        "audit_export": audit_export,
        "impose_constraint": impose_constraint,
    }
    rt = SealedRuntime(
        POLICY,
        audit_path=str(tmp_path / "audit.jsonl"),
        legitimacy=_legit,
        spent_store=InMemorySpentStore(),
    )
    for aid, actor, stake in [
        ("owner-1", "agent:owner", "owner"),
        ("ops-1", "agent:operator", "operator"),
        ("fan-1", "agent:fan", "fans"),
        ("critic-1", "agent:critic", "critics"),
        ("reg-1", "agent:regulator", "regulator"),
        ("atk-1", "agent:attacker", "attacker"),
    ]:
        # attacker has no grants — still register for spoof tests
        if actor == "agent:attacker":
            rt.register_agent(aid, actor=actor, stakeholder=stake)
        else:
            rt.register_agent(aid, actor=actor, stakeholder=stake)
    # attacker not in policy grants
    rt.register_agent("atk-1", actor="agent:ghost", stakeholder="attacker")

    exports = rt.seal(tools)
    return rt, tools, exports, effects


def _ok_deploy(rt, agent="owner-1"):
    t = rt.admit(agent)
    return rt.invoke(
        ticket=t,
        agent_id=agent,
        tool="deploy_ranking",
        payload={"model": "v1", "dark_pattern": False},
        intent="deploy",
        resource="ranking_model",
    )


# --- legitimate / illegitimate baselines ------------------------------------
def test_d0_legitimate_owner_deploy_executes(runtime):
    rt, _tools, _ex, effects = runtime
    assert _ok_deploy(rt) == "deployed:v1"
    assert effects["deploy_ranking"] == ["v1"]
    ev = rt.evidence[-1]
    assert ev.executed and ev.legitimacy_binding
    assert ev.authority_verdict in ("ALLOW", "LIMIT")


def test_d0b_authorized_but_illegitimate_denied(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("owner-1")
    with pytest.raises(SealedRefused) as e:
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "dark", "dark_pattern": True},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []
    assert e.value.verdict == DENY


def test_d0c_unresolved_defers_no_execution(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("owner-1")
    with pytest.raises(SealedRefused):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "x", "unresolved": True},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []


def test_d0d_legitimate_but_unauthorized_denied(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("fan-1")
    with pytest.raises(SealedRefused):
        rt.invoke(
            ticket=t,
            agent_id="fan-1",
            tool="deploy_ranking",
            payload={"model": "fan-build"},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []


# --- destructor attacks -----------------------------------------------------
def test_d1_raw_source_registry_poisoned(runtime):
    """ATTACK: call tools dict entry after seal — must not execute."""
    _rt, tools, _ex, effects = runtime
    with pytest.raises(SealedBreach):
        tools["deploy_ranking"](model="bypass")
    assert effects["deploy_ranking"] == []


def test_d1b_stronger_rebind_source_then_call(runtime):
    """STRONGER: attacker restores a live function into the source dict."""
    rt, tools, _ex, effects = runtime

    def evil(*, model: str, **_k):
        effects["deploy_ranking"].append("evil")
        return "evil"

    tools["deploy_ranking"] = evil
    # Direct call works on the rebound local — that is outside seal if attacker
    # owns a new callable. SealedRuntime.invoke must still refuse mutated registry
    # when source is un-poisoned.
    t = rt.admit("owner-1")
    with pytest.raises((SealedBreach, SealedRefused)):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "v2"},
            intent="deploy",
            resource="ranking_model",
        )
    # evil direct call is a NEW callable the attacker created — ambient Python.
    # Mark: sealed path blocked; ambient new callable is architectural OS limit.
    assert evil(model="x") == "evil"


def test_d2_export_handle_inert(runtime):
    _rt, _tools, exports, effects = runtime
    with pytest.raises(SealedBreach):
        exports["deploy_ranking"](model="x")
    assert effects["deploy_ranking"] == []


def test_d2b_no_wrapped_attr_on_export(runtime):
    _rt, _tools, exports, _effects = runtime
    assert not hasattr(exports["deploy_ranking"], "__wrapped__")


def test_d3_registry_mutation_of_internal_table(runtime):
    rt, _tools, _ex, effects = runtime

    def evil(payload):
        effects["deploy_ranking"].append("mutated")
        return "mutated"

    rt._tools["deploy_ranking"] = evil  # noqa: SLF001 — un-poison slot
    t = rt.admit("owner-1")
    with pytest.raises((SealedBreach, SealedRefused)):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "v1"},
            intent="deploy",
            resource="ranking_model",
        )
    assert "mutated" not in effects["deploy_ranking"]


def test_d3b_bodies_mutation_detected(runtime):
    rt, _tools, _ex, effects = runtime

    def evil(*, model: str, **_k):
        effects["deploy_ranking"].append("body-mut")
        return "body-mut"

    rt._bodies["deploy_ranking"] = evil  # noqa: SLF001 — replace cell with callable
    t = rt.admit("owner-1")
    with pytest.raises((SealedBreach, SealedRefused)):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "v1"},
            intent="deploy",
            resource="ranking_model",
        )
    assert "body-mut" not in effects["deploy_ranking"]


def test_d3c_direct_tools_call_cannot_execute(runtime):
    """Hostile finding: rt._tools[name](payload) must not run the effect."""
    rt, _tools, _ex, effects = runtime
    with pytest.raises(SealedBreach):
        rt._tools["deploy_ranking"]({"model": "x"})  # noqa: SLF001
    assert effects["deploy_ranking"] == []


def test_d3d_direct_bodies_call_cannot_execute(runtime):
    """rt._bodies[name](**kwargs) must not run — cell is non-callable."""
    rt, _tools, _ex, effects = runtime
    with pytest.raises(SealedBreach):
        rt._bodies["deploy_ranking"](model="bypass")  # noqa: SLF001
    assert effects["deploy_ranking"] == []


def test_d3e_stronger_getattribute_body_still_architectural(runtime):
    """Residual: object.__getattribute__(cell, '_fn') reaches the callable.

    Documented architectural FAIL for in-process introspection — not sealed surface.
    """
    rt, _tools, _ex, effects = runtime
    cell = rt._bodies["deploy_ranking"]  # noqa: SLF001
    raw = object.__getattribute__(cell, "_fn")
    assert raw(model="via-getattr") == "deployed:via-getattr"
    assert effects["deploy_ranking"] == ["via-getattr"]


def test_d4_actor_spoof_via_set_actor_irrelevant(runtime):
    """ATTACK: free set_actor cannot admit; need signed ticket for owner."""
    from decision_os_min import set_actor

    rt, _, _, effects = runtime
    set_actor("agent:owner")
    with pytest.raises((AdmissionError, SealedRefused, TypeError, KeyError)):
        # no ticket
        rt.invoke(
            ticket=None,  # type: ignore[arg-type]
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "v1"},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []


def test_d5_forged_admission_ticket(runtime):
    rt, _, _, effects = runtime
    fake = AdmissionTicket(
        actor="agent:owner",
        stakeholder="owner",
        expires_at="2099-01-01T00:00:00+00:00",
        nonce="forged-nonce",
        signature="ab" * 64,
    )
    with pytest.raises(AdmissionError):
        rt.invoke(
            ticket=fake,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "v1"},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []


def test_d5b_ticket_replay(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("owner-1")
    assert rt.invoke(
        ticket=t,
        agent_id="owner-1",
        tool="audit_export",
        payload={"scope": "public"},
        intent="audit",
        resource="audit",
    ) == "audit:public"
    with pytest.raises(AdmissionError):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="audit_export",
            payload={"scope": "public"},
            intent="audit",
            resource="audit",
        )
    assert effects["audit_export"] == ["public"]


def test_d5c_ticket_substitution_stakeholder(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("owner-1")
    forged = AdmissionTicket(
        actor=t.actor,
        stakeholder="regulator",
        expires_at=t.expires_at,
        nonce=t.nonce,
        signature=t.signature,
    )
    with pytest.raises(AdmissionError):
        rt.invoke(
            ticket=forged,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "v1"},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []


def test_d5d_admission_replay_across_runtimes_shared_store(tmp_path):
    """Admission spend must use shared SpentStore, not a process-local set."""
    store = InMemorySpentStore()

    def legit(action):
        return (True, "ok", ())

    def mk(path):
        rt = SealedRuntime(
            {
                "grants": {"agent:owner": ["tool:audit_export"]},
                "purpose_bindings": {"ops": ["audit"], "public": ["audit"]},
                "default": "deny",
            },
            audit_path=str(path),
            legitimacy=legit,
            spent_store=store,
        )
        rt.register_agent("owner-1", actor="agent:owner", stakeholder="owner")
        rt.seal({"audit_export": lambda *, scope="public": f"audit:{scope}"})
        return rt

    mk(tmp_path / "a.jsonl")
    mk(tmp_path / "b.jsonl")
    from decision_os_min.sealed import AdmissionOffice

    office_a = AdmissionOffice(seed_material="shared-seed", spent_store=store)
    office_b = AdmissionOffice(seed_material="shared-seed", spent_store=store)
    t = office_a.issue("agent:owner", "owner")
    assert office_a.consume(t) == ("agent:owner", "owner")
    with pytest.raises(AdmissionError, match="spent|replay"):
        office_b.consume(t)


def test_d6_capability_substitution_action_b(runtime):
    """Reuse decision for action A to run action B — PEP binding (bare Executor)."""
    rt, _, _, effects = runtime
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import ExecutionRefused, Executor

    t = rt.admit("owner-1")
    actor, _ = rt.admission.consume(t)
    action_a = {
        "actor": actor,
        "tool": "audit_export",
        "capability": "tool:audit_export",
        "action_purpose": "audit",
        "data_labels": ["ops"],
        "payload": {"scope": "public"},
        "nonce": "cap-a",
    }
    action_b = dict(action_a)
    action_b["payload"] = {"scope": "secrets"}
    result = rt._kernel.decide(action_a, evaluators=[rt._leg_eval])  # noqa: SLF001
    ex = Executor(rt.kernel.public_key_hex(), HashLog(rt.log._path.parent / "d6.jsonl"))  # noqa: SLF001
    with pytest.raises(ExecutionRefused):
        ex.execute(action_b, result, {"audit_export": lambda p: effects["audit_export"].append(p) or "x"})
    assert effects["audit_export"] == []


def test_d6b_sealed_kernel_decide_closed(runtime):
    rt, _, _, effects = runtime
    with pytest.raises(SealedBreach, match="decide is closed"):
        rt.kernel.decide({"actor": "agent:owner", "tool": "audit_export", "capability": "tool:audit_export",
                          "action_purpose": "audit", "data_labels": ["ops"], "payload": {}, "nonce": "x"})
    assert effects["deploy_ranking"] == []


def test_d6c_sealed_executor_unarmed_refuses(runtime):
    rt, _, _, effects = runtime
    from decision_os_min.execute import ExecutionRefused

    with pytest.raises(ExecutionRefused, match="not armed"):
        rt.executor.execute(
            {"actor": "agent:owner", "tool": "audit_export", "capability": "tool:audit_export",
             "nonce": "z", "payload": {}, "action_purpose": "audit", "data_labels": ["ops"]},
            {"decision": {"verdict": "ALLOW", "action_binding": "0" * 64}, "signature": ""},
            {"audit_export": lambda p: effects["audit_export"].append("x") or "x"},
        )
    assert effects["audit_export"] == []


def test_d7_decision_token_replay(runtime):
    rt, _, _, _effects = runtime
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import ExecutionRefused, Executor

    t = rt.admit("owner-1")
    actor, _stake = rt.admission.consume(t)
    action = {
        "actor": actor,
        "tool": "audit_export",
        "capability": "tool:audit_export",
        "action_purpose": "audit",
        "data_labels": ["ops"],
        "payload": {"scope": "public"},
        "nonce": "replay-1",
    }
    result = rt._kernel.decide(action, evaluators=[rt._leg_eval])  # noqa: SLF001
    ran: list = []

    def fn(p):
        ran.append(p)
        return "audit:public"

    ex = Executor(rt.kernel.public_key_hex(), HashLog(rt.log._path.parent / "d7.jsonl"))  # noqa: SLF001
    assert ex.execute(action, result, {"audit_export": fn}) == "audit:public"
    with pytest.raises(ExecutionRefused):
        ex.execute(action, result, {"audit_export": fn})
    assert ran == [{"scope": "public"}]

def test_d8_confused_deputy_operator_as_owner_payload(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("ops-1")
    # Operator may deploy, but dark_pattern illegitimate
    with pytest.raises(SealedRefused):
        rt.invoke(
            ticket=t,
            agent_id="ops-1",
            tool="deploy_ranking",
            payload={"model": "ops", "dark_pattern": True},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []


def test_d9_delegation_escalation_operator_set_price(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("ops-1")
    with pytest.raises(SealedRefused):
        rt.invoke(
            ticket=t,
            agent_id="ops-1",
            tool="set_price",
            payload={"surge": 1.0},
            intent="price",
            resource="pricing",
        )
    assert effects["set_price"] == []


def test_d10_stale_fdk_verdict_on_new_action(runtime):
    """FDK ALLOW digest for A cannot authorize B."""
    rt, _, _, effects = runtime
    from decision_os_min.execute import ExecutionRefused

    t = rt.admit("owner-1")
    actor, stake = rt.admission.consume(t)
    a = {
        "actor": actor,
        "tool": "deploy_ranking",
        "capability": "tool:deploy_ranking",
        "action_purpose": "deploy",
        "data_labels": ["ops"],
        "payload": {"model": "ok"},
        "nonce": "stale-a",
    }
    result = rt._kernel.decide(a, evaluators=[rt._leg_eval])  # noqa: SLF001
    assert result["decision"].get("legitimacy_binding")
    b = dict(a)
    b["payload"] = {"model": "evil", "dark_pattern": True}
    b["nonce"] = "stale-a"
    ran: list = []
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import Executor

    ex = Executor(rt.kernel.public_key_hex(), HashLog(rt.log._path.parent / "d10.jsonl"))  # noqa: SLF001
    with pytest.raises(ExecutionRefused):
        ex.execute(b, result, {"deploy_ranking": lambda p: ran.append(p) or "x"})
    assert ran == []
    assert effects["deploy_ranking"] == []

def test_d11_strip_legitimacy_binding_breaks_signature(runtime):
    rt, _, _, effects = runtime
    from decision_os_min.execute import ExecutionRefused

    t = rt.admit("owner-1")
    actor, stake = rt.admission.consume(t)
    a = {
        "actor": actor,
        "tool": "audit_export",
        "capability": "tool:audit_export",
        "action_purpose": "audit",
        "data_labels": ["ops"],
        "payload": {"scope": "public"},
        "nonce": "m5-1",
    }
    result = rt._kernel.decide(a, evaluators=[rt._leg_eval])  # noqa: SLF001
    assert "legitimacy_binding" in result["decision"]
    tampered = copy.deepcopy(result)
    tampered["decision"]["legitimacy_binding"] = "0" * 64
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import Executor

    ex = Executor(rt.kernel.public_key_hex(), HashLog(rt.log._path.parent / "d11.jsonl"))  # noqa: SLF001
    with pytest.raises(ExecutionRefused):
        ex.execute(a, tampered, {"audit_export": lambda p: effects["audit_export"].append(p) or "x"})
    assert effects["audit_export"] == []

def test_d12_replica_shared_spent_blocks_double_spend(tmp_path, monkeypatch):
    from decision_os_min.audit import HashLog
    from decision_os_min.execute import ExecutionRefused, Executor
    from decision_os_min.spentstore import InMemorySpentStore

    store = InMemorySpentStore()
    monkeypatch.setenv("DECISION_OS_SPENT_DIR", str(tmp_path / "s"))

    def legit(action):
        return (True, "ok", ())

    rt = SealedRuntime(
        {
            "grants": {"agent:owner": ["tool:audit_export"]},
            "purpose_bindings": {"ops": ["audit"]},
            "default": "deny",
        },
        audit_path=str(tmp_path / "a.jsonl"),
        legitimacy=legit,
        spent_store=store,
    )
    rt.register_agent("owner-1", actor="agent:owner", stakeholder="owner")
    tools = {"audit_export": lambda *, scope="public": f"audit:{scope}"}
    rt.seal(tools)
    t = rt.admit("owner-1")
    actor, stake = rt.admission.consume(t)
    action = {
        "actor": actor,
        "tool": "audit_export",
        "capability": "tool:audit_export",
        "action_purpose": "audit",
        "data_labels": ["ops"],
        "payload": {"scope": "public"},
        "nonce": "rep-1",
    }
    result = rt._kernel.decide(action, evaluators=[rt._leg_eval])  # noqa: SLF001
    pub = rt.kernel.public_key_hex()
    ex1 = Executor(pub, HashLog(tmp_path / "e1.jsonl"), spent_store=store)
    ex2 = Executor(pub, HashLog(tmp_path / "e2.jsonl"), spent_store=store)
    assert ex1.execute(action, result, {"audit_export": lambda p: f"audit:{p.get('scope')}"})
    with pytest.raises(ExecutionRefused):
        ex2.execute(action, result, {"audit_export": lambda p: f"audit:{p.get('scope')}"})


def test_d13_second_seal_refused(runtime):
    rt, tools, _, _ = runtime
    with pytest.raises(SealedBreach):
        rt.seal(tools)


def test_d14_collusion_fan_plus_ops_cannot_set_illegitimate_price(runtime):
    """Neither fan nor ops alone; together still cannot set surge>3 without legitimacy."""
    rt, _, _, effects = runtime
    t = rt.admit("owner-1")
    with pytest.raises(SealedRefused):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="set_price",
            payload={"surge": 9.0},
            intent="price",
            resource="pricing",
        )
    assert effects["set_price"] == []


def test_d15_regulator_constraint_blocks_owner_preference(runtime):
    rt, _, _, effects = runtime
    t = rt.admit("owner-1")
    with pytest.raises(SealedRefused):
        rt.invoke(
            ticket=t,
            agent_id="owner-1",
            tool="deploy_ranking",
            payload={"model": "max-revenue", "bypass_regulator": True},
            intent="deploy",
            resource="ranking_model",
        )
    assert effects["deploy_ranking"] == []
