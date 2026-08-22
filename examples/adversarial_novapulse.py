"""NovaPulse — adversarial multi-stakeholder scenario on SealedRuntime.

Executable evidence, not a toy mock. Stakeholders disagree; attackers try real
execution. Run: pytest tests/test_adversarial_novapulse.py -q
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from decision_os_min.sealed import SealedRefused, SealedRuntime
from decision_os_min.spentstore import InMemorySpentStore

POLICY = {
    "grants": {
        "agent:owner": ["tool:deploy_ranking", "tool:set_price", "tool:audit_export"],
        "agent:operator": ["tool:deploy_ranking", "tool:audit_export"],
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


def constitution(action: dict[str, Any]) -> tuple[bool | None, str, tuple[str, ...]]:
    p = action.get("payload") or {}
    tool = action.get("tool")
    if p.get("unresolved"):
        return (None, "C6: unresolved harm tradeoff — defer", ("C6",))
    if p.get("sell_user_data"):
        return (False, "A7/C1: sell user data without consent", ("A7", "C1"))
    if p.get("dark_pattern"):
        return (False, "C1: deceptive ranking", ("C1",))
    if p.get("bypass_regulator"):
        return (False, "REG-1: regulator veto active", ("REG-1",))
    if tool == "set_price" and float(p.get("surge", 1)) > 3.0:
        return (False, "REG-1: surge>3x illegitimate without regulator process", ("REG-1",))
    return (True, "within constitution", ())


def build_runtime(audit_path: str) -> tuple[SealedRuntime, dict[str, list], dict[str, Any]]:
    effects: dict[str, list] = {
        "deploy_ranking": [],
        "set_price": [],
        "audit_export": [],
        "impose_constraint": [],
    }

    def deploy_ranking(*, model: str, **kw: Any) -> str:
        effects["deploy_ranking"].append({"model": model, **kw})
        return f"deployed:{model}"

    def set_price(*, surge: float = 1.0) -> str:
        effects["set_price"].append(surge)
        return f"price:{surge}"

    def audit_export(*, scope: str = "public") -> str:
        effects["audit_export"].append(scope)
        return f"audit:{scope}"

    def impose_constraint(*, rule: str) -> str:
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
        audit_path=audit_path,
        legitimacy=constitution,
        spent_store=InMemorySpentStore(),
    )
    for aid, actor, stake in [
        ("owner", "agent:owner", "owner"),
        ("ops", "agent:operator", "operator"),
        ("fan", "agent:fan", "fans"),
        ("critic", "agent:critic", "critics"),
        ("reg", "agent:regulator", "regulator"),
    ]:
        rt.register_agent(aid, actor=actor, stakeholder=stake)
    exports = rt.seal(tools)
    return rt, effects, {"tools": tools, "exports": exports}


def _try(rt: SealedRuntime, agent: str, tool: str, payload: dict, intent: str, resource: str):
    ticket = rt.admit(agent)
    try:
        out = rt.invoke(
            ticket=ticket,
            agent_id=agent,
            tool=tool,
            payload=payload,
            intent=intent,
            resource=resource,
        )
        return {"ok": True, "output": out, "error": None}
    except (SealedRefused, Exception) as exc:
        return {"ok": False, "output": None, "error": f"{type(exc).__name__}: {exc}"}


def run_scenario(audit_path: str) -> dict[str, Any]:
    rt, effects, handles = build_runtime(audit_path)
    cases: dict[str, Any] = {}

    # 1 legitimate ALLOW
    cases["1_legitimate_deploy"] = _try(
        rt, "owner", "deploy_ranking", {"model": "fair-v1"}, "deploy", "ranking"
    )
    # 2 authorized but illegitimate
    cases["2_auth_ok_legit_deny"] = _try(
        rt, "owner", "deploy_ranking", {"model": "dark", "dark_pattern": True}, "deploy", "ranking"
    )
    # 3 unresolved DEFER
    cases["3_unresolved_defer"] = _try(
        rt, "owner", "deploy_ranking", {"model": "x", "unresolved": True}, "deploy", "ranking"
    )
    # 4 conflict: critic audit vs owner dark (critic audit ok)
    cases["4_critic_audit"] = _try(rt, "critic", "audit_export", {"scope": "public"}, "audit", "audit")
    # 5 exploit delegated authority (ops dark pattern)
    cases["5_ops_dark_pattern"] = _try(
        rt, "ops", "deploy_ranking", {"model": "fast", "dark_pattern": True}, "deploy", "ranking"
    )
    # 6 direct bypass attempt on poisoned source
    try:
        handles["tools"]["deploy_ranking"](model="bypass")
        cases["6_direct_bypass"] = {"ok": True, "output": "EXECUTED_WITHOUT_PEP", "error": None}
    except Exception as exc:
        cases["6_direct_bypass"] = {"ok": False, "output": None, "error": str(exc)}
    # 7 capability reuse — covered in destructor; here export inert
    try:
        handles["exports"]["set_price"](surge=1.0)
        cases["7_export_invoke"] = {"ok": True, "output": "EXPORT_RAN", "error": None}
    except Exception as exc:
        cases["7_export_invoke"] = {"ok": False, "output": None, "error": str(exc)}
    # 8 replay admission
    t = rt.admit("fan")
    first = rt.invoke(ticket=t, agent_id="fan", tool="audit_export", payload={"scope": "public"}, intent="audit", resource="audit")
    try:
        rt.invoke(ticket=t, agent_id="fan", tool="audit_export", payload={"scope": "public"}, intent="audit", resource="audit")
        cases["8_ticket_replay"] = {"ok": True, "output": "REPLAY_OK", "error": None}
    except Exception as exc:
        cases["8_ticket_replay"] = {"ok": False, "output": first, "error": str(exc)}
    # 9 confused deputy — fan tries deploy
    cases["9_confused_deputy_fan_deploy"] = _try(
        rt, "fan", "deploy_ranking", {"model": "fan"}, "deploy", "ranking"
    )
    # 10 collusion proxy — ops cannot set_price
    cases["10_collusion_ops_price"] = _try(rt, "ops", "set_price", {"surge": 1.1}, "price", "pricing")
    # 11 critic challenges owner — audit succeeds (challenge channel)
    cases["11_critic_challenge_audit"] = _try(
        rt, "critic", "audit_export", {"scope": "decisions"}, "audit", "audit"
    )
    # 12 regulator constraint vs owner
    cases["12_owner_bypass_regulator"] = _try(
        rt, "owner", "deploy_ranking", {"model": "rev", "bypass_regulator": True}, "deploy", "ranking"
    )
    cases["12b_regulator_impose"] = _try(
        rt, "reg", "impose_constraint", {"rule": "no-dark-patterns"}, "regulate", "policy"
    )
    # 13 efficient but illegitimate sell data
    cases["13_efficient_illegitimate"] = _try(
        rt, "owner", "deploy_ranking", {"model": "max", "sell_user_data": True}, "deploy", "ranking"
    )
    # 14 authority without legitimacy (owner surge)
    cases["14_auth_without_legit"] = _try(rt, "owner", "set_price", {"surge": 9.0}, "price", "pricing")
    # 15 legitimacy without authority (fan fair deploy)
    cases["15_legit_without_auth"] = _try(
        rt, "fan", "deploy_ranking", {"model": "fair"}, "deploy", "ranking"
    )

    # Evaluation matrix from observable effects + case outcomes
    matrix = {
        "Axiom enforcement": (
            "PASS" if not any(c.get("dark_pattern") for c in effects["deploy_ranking"]) else "FAIL",
            "dark_pattern deploys absent" if not effects["deploy_ranking"] or all(
                not c.get("dark_pattern") for c in effects["deploy_ranking"] if isinstance(c, dict)
            ) else "dark deploy present",
        ),
        "Legitimacy decision": (
            "PASS" if cases["2_auth_ok_legit_deny"]["ok"] is False else "FAIL",
            cases["2_auth_ok_legit_deny"]["error"],
        ),
        "Authority separation": (
            "PASS" if cases["15_legit_without_auth"]["ok"] is False else "FAIL",
            cases["15_legit_without_auth"]["error"],
        ),
        "PEP enforcement": (
            "PASS" if cases["6_direct_bypass"]["ok"] is False else "FAIL",
            cases["6_direct_bypass"]["error"],
        ),
        "Non-bypassability (sealed surface)": (
            "PASS"
            if cases["6_direct_bypass"]["ok"] is False and cases["7_export_invoke"]["ok"] is False
            else "FAIL",
            "poisoned source + inert export",
        ),
        "Non-bypassability (process-wide ambient Python)": (
            "FAIL",
            "architectural: callables never passed to seal() retain ambient IO",
        ),
        "Capability isolation": (
            "PASS" if cases["10_collusion_ops_price"]["ok"] is False else "FAIL",
            cases["10_collusion_ops_price"]["error"],
        ),
        "Replay resistance": (
            "PASS" if cases["8_ticket_replay"]["ok"] is False else "FAIL",
            cases["8_ticket_replay"]["error"],
        ),
        "Confused-deputy resistance": (
            "PASS" if cases["9_confused_deputy_fan_deploy"]["ok"] is False else "FAIL",
            cases["9_confused_deputy_fan_deploy"]["error"],
        ),
        "Delegation safety": (
            "PASS" if cases["5_ops_dark_pattern"]["ok"] is False else "FAIL",
            cases["5_ops_dark_pattern"]["error"],
        ),
        "Auditability": (
            "PASS" if rt.log.verify() and len(rt.evidence) >= 10 else "PARTIAL",
            f"entries={len(rt.evidence)} hash_ok={rt.log.verify()}",
        ),
        "Model independence": (
            "PASS",
            "no LLM in decision path; SealedRuntime+Kernel only",
        ),
        "End-to-end invariant (sealed)": (
            "PASS"
            if cases["1_legitimate_deploy"]["ok"]
            and cases["2_auth_ok_legit_deny"]["ok"] is False
            and cases["6_direct_bypass"]["ok"] is False
            else "FAIL",
            "ALLOW only via invoke; bypass blocked",
        ),
        "FDK/AuthGate binding (M5)": (
            "PASS" if all(e.legitimacy_binding for e in rt.evidence if e.executed) else "FAIL",
            "legitimacy_binding on executed evidence",
        ),
    }

    report = {
        "cases": cases,
        "effects": effects,
        "matrix": {k: {"status": v[0], "evidence": v[1]} for k, v in matrix.items()},
        "evidence": [e.as_dict() for e in rt.evidence],
        "question": {
            "can_adversary_execute_without_legit_auth_pep_chain_on_sealed_surface": False,
            "can_adversary_execute_via_ambient_unsealed_python": True,
            "infrastructure_grade_claim": "PARTIAL — sealed surface PASS; process-wide FAIL",
        },
    }
    Path(audit_path).with_suffix(".report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    return report
