"""The first 3→1 convergence brick: the sequential legitimacy pipeline and the
co-equal composer must produce IDENTICAL outcomes.

`paradigm.LegitimacyAuthorityPipeline` runs legitimacy as a sequential boolean gate
(a second stacked engine); `handle(..., evaluators=[legitimacy(policy)])` runs the
same policy as a co-equal veto plugin inside ONE kernel. If these agree on every
case, the sequential path is redundant and can eventually be deleted — which is the
whole point of convergence. This test is the evidence for that claim.
"""

from __future__ import annotations

from decision_os_min import DecisionOS, LegitimacyAuthorityPipeline
from decision_os_min.compose import DENY
from decision_os_min.evaluators import legitimacy

AUTH_POLICY = {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"}


def _legit(action):
    # Illegitimate to email a blocked recipient, regardless of authority.
    if str(action.get("payload", {}).get("to", "")).endswith("@blocked.test"):
        return (False, "recipient domain blocked")
    return (True, "ok")


def _tools():
    return {"send_email": lambda p: "sent", "wire_money": lambda p: "wired"}


def _action(**kw):
    base = {
        "actor": "agent:bot", "tool": "send_email",
        "capability": "tool:send_email", "payload": {"to": "x@ok.test"}, "nonce": "n-1",
    }
    base.update(kw)
    return base


# Cases spanning the truth table: (legit pass/fail) × (authority pass/fail).
_CASES = {
    "legit_ok_auth_ok": _action(),
    "legit_fail_auth_ok": _action(payload={"to": "x@blocked.test"}),
    "legit_ok_auth_fail": _action(tool="wire_money", capability="tool:wire_money"),
    "legit_fail_auth_fail": _action(
        tool="wire_money", capability="tool:wire_money", payload={"to": "x@blocked.test"}
    ),
}


def test_sequential_pipeline_and_composer_agree(tmp_path):
    for name, action in _CASES.items():
        pipe = LegitimacyAuthorityPipeline(
            AUTH_POLICY, audit_path=str(tmp_path / f"{name}_pipe.jsonl"), legitimacy=_legit
        )
        r_seq = pipe.handle(action, _tools())

        dos = DecisionOS(AUTH_POLICY, audit_path=str(tmp_path / f"{name}_dos.jsonl"))
        r_comp = dos.handle(action, _tools(), evaluators=[legitimacy(_legit)])

        assert (r_seq.verdict, r_seq.executed, r_seq.output) == (
            r_comp.verdict, r_comp.executed, r_comp.output
        ), f"pipeline vs composer disagree on {name}"


def test_legitimacy_plugin_is_fail_closed(tmp_path):
    def boom(action):
        raise RuntimeError("policy crashed")

    dos = DecisionOS(AUTH_POLICY, audit_path=str(tmp_path / "a.jsonl"))
    out = dos.handle(_action(), _tools(), evaluators=[legitimacy(boom)])
    assert out.verdict == DENY and not out.executed


def test_legitimacy_true_cannot_grant_missing_authority(tmp_path):
    # Veto-only: an ALLOW from legitimacy grants nothing the actor lacks.
    dos = DecisionOS(AUTH_POLICY, audit_path=str(tmp_path / "b.jsonl"))
    out = dos.handle(
        _action(tool="wire_money", capability="tool:wire_money"),
        _tools(),
        evaluators=[legitimacy(lambda a: (True, "fine by me"))],
    )
    assert out.verdict == DENY and not out.executed
