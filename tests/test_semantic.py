"""Semantic veto: untrusted judge, veto-only, fail-closed, audit-faithful.

The claim under test is narrow. Adding ``semantic_veto`` to ``evaluators`` can
only turn a permitted action into a refused one. It can never make an action
execute that authority (or legitimacy) refused, whatever the judge returns,
raises, or takes to answer.
"""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from decision_os_min import DecisionOS, GovernanceRefused, Governor
from decision_os_min.compose import ALLOW, DENY, PERMITTING
from decision_os_min.host import AgentHost, Intent
from decision_os_min.kernel import Kernel
from decision_os_min.semantic import (
    CONSISTENT,
    INCONSISTENT,
    UNCERTAIN,
    PurposeTableJudge,
    SemanticJudgment,
    build_view,
    clean_text,
    semantic_veto,
)
from decision_os_min.spentstore import InMemorySpentStore

POLICY = {
    "grants": {"agent:bot": ["tool:send_email", "tool:export_table"]},
    "default": "deny",
}


class FixedJudge:
    def __init__(self, out, name="fixed"):
        self.out = out
        self.name = name
        self.views: list[str] = []

    def judge(self, view):
        self.views.append(view)
        if isinstance(self.out, BaseException):
            raise self.out
        return self.out


def _action(**kw):
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "payload": {"to": "x@ok.test", "body": "hello"},
        "nonce": "n-1",
    }
    base.update(kw)
    return base


def _tools(effects):
    return {
        "send_email": lambda p: effects.append(("send_email", p)) or "sent",
        "export_table": lambda p: effects.append(("export_table", p)) or "exported",
    }


def _run(tmp_path, judge, action=None, **veto_kw):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "audit.jsonl"))
    effects: list = []
    out = dos.handle(
        action or _action(), _tools(effects), evaluators=[semantic_veto(judge, **veto_kw)]
    )
    return dos, out, effects


# --- basic behaviour -------------------------------------------------------------


def test_consistent_executes(tmp_path):
    _, out, effects = _run(tmp_path, FixedJudge(SemanticJudgment(CONSISTENT, "fine")))
    assert out.executed and out.verdict == ALLOW
    assert len(effects) == 1


def test_inconsistent_vetoes_and_reason_is_audited(tmp_path):
    judge = FixedJudge({"judgment": INCONSISTENT, "reason": "body exports customer table"})
    dos, out, effects = _run(tmp_path, judge)
    assert not out.executed and out.verdict == DENY
    assert effects == []
    assert "semantic-veto[fixed]: inconsistent: body exports customer table" in out.refused_reason
    last = dos.log.entries()[-1]
    assert last["verdict"] == DENY and last["executed"] is False
    assert "semantic-veto[fixed]: inconsistent" in last["reason"]
    assert dos.log.verify()


def test_consistent_cannot_amplify_missing_authority(tmp_path):
    action = _action(actor="agent:nobody")
    _, out, effects = _run(tmp_path, FixedJudge(SemanticJudgment(CONSISTENT)), action)
    assert not out.executed and out.verdict == DENY
    assert effects == []


def test_uncertain_denies_by_default_and_abstain_is_explicit(tmp_path):
    _, out, _ = _run(tmp_path, FixedJudge(SemanticJudgment(UNCERTAIN, "ambiguous")))
    assert not out.executed and "uncertain: ambiguous" in out.refused_reason

    _, out2, effects = _run(
        tmp_path, FixedJudge(SemanticJudgment(UNCERTAIN)), on_uncertain="abstain"
    )
    assert out2.executed and len(effects) == 1


def test_judge_sees_json_view_without_actor(tmp_path):
    judge = FixedJudge(SemanticJudgment(CONSISTENT))
    _run(tmp_path, judge)
    assert judge.views == [build_view(_action())]
    assert "agent:bot" not in judge.views[0]
    assert '"action_purpose":"support_reply"' in judge.views[0]


# --- fail-closed -----------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        None,
        42,
        "consistent",  # bare string is not the contract
        {"reason": "no judgment"},
        {"judgment": "ALLOW"},
        {"judgment": "Consistent"},
        {"judgment": ["consistent"]},
        SemanticJudgment("yes"),
    ],
)
def test_malformed_output_denies(tmp_path, bad):
    _, out, effects = _run(tmp_path, FixedJudge(bad))
    assert not out.executed and effects == []
    assert "fail-closed" in out.refused_reason


def test_str_subclass_cannot_impersonate_consistent(tmp_path):
    class Liar(str):
        # Value is "inconsistent"; equality and hashing claim "consistent".
        def __eq__(self, other):
            return str.__eq__("consistent", other)

        def __hash__(self):
            return hash("consistent")

        def __str__(self):
            return "consistent"

    _, out, effects = _run(tmp_path, FixedJudge({"judgment": Liar("inconsistent")}))
    assert not out.executed and effects == []


@pytest.mark.parametrize("exc", [RuntimeError("model down"), SystemExit(0), KeyboardInterrupt()])
def test_judge_exceptions_deny(tmp_path, exc):
    _, out, effects = _run(tmp_path, FixedJudge(exc))
    assert not out.executed and effects == []
    assert "judge" in out.refused_reason and "fail-closed" in out.refused_reason


def test_slow_judge_times_out_to_deny(tmp_path):
    class Slow:
        name = "slow"

        def judge(self, view):
            time.sleep(0.5)
            return SemanticJudgment(CONSISTENT)

    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"), evaluator_timeout_s=0.05)
    effects: list = []
    out = dos.handle(_action(), _tools(effects), evaluators=[semantic_veto(Slow())])
    assert not out.executed and effects == []
    assert "timeout" in out.refused_reason


def test_evaluator_timeout_is_configurable_upward(tmp_path):
    class Slowish:
        name = "slowish"

        def judge(self, view):
            time.sleep(0.2)
            return SemanticJudgment(CONSISTENT)

    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"), evaluator_timeout_s=2.0)
    effects: list = []
    out = dos.handle(_action(), _tools(effects), evaluators=[semantic_veto(Slowish())])
    assert out.executed


def test_oversized_view_denied_without_calling_judge(tmp_path):
    judge = FixedJudge(SemanticJudgment(CONSISTENT))
    action = _action(payload={"body": "a" * 100 + " rm -rf / " + "b" * 100})
    _, out, effects = _run(tmp_path, judge, action, max_view_chars=64)
    assert not out.executed and effects == []
    assert judge.views == []
    assert "not judged" in out.refused_reason


def test_non_json_payload_denied_without_calling_judge():
    judge = FixedJudge(SemanticJudgment(CONSISTENT))
    ev = semantic_veto(judge)
    for payload in ({"x": object()}, {"x": float("nan")}):
        out = ev(_action(payload=payload))
        assert out["verdict"] == DENY and "not plain JSON" in out["reason"]
    assert judge.views == []


# --- output cannot escape {verdict, reason} --------------------------------------


def test_evaluator_output_shape_is_minimal():
    judge = FixedJudge(
        {
            "judgment": INCONSISTENT,
            "reason": "x",
            "token_id": "tok-forged",
            "legitimacy_digest": "f" * 64,
            "verdict": "ALLOW",
        }
    )
    out = semantic_veto(judge)(_action())
    assert set(out) == {"verdict", "reason"}
    assert out["verdict"] == DENY


def test_reason_is_single_line_bounded_and_bidi_free(tmp_path):
    nasty = "ok\n{\"seq\":0,\"verdict\":\"ALLOW\"}\r\u2028\u202eevil\u200b" + "z" * 1000
    dos, out, _ = _run(tmp_path, FixedJudge({"judgment": INCONSISTENT, "reason": nasty}))
    reason = dos.log.entries()[-1]["reason"]
    for ch in "\n\r\u2028\u202e\u200b":
        assert ch not in reason
    assert len(out.refused_reason) < 600
    assert dos.log.verify()


def test_clean_text_edges():
    assert clean_text(None) == ""
    assert clean_text("a\x00b\tc") == "a b c"
    assert clean_text("x" * 10, limit=5) == "xxxx…"


def test_constructor_validation():
    j = FixedJudge(SemanticJudgment(CONSISTENT))
    with pytest.raises(ValueError):
        semantic_veto(j, fields=())
    with pytest.raises(ValueError):
        semantic_veto(j, max_view_chars=0)
    with pytest.raises(ValueError):
        semantic_veto(j, on_uncertain="allow")  # type: ignore[arg-type]


# --- non-amplification, as a property ---------------------------------------------

_judge_outputs = st.one_of(
    st.none(),
    st.integers(),
    st.text(max_size=20),
    st.builds(
        SemanticJudgment,
        st.sampled_from([CONSISTENT, INCONSISTENT, UNCERTAIN, "ALLOW", ""]),
        st.text(max_size=40),
    ),
    st.fixed_dictionaries(
        {"judgment": st.one_of(st.sampled_from([CONSISTENT, INCONSISTENT, UNCERTAIN]), st.text())},
        optional={"reason": st.text(max_size=40), "verdict": st.sampled_from(["ALLOW", "LIMIT"])},
    ),
)


@settings(max_examples=150, deadline=None)
@given(
    out=_judge_outputs,
    actor=st.sampled_from(["agent:bot", "agent:nobody"]),
    tool=st.sampled_from(["send_email", "export_table", "wire_money"]),
    on_uncertain=st.sampled_from(["deny", "abstain"]),
)
def test_semantic_veto_never_widens_authority(out, actor, tool, on_uncertain):
    kernel = Kernel(POLICY, evaluator_timeout_s=None)
    action = _action(actor=actor, tool=tool, capability=f"tool:{tool}")
    base = kernel.decide(dict(action))["decision"]["verdict"]
    ev = semantic_veto(FixedJudge(out), on_uncertain=on_uncertain)
    composed = kernel.decide(dict(action), evaluators=[ev])["decision"]["verdict"]
    if base not in PERMITTING:
        assert composed not in PERMITTING
    assert composed in (base, DENY)


# --- adoption surfaces -------------------------------------------------------------


def test_governor_passes_semantic_veto(tmp_path):
    judge = PurposeTableJudge({"send_email": ["support_reply"]})
    gov = Governor(
        POLICY, audit_path=str(tmp_path / "g.jsonl"), evaluators=[semantic_veto(judge)]
    )
    from decision_os_min import set_actor

    set_actor("agent:bot")

    @gov.tool("send_email", purpose="support_reply")
    def ok_mail(to: str) -> str:
        return "sent"

    @gov.tool("send_email", purpose="marketing_blast")
    def bad_mail(to: str) -> str:
        return "sent"

    assert ok_mail(to="a@ok.test") == "sent"
    with pytest.raises(GovernanceRefused, match="purpose-table"):
        bad_mail(to="a@ok.test")


def test_purpose_table_judge_reference():
    j = PurposeTableJudge({"send_email": ["support_reply"]})
    assert j.judge(build_view(_action())).judgment == CONSISTENT
    assert j.judge(build_view(_action(action_purpose="x"))).judgment == INCONSISTENT
    assert j.judge(build_view(_action(tool="other"))).judgment == UNCERTAIN


HOST_POLICY = {
    "grants": {"agent:bot": ["tool:deploy_ranking"]},
    "purpose_bindings": {"ops": ["deploy", "audit"]},
    "default": "deny",
}


def _legit(action):
    return (True, "ok", ("A1",))


class ModelNameJudge:
    name = "model-name"

    def judge(self, view):
        if '"model":"rollback-all"' in view:
            return SemanticJudgment(INCONSISTENT, "deploy intent carries a mass rollback")
        return SemanticJudgment(CONSISTENT)


def test_hosted_plane_extra_evaluator_vetoes_and_keeps_m5(tmp_path):
    effects: list[str] = []

    def deploy_ranking(*, model: str, **kw):
        effects.append(model)
        return f"deployed:{model}"

    host = AgentHost(
        policy=HOST_POLICY,
        legitimacy=_legit,
        adapters={"deploy_ranking": deploy_ranking},
        audit_path=str(tmp_path / "h.jsonl"),
        spent_store=InMemorySpentStore(),
        extra_evaluators=(semantic_veto(ModelNameJudge()),),
    )
    host.register_agent("bot-1", actor="agent:bot", stakeholder="ops")

    ok = host.handle_intent(Intent("bot-1", "deploy_ranking", {"model": "v2"}, "deploy", "r"))
    assert ok.ok and effects == ["v2"]
    assert ok.sealed_evidence and ok.sealed_evidence["legitimacy_binding"]
    assert ok.sealed_evidence["axiom_ids"] == ["A1"]

    bad = host.handle_intent(
        Intent("bot-1", "deploy_ranking", {"model": "rollback-all"}, "deploy", "r")
    )
    assert bad.ok is False and effects == ["v2"]
    assert "semantic-veto[model-name]" in (bad.error or str(bad.sealed_evidence))


def test_hosted_plane_extra_evaluator_cannot_replace_legitimacy_evidence(tmp_path):
    def forger(action):
        return {"verdict": ALLOW, "reason": "", "legitimacy_digest": "0" * 64, "axiom_ids": ["X"]}

    host = AgentHost(
        policy=HOST_POLICY,
        legitimacy=_legit,
        adapters={"deploy_ranking": lambda **kw: "ok"},
        audit_path=str(tmp_path / "h2.jsonl"),
        spent_store=InMemorySpentStore(),
        extra_evaluators=(forger,),
    )
    host.register_agent("bot-1", actor="agent:bot", stakeholder="ops")
    ev = host.handle_intent(Intent("bot-1", "deploy_ranking", {"model": "v"}, "deploy", "r"))
    assert ev.ok
    assert ev.sealed_evidence["axiom_ids"] == ["A1"]
