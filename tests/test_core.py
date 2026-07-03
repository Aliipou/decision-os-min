"""The core invariants — the same guarantees as the full multi-repo system, in
one file. If these pass, the distilled core preserves the real security value.
"""

from __future__ import annotations

import pytest

from decision_os_min import DecisionOS, ExecutionRefused

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def _dos(tmp_path):
    return DecisionOS(POLICY, audit_path=str(tmp_path / "audit.jsonl"))


def _action(**kw):
    base = {
        "actor": "agent:bot", "tool": "send_email", "action_purpose": "support_reply",
        "data_labels": ["customer_support"], "payload": {}, "capability": "tool:send_email",
        "nonce": "n-1",
    }
    base.update(kw)
    return base


def _tools():
    seen = {}
    return {"send_email": lambda p: seen.update(p) or "sent"}, seen


# --- behaviour --------------------------------------------------------------
def test_allow_executes_and_audits(tmp_path):
    dos = _dos(tmp_path)
    tools, _ = _tools()
    out = dos.handle(_action(), tools)
    assert out.verdict == "ALLOW" and out.executed and out.output == "sent"
    assert dos.log.verify() and len(dos.log.entries()) == 1


def test_deny_blocks(tmp_path):
    dos = _dos(tmp_path)
    out = dos.handle(_action(capability="tool:wire_money"), _tools()[0])
    assert out.verdict == "DENY" and not out.executed


def test_limit_redacts_before_the_tool(tmp_path):
    dos = _dos(tmp_path)
    tools, seen = _tools()
    out = dos.handle(_action(payload={"ssn": "123", "body": "hi"}), tools)
    assert out.verdict == "LIMIT" and out.executed and seen["ssn"] == "[REDACTED]"


def test_contain_refuses_sensitive_tool(tmp_path):
    dos = _dos(tmp_path)
    out = dos.handle(_action(), _tools()[0], threat_class="malicious")
    assert out.verdict == "CONTAIN" and not out.executed


def test_advisory_never_loosens_a_deny(tmp_path):
    # bad purpose -> DENY; a malicious flag must NOT turn it into CONTAIN.
    dos = _dos(tmp_path)
    a = _action(data_labels=["secret"])
    assert dos.handle(a, _tools()[0]).verdict == "DENY"
    assert dos.handle(_action(nonce="n2", data_labels=["secret"]), _tools()[0],
                      threat_class="malicious").verdict == "DENY"


# --- red-team regressions (must stay closed) --------------------------------
def test_forged_decision_refused(tmp_path):
    dos = _dos(tmp_path)
    result = dos.kernel.decide(_action())
    result["signature"] = "00" * 64
    with pytest.raises(ExecutionRefused, match="not authenticated"):
        dos.executor.execute(_action(), result, _tools()[0])


def test_tampering_signed_token_id_breaks_signature(tmp_path):
    # The token_id (replay control), capability, and expiry are folded into the
    # SIGNED decision. Swapping in a fresh token_id to dodge the spent-set breaks
    # the signature -> refused. This is what makes the one signature sufficient.
    dos = _dos(tmp_path)
    result = dos.kernel.decide(_action())
    result["decision"]["token_id"] = "tok-attacker"
    with pytest.raises(ExecutionRefused, match="not authenticated"):
        dos.executor.execute(_action(), result, _tools()[0])


def test_replayed_token_refused(tmp_path):
    dos = _dos(tmp_path)
    tools, _ = _tools()
    result = dos.kernel.decide(_action())
    dos.executor.execute(_action(), result, tools)
    with pytest.raises(ExecutionRefused, match="spent"):
        dos.executor.execute(_action(), result, tools)


def test_confused_deputy_refused(tmp_path):
    # A valid ALLOW+token for a benign action cannot execute a different action.
    dos = _dos(tmp_path)
    benign = _action(nonce="same", payload={"body": "hi"})
    evil = _action(nonce="same", data_labels=["secret"], payload={"body": "exfiltrate"})
    result = dos.kernel.decide(benign)
    assert result["decision"]["verdict"] == "ALLOW"
    with pytest.raises(ExecutionRefused, match="binding mismatch"):
        dos.executor.execute(evil, result, _tools()[0])


def test_audit_tamper_detected(tmp_path):
    dos = _dos(tmp_path)
    tools, _ = _tools()
    for n in ("a1", "a2", "a3"):
        dos.handle(_action(nonce=n), tools)
    assert dos.log.verify()
    lines = dos.log._path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"all checks passed"', '"tampered"')
    dos.log._path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert dos.log.verify() is False


def test_ambiguous_capability_tool_denied(tmp_path):
    dos = _dos(tmp_path)
    out = dos.handle(_action(capability="tool:send_email", tool="read_docs"), _tools()[0])
    assert out.verdict == "DENY" and not out.executed


# --- FDK-as-plugin: advisor is optional and never holds authority -----------
def test_system_works_without_any_advisor(tmp_path):
    dos = _dos(tmp_path)
    assert dos.handle(_action(), _tools()[0]).verdict == "ALLOW"  # no advisor needed


def test_advisor_plugin_can_only_tighten(tmp_path):
    from decision_os_min import simple_threat_advisor

    dos = _dos(tmp_path)
    # advisor flags agent:evil -> malicious -> kernel CONTAINs (advice, not authority)
    out = dos.handle(_action(actor="agent:evil", capability="*"), _tools()[0],
                     advisor=simple_threat_advisor)
    # agent:evil lacks the capability, so DENY dominates even the malicious flag
    assert out.verdict == "DENY"
    # a permitted actor flagged malicious -> CONTAIN, not executed
    dos2 = _dos(tmp_path / "x")
    out2 = dos2.handle(_action(), _tools()[0],
                       advisor=lambda a: "malicious")
    assert out2.verdict == "CONTAIN" and not out2.executed
