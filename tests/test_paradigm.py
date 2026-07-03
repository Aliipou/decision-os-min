"""Legitimacy ⊥ Authority invariant: legitimacy may only DENY; authority may never
override a legitimacy DENY."""
from decision_os_min import LegitimacyAuthorityPipeline

POLICY = {"grants": {"agent:bot": ["tool:send_email"]}, "default": "deny"}
TOOLS = {"send_email": lambda p: "sent", "wire_money": lambda p: "wired"}

def _act(**kw):
    b = {"tool": "send_email", "capability": "tool:send_email", "actor": "agent:bot",
         "action_purpose": "x", "data_labels": [], "payload": {}, "nonce": "n"}
    b.update(kw); return b

def test_legitimacy_deny_blocks_even_when_authorized(tmp_path):
    # authorized action, but legitimacy says no -> DENY, authority never consulted.
    p = LegitimacyAuthorityPipeline(POLICY, audit_path=str(tmp_path/"a.jsonl"),
                                    legitimacy=lambda a: (False, "off-purpose sale"))
    out = p.handle(_act(), TOOLS)
    assert out.verdict == "DENY" and not out.executed and "illegitimate" in out.refused_reason

def test_legitimacy_pass_then_authority_decides(tmp_path):
    p = LegitimacyAuthorityPipeline(POLICY, audit_path=str(tmp_path/"a.jsonl"),
                                    legitimacy=lambda a: (True, "ok"))
    assert p.handle(_act(), TOOLS).executed is True                 # legit + authorized

def test_legitimacy_cannot_grant_authority(tmp_path):
    # legitimacy says YES for an UNauthorized action -> still DENY (authority holds).
    p = LegitimacyAuthorityPipeline(POLICY, audit_path=str(tmp_path/"a.jsonl"),
                                    legitimacy=lambda a: (True, "legit"))
    out = p.handle(_act(tool="wire_money", capability="tool:wire_money"), TOOLS)
    assert out.verdict == "DENY" and not out.executed               # legitimacy can't grant

def test_no_legitimacy_policy_is_pure_authority(tmp_path):
    p = LegitimacyAuthorityPipeline(POLICY, audit_path=str(tmp_path/"a.jsonl"))
    assert p.handle(_act(), TOOLS).executed is True
