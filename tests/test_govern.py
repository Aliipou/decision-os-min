"""The forced-path wrapper: a governed tool cannot execute without the kernel."""

from __future__ import annotations

import pytest

from decision_os_min import GovernanceRefused, Governor, set_actor

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


@pytest.fixture
def gov(tmp_path):
    return Governor(POLICY, audit_path=str(tmp_path / "audit.jsonl"))


def _send_email(gov):
    @gov.tool("send_email", capability="tool:send_email", purpose="support_reply",
              data_labels=["customer_support"])
    def send_email(to: str, body: str) -> str:
        return f"sent to {to}: {body}"

    return send_email


def test_permitted_call_executes(gov):
    send_email = _send_email(gov)
    set_actor("agent:bot")
    assert send_email(to="x@y.com", body="hi") == "sent to x@y.com: hi"


def test_unpermitted_actor_is_refused(gov):
    send_email = _send_email(gov)
    set_actor("agent:ghost")                      # not granted
    with pytest.raises(GovernanceRefused) as e:
        send_email(to="x", body="y")
    assert e.value.verdict == "DENY"


def test_there_is_no_bypass_the_wrapper_is_the_tool(gov):
    send_email = _send_email(gov)
    # The only callable a consumer holds is the governed one; calling it always
    # routes through the kernel. There is no ungoverned reference to reach.
    set_actor("agent:ghost")
    with pytest.raises(GovernanceRefused):
        send_email(to="x", body="y")
    # ...and every governed call is audited.
    assert gov._dos.log.verify() is True and len(gov._dos.log.entries()) == 1


def test_wrap_a_whole_registry(gov):
    def a(**p):
        return "A"

    def b(**p):
        return "B"

    governed = gov.wrap(
        {"send_email": a, "wire_money": b},
        specs={"send_email": {"capability": "tool:send_email",
                              "purpose": "support_reply",
                              "data_labels": ["customer_support"]}},
    )
    set_actor("agent:bot")
    assert governed["send_email"](x=1) == "A"        # granted
    with pytest.raises(GovernanceRefused):
        governed["wire_money"](x=1)                  # not granted -> refused
