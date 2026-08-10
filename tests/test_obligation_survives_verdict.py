"""A redaction is an OBLIGATION, not a property of the LIMIT branch.

`kernel._evaluate` used to compute the redaction pass AFTER the containment
return, so a `CONTAIN` decision carried no `transformed_payload` at all and the
obligation was dropped at the decision level. That was LATENT rather than
harmless, and the distinction is the whole point of this file:

- the default containment allowlist is empty, so a contained action executes
  nothing and nothing leaks — which is why the bug looked like a non-issue;
- but an empty allowlist also makes `CONTAIN` operationally equivalent to `DENY`.
  The first operator to allowlist the tool — i.e. to make `CONTAIN` do the job it
  exists for — would have had the RAW payload delivered into the sandbox.

A sandbox constrains egress and lifetime. It does not constrain what the tool is
shown. Verdict and obligation are orthogonal, and composing them by `if verdict ==
LIMIT` conflated them at both ends: the kernel only attached the obligation on
LIMIT, and the executor only applied it on LIMIT.
"""

from __future__ import annotations

import pytest

import decision_os_min.kernel as kernel_module
from decision_os_min import DecisionOS
from decision_os_min.compose import CONTAIN, LIMIT

SECRET = "123-45-6789"

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "default": "allow",
    "contain_threat_classes": ["malicious"],
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
}


def _action(nonce):
    return {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "payload": {"to": "x@ok.test", "ssn": SECRET},
        "nonce": nonce,
    }


@pytest.fixture
def permissive_sandbox(monkeypatch):
    """A containment spec that actually permits the tool.

    Without this the test proves nothing: the shipped default allows no tools, so
    the action is refused before any payload is handed over and the leak is masked.
    This is the configuration an operator reaches for the moment they want CONTAIN
    to mean 'run it, but boxed in' rather than 'refuse it'.
    """
    monkeypatch.setattr(
        kernel_module,
        "_CONTAINMENT",
        {
            "sandbox": True,
            "network": "none",
            "allowed_tools": ["send_email"],
            "time_limit_seconds": 5,
        },
    )


@pytest.mark.parametrize(
    "threat_class,expected_verdict",
    [(None, LIMIT), ("malicious", CONTAIN)],
    ids=["limit", "contain"],
)
def test_the_decision_carries_the_redaction_under_either_verdict(
    threat_class, expected_verdict, tmp_path
):
    """The obligation must be attached by the kernel regardless of verdict."""
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"))
    decision = dos.kernel.decide(_action("n-dec"), threat_class)["decision"]

    assert decision["verdict"] == expected_verdict
    assert "transformed_payload" in decision, "the redaction obligation was dropped"
    assert decision["transformed_payload"]["ssn"] == "[REDACTED]"


def test_a_contained_tool_is_shown_the_redacted_payload(permissive_sandbox, tmp_path):
    """The end-to-end leak: with a sandbox that permits the tool, the tool must
    still receive the minimized payload. Before the fix it received the raw SSN."""
    seen: dict = {}
    tools = {"send_email": lambda p: seen.update(p) or "sent"}

    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "b.jsonl"))
    out = dos.handle(_action("n-e2e"), tools, "malicious")

    assert out.executed and out.verdict == CONTAIN
    assert seen["ssn"] == "[REDACTED]"
    assert SECRET not in str(seen), "the raw secret reached the contained tool"


def test_an_unredacted_action_carries_no_obligation(tmp_path):
    """The converse — no redaction rule matches, so no obligation is attached and
    the executor falls through to the action's own payload. Guards against the fix
    over-reaching into a blanket transform."""
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "c.jsonl"))
    action = _action("n-plain")
    action["payload"] = {"to": "x@ok.test"}  # nothing to redact

    result = dos.kernel.decide(action)
    assert result["decision"]["verdict"] == "ALLOW"
    assert "transformed_payload" not in result["decision"]

    seen: dict = {}
    out = dos.handle(action, {"send_email": lambda p: seen.update(p) or "sent"})
    assert out.executed and seen == {"to": "x@ok.test"}
