"""End-to-end loop: decide → audit → execute, plus key persistence."""

from __future__ import annotations

from decision_os_min import DecisionOS
from decision_os_min.kernel import Kernel, load_or_create_signing_key, verify

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "default": "deny",
}


def test_full_loop_allow_and_audit(tmp_path):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "a.jsonl"))
    sink = []
    out = dos.handle(
        {
            "actor": "agent:bot",
            "tool": "send_email",
            "capability": "tool:send_email",
            "action_purpose": "support_reply",
            "data_labels": ["customer_support"],
            "payload": {"to": "a@b.test", "body": "hi"},
            "nonce": "n-ok",
        },
        {"send_email": lambda p: sink.append(p) or "sent"},
    )
    assert out.executed and out.verdict == "ALLOW" and sink
    assert dos.log.verify()
    entry = dos.log.entries()[-1]
    assert entry["executed"] is True and entry["tool"] == "send_email"


def test_full_loop_deny_ungranted(tmp_path):
    dos = DecisionOS(POLICY, audit_path=str(tmp_path / "d.jsonl"))
    sink = []
    out = dos.handle(
        {
            "actor": "agent:bot",
            "tool": "wire_money",
            "capability": "tool:wire_money",
            "action_purpose": "support_reply",
            "data_labels": ["customer_support"],
            "payload": {"amount": 1},
            "nonce": "n-deny",
        },
        {"wire_money": lambda p: sink.append(p) or "wired"},
    )
    assert not out.executed and out.verdict == "DENY" and sink == []
    assert dos.log.verify()
    assert dos.log.entries()[-1]["executed"] is False


def test_signing_key_persists_across_kernel_instances(tmp_path):
    path = str(tmp_path / "k.pem")
    k1 = Kernel(POLICY, key_path=path)
    pub = k1.public_key_hex()
    action = {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {"to": "a@b.test"},
        "nonce": "n-key",
    }
    result = k1.decide(action)
    k2 = Kernel(POLICY, key_path=path)
    assert k2.public_key_hex() == pub
    assert verify(result["decision"], result["signature"], k2.public_key_hex())


def test_load_or_create_signing_key_roundtrip(tmp_path):
    path = str(tmp_path / "round.pem")
    a = load_or_create_signing_key(path)
    b = load_or_create_signing_key(path)
    assert a.public_key().public_bytes_raw() == b.public_key().public_bytes_raw()
