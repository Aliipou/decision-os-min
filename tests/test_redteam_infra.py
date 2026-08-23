"""RED TEAM — infra-ready HTTP service (service.py / Docker surface).

Breaks closed here:
  * key rotation loss — create_app ignored DECISION_OS_KEY_FILE / ephemeral key
    every restart (signatures from prior boots unverifiable).
  * unsigned decide — every /v1/decide response must carry a signature that
    verifies against /v1/pubkey.
  * capability ≠ tool — ambiguous actions must DENY (kernel rule exposed via HTTP).
  * audit path unwritable — decide must fail closed (503), not return a live token.
  * /metrics + /v1/audit info leak — metrics are verdict counters only; full audit
    dump is off unless DECISION_OS_EXPOSE_AUDIT is explicitly enabled.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from decision_os_min.service import create_app  # noqa: E402


def _action(**kw):
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {},
        "nonce": "n-1",
    }
    base.update(kw)
    return base


@pytest.fixture
def key_and_audit(tmp_path, monkeypatch):
    key = tmp_path / "kernel.pem"
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("DECISION_OS_KEY_FILE", str(key))
    monkeypatch.setenv("DECISION_OS_AUDIT", str(audit))
    monkeypatch.delenv("DECISION_OS_EXPOSE_AUDIT", raising=False)
    return key, audit


def test_fixed_key_persists_across_app_restarts(key_and_audit, monkeypatch):
    """CLOSED. Without DECISION_OS_KEY_FILE every create_app() minted a new key
    (Docker restart = all prior signatures unverifiable)."""
    key, _audit = key_and_audit
    c1 = TestClient(create_app())
    pub1 = c1.get("/v1/pubkey").json()["kernel_public_key"]
    assert key.is_file()
    c2 = TestClient(create_app())
    pub2 = c2.get("/v1/pubkey").json()["kernel_public_key"]
    assert pub1 == pub2
    # A decide from boot1 still verifies under boot2's pubkey.
    from decision_os_min import verify

    r = c1.post("/v1/decide", json=_action(nonce="persist-1")).json()
    assert verify(r["decision"], r["signature"], pub2) is True


def test_fixed_decide_always_signed_and_verifiable(key_and_audit):
    """CLOSED. 'Unsigned decide' — response signature must verify for ALLOW and DENY."""
    from decision_os_min import verify

    client = TestClient(create_app())
    pub = client.get("/v1/pubkey").json()["kernel_public_key"]
    allow = client.post("/v1/decide", json=_action(nonce="sig-allow")).json()
    deny = client.post(
        "/v1/decide", json=_action(nonce="sig-deny", capability="tool:wire_money")
    ).json()
    assert allow["signature"] and deny["signature"]
    assert verify(allow["decision"], allow["signature"], pub) is True
    assert verify(deny["decision"], deny["signature"], pub) is True
    assert allow["token"] is not None and deny["token"] is None


def test_fixed_capability_neq_tool_denied_over_http(key_and_audit):
    """CLOSED. capability≠tool must DENY at the HTTP boundary (no token)."""
    client = TestClient(create_app())
    r = client.post(
        "/v1/decide",
        json=_action(
            tool="send_email",
            capability="tool:wire_money",
            nonce="ambig-1",
        ),
    ).json()
    assert r["decision"]["verdict"] == "DENY"
    assert r["token"] is None
    assert "ambiguous" in r["decision"]["reason"].lower()


def test_fixed_unwritable_audit_fails_closed(key_and_audit):
    """CLOSED. If the audit sink cannot append, /v1/decide must not return a
    live signed token (fail closed with 5xx)."""
    client = TestClient(create_app(), raise_server_exceptions=False)

    def _boom(*_a, **_k):
        raise OSError("audit path not writable")

    with patch("decision_os_min.audit.HashLog.record", side_effect=_boom):
        resp = client.post("/v1/decide", json=_action(nonce="aud-fail"))
    assert resp.status_code >= 500


def test_fixed_metrics_have_no_actor_or_payload_labels(key_and_audit):
    """CLOSED. /metrics is counters by verdict only — no actor/tool/payload leak."""
    client = TestClient(create_app())
    client.post("/v1/decide", json=_action(nonce="m1", payload={"ssn": "SECRET-999"}))
    body = client.get("/metrics").text
    assert "decision_os_decisions_total" in body
    assert "agent:bot" not in body
    assert "SECRET-999" not in body
    assert "ssn" not in body
    assert "send_email" not in body


def test_fixed_audit_api_disabled_by_default(key_and_audit, monkeypatch):
    """CLOSED. Unauthenticated /v1/audit dumped the full trail (actors, tools,
    reasons). Default is now closed; opt-in via DECISION_OS_EXPOSE_AUDIT."""
    client = TestClient(create_app())
    client.post("/v1/decide", json=_action(nonce="a1"))
    assert client.get("/v1/audit").status_code == 404
    # verify stays available (integrity check, no entry bodies).
    assert client.get("/v1/audit/verify").json() == {"chain_intact": True}

    monkeypatch.setenv("DECISION_OS_EXPOSE_AUDIT", "1")
    exposed = TestClient(create_app())
    exposed.post("/v1/decide", json=_action(nonce="a2"))
    entries = exposed.get("/v1/audit").json()
    assert len(entries) >= 1


def test_readyz_reports_key_persisted(key_and_audit):
    client = TestClient(create_app())
    body = client.get("/readyz").json()
    assert body["status"] == "ready"
    assert body["key_persisted"] is True
