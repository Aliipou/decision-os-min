"""Tests for the deployable HTTP starter. Skipped cleanly if FastAPI isn't
installed (the service is an optional extra)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from decision_os_min.service import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISION_OS_AUDIT", str(tmp_path / "audit.jsonl"))
    return TestClient(create_app())


def _action(**kw):
    base = {
        "actor": "agent:bot", "tool": "send_email", "capability": "tool:send_email",
        "action_purpose": "support_reply", "data_labels": ["customer_support"],
        "payload": {}, "nonce": "n-1",
    }
    base.update(kw)
    return base


def test_health_and_pubkey(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert len(client.get("/v1/pubkey").json()["kernel_public_key"]) == 64


def test_decide_allow_is_signed_and_audited(client):
    r = client.post("/v1/decide", json=_action()).json()
    assert r["decision"]["verdict"] == "ALLOW"
    assert r["token"] is not None and r["audit_seq"] == 0
    # the returned decision verifies against the served public key
    from decision_os_min import verify

    pub = client.get("/v1/pubkey").json()["kernel_public_key"]
    assert verify(r["decision"], r["signature"], pub) is True


def test_decide_deny_has_no_token(client):
    r = client.post("/v1/decide", json=_action(capability="tool:wire_money")).json()
    assert r["decision"]["verdict"] == "DENY" and r["token"] is None


def test_audit_endpoints_and_metrics(client):
    client.post("/v1/decide", json=_action(nonce="a"))
    client.post("/v1/decide", json=_action(nonce="b", capability="tool:wire_money"))
    assert client.get("/v1/audit/verify").json() == {"chain_intact": True}
    assert len(client.get("/v1/audit").json()) == 2
    metrics = client.get("/metrics").text
    assert 'decision_os_decisions_total{verdict="ALLOW"} 1' in metrics
    assert 'decision_os_decisions_total{verdict="DENY"} 1' in metrics


def test_openapi_is_served(client):
    assert client.get("/openapi.json").status_code == 200
