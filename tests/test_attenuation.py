"""AE-4 / AE-5 — macaroon-inspired attenuation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from decision_os_min import AttenuationError, DecisionOS
from decision_os_min.attenuation import AuthorityGraph


def _dos(tmp_path, name="a.jsonl"):
    return DecisionOS({"grants": {}, "default": "allow"}, audit_path=str(tmp_path / name))


def _tools(sink):
    return {
        "send_email": lambda p: sink.append(("send_email", p)) or "ok",
        "wire_money": lambda p: sink.append(("wire_money", p)) or "ok",
    }


def test_ae4_delegation_cannot_amplify(tmp_path):
    dos = _dos(tmp_path)
    dos.grant("principal", "tool:send_email")
    # Ask for more than the parent holds — wire_money must be dropped.
    m = dos.delegate("principal", "agent:sub", ["send_email", "wire_money"])
    assert m.caveats[0] == "tools:send_email"
    assert m.tool_set() == frozenset({"send_email"})
    assert "wire_money" not in (m.tool_set() or frozenset())

    sink: list = []
    denied = dos.handle(
        {
            "actor": "agent:sub",
            "tool": "wire_money",
            "capability": "tool:wire_money",
            "action_purpose": "t",
            "payload": {"amount": 1},
            "nonce": "n1",
        },
        _tools(sink),
    )
    assert not denied.executed and sink == []

    ok = dos.handle(
        {
            "actor": "agent:sub",
            "tool": "send_email",
            "capability": "tool:send_email",
            "action_purpose": "t",
            "payload": {"to": "a@b.test"},
            "nonce": "n2",
        },
        _tools(sink),
    )
    assert ok.executed and sink[0][0] == "send_email"


def test_ae4_empty_after_attenuation_refused(tmp_path):
    dos = _dos(tmp_path)
    dos.grant("principal", "tool:send_email")
    with pytest.raises(AttenuationError):
        dos.delegate("principal", "agent:sub", ["wire_money"])


def test_ae5_child_cannot_outlive_parent(tmp_path):
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    parent_exp = datetime.now(UTC) + timedelta(seconds=1)
    child_want = datetime.now(UTC) + timedelta(hours=1)
    parent = g.delegate("root", "agent:parent", ["send_email"], expires_at=parent_exp)
    child = g.delegate("agent:parent", "agent:child", ["send_email"], expires_at=child_want)
    # Clamped to parent ceiling.
    assert child.expires_at() == parent.expires_at() == parent_exp
    assert g.holds("agent:child", "tool:send_email", now=parent_exp - timedelta(milliseconds=50))
    assert not g.holds("agent:child", "tool:send_email", now=parent_exp + timedelta(milliseconds=50))


def test_ae5_expired_macaroon_refused_by_kernel(tmp_path):
    """An already-expired macaroon in the graph must not authorize (holds/kernel).

    Minting with ``expires_at`` in the past is refused at ``delegate`` (AE-5);
    inject a past-dated caveat via ``_mint`` to exercise the holds() path.
    """

    dos = _dos(tmp_path)
    past = datetime.now(UTC) - timedelta(seconds=1)
    g: AuthorityGraph = dos.kernel.authority
    expired = g._mint(
        "agent:sub",
        ("tools:send_email", f"time < {past.astimezone(UTC).isoformat()}"),
    )
    g._macaroons.setdefault("agent:sub", []).append(expired)
    sink: list = []
    out = dos.handle(
        {
            "actor": "agent:sub",
            "tool": "send_email",
            "capability": "tool:send_email",
            "action_purpose": "t",
            "payload": {"to": "a@b.test"},
            "nonce": "n-exp",
        },
        _tools(sink),
    )
    assert not out.executed and sink == []


def test_dropping_a_caveat_breaks_the_hmac_chain():
    g = AuthorityGraph()
    g.grant("root", "tool:send_email")
    g.grant("root", "tool:wire_money")
    exp = datetime.now(UTC) + timedelta(hours=1)
    m = g.delegate("root", "agent:sub", ["send_email", "wire_money"], expires_at=exp)
    # Multi-tool mint is one tools: caveat + time. Drop the time caveat and keep
    # the stale tip — signature must not verify, holds must fail.
    from decision_os_min.attenuation import Macaroon

    forged = Macaroon(
        location=m.location,
        identifier=m.identifier,
        caveats=(m.caveats[0],),  # drop the time caveat
        signature=m.signature,  # stale tip
    )
    g._macaroons["agent:sub"] = [forged]
    assert not g.holds("agent:sub", "tool:send_email")
