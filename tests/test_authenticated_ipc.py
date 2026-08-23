"""Authenticated IPC framing, identity, replay, size, and timeout destructors."""

from __future__ import annotations

import socket
import struct
import threading
import time
import uuid

import pytest

import decision_os_min.host as host_module
from decision_os_min.host import (
    AgentHost,
    AuthenticatedAgentClient,
    Intent,
    IPCAuthenticationError,
    IPCFrameTooLarge,
    IPCProtocolError,
    IPCReplayError,
    IPCTimeout,
    ReplayWindow,
    authenticate_wire,
    encode_frame,
    recv_frame,
)

POLICY = {
    "grants": {"agent:bot": ["tool:deploy_ranking"]},
    "purpose_bindings": {"ops": ["deploy"]},
    "default": "deny",
}
KEY = bytes(range(32))


def _legit(action):
    if (action.get("payload") or {}).get("dark_pattern"):
        return (False, "C1", ("C1",))
    return (True, "ok", ())


def _host(tmp_path):
    effects: list[str] = []

    def deploy_ranking(*, model: str, **_kw):
        effects.append(model)
        return f"deployed:{model}"

    host = AgentHost(
        policy=POLICY,
        legitimacy=_legit,
        adapters={"deploy_ranking": deploy_ranking},
        audit_path=str(tmp_path / "ipc-audit.jsonl"),
    )
    host.register_agent("bot-1", actor="agent:bot", stakeholder="ops")
    return host, effects


def _message(**changes):
    message = Intent(
        "bot-1",
        "deploy_ranking",
        {"model": "v1"},
        "deploy",
        "ranking",
        uuid.uuid4().hex,
    ).to_wire()
    message.update(
        nonce=uuid.uuid4().hex,
        issued_at_ms=int(time.time() * 1000),
    )
    message.update(changes)
    return authenticate_wire(message, KEY)


def test_framing_survives_fragmentation_and_rejects_size_and_timeout():
    left, right = socket.socketpair()
    encoded = encode_frame({"v": 1, "type": "probe", "data": "fragmented"})

    def fragmented_send():
        for byte in encoded:
            left.sendall(bytes([byte]))

    sender = threading.Thread(target=fragmented_send)
    sender.start()
    assert recv_frame(right)["data"] == "fragmented"
    sender.join(timeout=2)
    left.close()
    right.close()

    left, right = socket.socketpair()
    left.sendall(struct.pack("!I", 65_537))
    with pytest.raises(IPCFrameTooLarge):
        recv_frame(right, max_bytes=65_536)
    left.close()
    right.close()

    left, right = socket.socketpair()
    with pytest.raises(IPCTimeout):
        recv_frame(right, timeout_s=0.01)
    left.close()
    right.close()

    with pytest.raises(IPCFrameTooLarge):
        encode_frame({"blob": "x" * 65_536})


def test_identity_authentication_replay_and_freshness_fail_closed(tmp_path):
    host, effects = _host(tmp_path)
    replay = ReplayWindow()
    message = _message()
    response = host.handle_authenticated_wire(message, agent_keys={"bot-1": KEY}, replay=replay)
    assert response["ok"] is True
    assert effects == ["v1"]

    with pytest.raises(IPCReplayError):
        host.handle_authenticated_wire(message, agent_keys={"bot-1": KEY}, replay=replay)
    assert effects == ["v1"]

    forged = dict(_message())
    forged["payload"] = {"model": "forged"}
    with pytest.raises(IPCAuthenticationError):
        host.handle_authenticated_wire(
            forged, agent_keys={"bot-1": KEY}, replay=ReplayWindow()
        )

    spoofed = _message(agent_id="other-agent")
    with pytest.raises(IPCAuthenticationError):
        host.handle_authenticated_wire(
            spoofed, agent_keys={"bot-1": KEY}, replay=ReplayWindow()
        )

    stale = _message(issued_at_ms=int((time.time() - 120) * 1000))
    with pytest.raises(IPCReplayError):
        host.handle_authenticated_wire(stale, agent_keys={"bot-1": KEY}, replay=ReplayWindow())
    assert effects == ["v1"]


def test_future_dated_nonce_is_retained_for_its_whole_acceptance_window(monkeypatch):
    now = 1_700_000_000.0
    monkeypatch.setattr(host_module.time, "time", lambda: now)
    replay = ReplayWindow(clock_skew_s=30)
    issued_at_ms = int((now + 20) * 1000)
    replay.consume("bot-1", "future-nonce-0001", issued_at_ms)
    monkeypatch.setattr(host_module.time, "time", lambda: now + 31)
    with pytest.raises(IPCReplayError):
        replay.consume("bot-1", "future-nonce-0001", issued_at_ms)


def test_authenticated_malformed_intent_consumes_nonce_before_parse(tmp_path):
    host, effects = _host(tmp_path)
    replay = ReplayWindow()
    malformed = _message(payload=["not", "an", "object"])
    with pytest.raises(IPCProtocolError, match="payload must be an object"):
        host.handle_authenticated_wire(
            malformed, agent_keys={"bot-1": KEY}, replay=replay
        )
    with pytest.raises(IPCReplayError):
        host.handle_authenticated_wire(
            malformed, agent_keys={"bot-1": KEY}, replay=replay
        )
    assert effects == []


def test_socket_server_returns_signed_replay_refusal_without_duplicate_effect(tmp_path):
    host, effects = _host(tmp_path)
    server_conn, agent_conn = socket.socketpair()
    server = threading.Thread(
        target=host.serve_authenticated_socket,
        args=(server_conn,),
        kwargs={"agent_keys": {"bot-1": KEY}},
    )
    server.start()
    client = AuthenticatedAgentClient(agent_conn, "bot-1", KEY)
    nonce = uuid.uuid4().hex
    request_id = uuid.uuid4().hex
    first = client.request(
        "deploy_ranking",
        {"model": "socket"},
        "deploy",
        "ranking",
        nonce=nonce,
        request_id=request_id,
    )
    assert first["ok"] is True
    second = client.request(
        "deploy_ranking",
        {"model": "socket"},
        "deploy",
        "ranking",
        nonce=nonce,
        request_id=request_id,
    )
    assert second["ok"] is False
    assert "IPCReplayError" in second["error"]
    assert effects == ["socket"]
    agent_conn.close()
    server.join(timeout=2)
    server_conn.close()
    assert not server.is_alive()


def test_non_object_json_is_rejected():
    left, right = socket.socketpair()
    left.sendall(struct.pack("!I", 2) + b"[]")
    with pytest.raises(IPCProtocolError, match="JSON object"):
        recv_frame(right)
    left.close()
    right.close()


@pytest.mark.parametrize(
    "body,error",
    [
        (b'{"v":1,"v":2}', "duplicate IPC JSON key"),
        (b'{"value":NaN}', "strict JSON"),
    ],
)
def test_ambiguous_or_nonstandard_json_is_rejected(body, error):
    left, right = socket.socketpair()
    left.sendall(struct.pack("!I", len(body)) + body)
    with pytest.raises(IPCProtocolError, match=error):
        recv_frame(right)
    left.close()
    right.close()
