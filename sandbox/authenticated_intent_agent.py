"""Untrusted Linux agent used for real sandbox → AgentHost boundary evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import time
from typing import Any

MAX_FRAME_BYTES = 64 * 1024
HEADER = struct.Struct("!I")


def canon(message: dict[str, Any]) -> bytes:
    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign(message: dict[str, Any], key: bytes) -> dict[str, Any]:
    body = dict(message)
    body.pop("auth", None)
    body["auth"] = hmac.new(key, canon(body), hashlib.sha256).hexdigest()
    return body


def frame(message: dict[str, Any]) -> bytes:
    body = canon(message)
    if len(body) > MAX_FRAME_BYTES:
        raise ValueError("oversized frame")
    return HEADER.pack(len(body)) + body


def recv_exact(conn: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = conn.recv(count)
        if not chunk:
            raise RuntimeError("AgentHost closed IPC")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def recv_response(conn: socket.socket, key: bytes, request_id: str) -> dict[str, Any]:
    (size,) = HEADER.unpack(recv_exact(conn, HEADER.size))
    if size == 0 or size > MAX_FRAME_BYTES:
        raise RuntimeError("invalid AgentHost frame size")
    response = json.loads(recv_exact(conn, size).decode("utf-8"))
    supplied = response.pop("auth", "")
    expected = hmac.new(key, canon(response), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise RuntimeError("unauthenticated AgentHost response")
    response["auth"] = supplied
    if response.get("request_id") != request_id:
        raise RuntimeError("AgentHost response substitution")
    return response


def intent(
    agent_id: str,
    tool: str,
    payload: dict[str, Any],
    purpose: str,
    request_id: str,
) -> dict[str, Any]:
    return {
        "v": 1,
        "type": "intent",
        "request_id": request_id,
        "agent_id": agent_id,
        "tool": tool,
        "payload": payload,
        "intent": purpose,
        "resource": "ranking",
        "nonce": os.urandom(16).hex(),
        "issued_at_ms": int(time.time() * 1000),
    }


def direct_effect_destructors() -> dict[str, str]:
    results: dict[str, str] = {}
    try:
        with open("/agent_escape.txt", "w", encoding="utf-8") as handle:
            handle.write("escape")
        results["filesystem"] = "WROTE"
    except Exception as exc:
        results["filesystem"] = f"BLOCKED:{type(exc).__name__}"
    try:
        conn = socket.create_connection(("1.1.1.1", 443), timeout=0.5)
        conn.close()
        results["network"] = "CONNECTED"
    except Exception as exc:
        results["network"] = f"BLOCKED:{type(exc).__name__}"
    try:
        child = subprocess.run(
            [sys.executable, "-c", "print('escape')"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        results["subprocess"] = f"RAN:{child.returncode}"
    except Exception as exc:
        results["subprocess"] = f"BLOCKED:{type(exc).__name__}"
    try:
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        os.waitpid(pid, 0)
        results["fork"] = "FORKED"
    except Exception as exc:
        results["fork"] = f"BLOCKED:{type(exc).__name__}"
    return results


def main() -> None:
    agent_id = os.environ["DECISION_OS_AGENT_ID"]
    key = open(os.environ["DECISION_OS_AGENT_KEY"], "rb").read()
    conn = socket.socket(fileno=int(os.environ["DECISION_OS_AGENT_FD"]))
    conn.settimeout(3.0)

    denied_id = "deny-" + os.urandom(6).hex()
    denied = sign(
        intent(
            agent_id,
            "deploy_ranking",
            {"model": "malicious", "dark_pattern": True},
            "deploy",
            denied_id,
        ),
        key,
    )
    conn.sendall(frame(denied))
    denied_response = recv_response(conn, key, denied_id)

    allowed_id = "allow-" + os.urandom(6).hex()
    allowed = sign(
        intent(agent_id, "deploy_ranking", {"model": "sandbox-v1"}, "deploy", allowed_id),
        key,
    )
    encoded_allowed = frame(allowed)
    conn.sendall(encoded_allowed)
    allowed_response = recv_response(conn, key, allowed_id)

    conn.sendall(encoded_allowed)
    replay_response = recv_response(conn, key, allowed_id)

    report = {
        "denied": denied_response,
        "allowed": allowed_response,
        "replay": replay_response,
        "direct_effects": direct_effect_destructors(),
        "effect_handles": "deploy_ranking" in globals(),
        "ipc_fd": int(os.environ["DECISION_OS_AGENT_FD"]),
    }
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
