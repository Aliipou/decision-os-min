"""Hosted Agent Enforcement Plane v1 — trust boundary, not Python sealing.

Untrusted agent processes may only send Intents over IPC. They never receive
tool callables, credentials, or effect adapters. All consequential effects run
inside AgentHost through SealedRuntime (admission → legitimacy → authority → PEP).

Claim (precise):
  On the hosted agent plane, an agent without ambient OS privileges cannot cause
  host-registered effects except via a governed Intent.

Non-claim:
  A co-located agent with full OS rights can still open sockets/files in its own
  process. Closing that requires OS sandbox (seccomp/container). This module
  separates trust domains; it does not re-secure ambient Python/OS.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sealed import AdmissionError, SealedRefused, SealedRuntime
from .spentstore import InMemorySpentStore, SpentStore

PROTOCOL = 1
MAX_FRAME_BYTES = 64 * 1024
DEFAULT_IPC_TIMEOUT_S = 2.0
DEFAULT_CLOCK_SKEW_S = 30.0
_FRAME_HEADER = struct.Struct("!I")


class IPCError(RuntimeError):
    """Fail-closed authenticated IPC error."""


class IPCProtocolError(IPCError):
    pass


class IPCAuthenticationError(IPCError):
    pass


class IPCReplayError(IPCError):
    pass


class IPCFrameTooLarge(IPCProtocolError):
    pass


class IPCTimeout(IPCError):
    pass


def _wire_json(msg: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            msg,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IPCProtocolError(f"message is not strict JSON: {exc}") from exc


def encode_frame(msg: dict[str, Any], *, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    """Encode one unambiguous, bounded, four-byte-length-prefixed JSON frame."""
    body = _wire_json(msg)
    if not body:
        raise IPCProtocolError("empty IPC frame")
    if len(body) > max_bytes:
        raise IPCFrameTooLarge(f"IPC frame is {len(body)} bytes; limit is {max_bytes}")
    return _FRAME_HEADER.pack(len(body)) + body


def _recv_exact(conn: socket.socket, size: int, timeout_s: float) -> bytes:
    deadline = time.monotonic() + timeout_s
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        wait = deadline - time.monotonic()
        if wait <= 0:
            raise IPCTimeout("IPC receive deadline exceeded")
        conn.settimeout(wait)
        try:
            chunk = conn.recv(remaining)
        except TimeoutError as exc:
            raise IPCTimeout("IPC receive deadline exceeded") from exc
        if not chunk:
            raise EOFError("IPC peer closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(
    conn: socket.socket,
    *,
    max_bytes: int = MAX_FRAME_BYTES,
    timeout_s: float = DEFAULT_IPC_TIMEOUT_S,
) -> dict[str, Any]:
    """Receive exactly one bounded frame, including fragmented socket reads."""
    header = _recv_exact(conn, _FRAME_HEADER.size, timeout_s)
    (size,) = _FRAME_HEADER.unpack(header)
    if size == 0:
        raise IPCProtocolError("empty IPC frame")
    if size > max_bytes:
        raise IPCFrameTooLarge(f"declared IPC frame is {size} bytes; limit is {max_bytes}")
    body = _recv_exact(conn, size, timeout_s)

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise IPCProtocolError(f"duplicate IPC JSON key: {key}")
            obj[key] = value
        return obj

    try:
        msg = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object)
        if isinstance(msg, dict):
            _wire_json(msg)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise IPCProtocolError(f"invalid IPC JSON: {exc}") from exc
    if not isinstance(msg, dict):
        raise IPCProtocolError("IPC message must be a JSON object")
    return msg


def authenticate_wire(msg: dict[str, Any], key: bytes) -> dict[str, Any]:
    """Return a copy authenticated over canonical JSON (excluding ``auth``)."""
    if len(key) < 32:
        raise ValueError("agent IPC keys must contain at least 32 bytes")
    body = dict(msg)
    body.pop("auth", None)
    body["auth"] = hmac.new(key, _wire_json(body), hashlib.sha256).hexdigest()
    return body


def verify_wire_auth(msg: dict[str, Any], key: bytes) -> None:
    if len(key) < 32:
        raise IPCAuthenticationError("agent IPC key is too short")
    supplied = msg.get("auth")
    if not isinstance(supplied, str) or len(supplied) != 64:
        raise IPCAuthenticationError("missing or malformed IPC authenticator")
    body = dict(msg)
    body.pop("auth", None)
    expected = hmac.new(key, _wire_json(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise IPCAuthenticationError("invalid IPC authenticator")


@dataclass
class ReplayWindow:
    """Bounded in-memory nonce window; capacity exhaustion fails closed."""

    max_entries: int = 4096
    clock_skew_s: float = DEFAULT_CLOCK_SKEW_S
    _seen: dict[tuple[str, str], float] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def consume(self, agent_id: str, nonce: Any, issued_at_ms: Any) -> None:
        if not isinstance(nonce, str) or not (16 <= len(nonce) <= 128):
            raise IPCProtocolError("nonce must be a 16..128 character string")
        if not isinstance(issued_at_ms, int) or isinstance(issued_at_ms, bool):
            raise IPCProtocolError("issued_at_ms must be an integer")
        now_wall = time.time()
        if abs(now_wall - (issued_at_ms / 1000.0)) > self.clock_skew_s:
            raise IPCReplayError("IPC message timestamp outside accepted window")
        key = (agent_id, nonce)
        with self._lock:
            expired = [item for item, expiry in self._seen.items() if expiry <= now_wall]
            for item in expired:
                del self._seen[item]
            if key in self._seen:
                raise IPCReplayError("IPC nonce already consumed")
            if len(self._seen) >= self.max_entries:
                raise IPCReplayError("IPC replay window capacity exhausted")
            # Retain through the message's entire acceptance lifetime. Using
            # ``now + skew`` would expire a future-dated nonce too early.
            self._seen[key] = (issued_at_ms / 1000.0) + self.clock_skew_s


@dataclass(frozen=True)
class Intent:
    agent_id: str
    tool: str
    payload: dict[str, Any]
    intent: str
    resource: str = ""
    request_id: str = ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "v": PROTOCOL,
            "type": "intent",
            "request_id": self.request_id or uuid.uuid4().hex[:12],
            "agent_id": self.agent_id,
            "tool": self.tool,
            "payload": self.payload,
            "intent": self.intent,
            "resource": self.resource,
        }

    @staticmethod
    def from_wire(msg: dict[str, Any]) -> Intent:
        if msg.get("v") != PROTOCOL or msg.get("type") != "intent":
            raise ValueError("invalid intent wire message")
        for key in ("agent_id", "tool", "intent", "request_id"):
            value = msg.get(key)
            if not isinstance(value, str) or not value or len(value) > 128:
                raise ValueError(f"{key} must be a non-empty string of at most 128 characters")
        resource = msg.get("resource", "")
        if not isinstance(resource, str) or len(resource) > 1024:
            raise ValueError("resource must be a string of at most 1024 characters")
        payload = msg.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        return Intent(
            agent_id=msg["agent_id"],
            tool=msg["tool"],
            payload=payload,
            intent=msg["intent"],
            resource=resource,
            request_id=msg["request_id"],
        )


@dataclass
class HostedEvidence:
    request_id: str
    agent_id: str
    tool: str
    ok: bool
    output: Any = None
    error: str | None = None
    sealed_evidence: dict[str, Any] | None = None


@dataclass
class AgentHost:
    """Trusted effect plane. Owns adapters + SealedRuntime. Speaks IPC only."""

    policy: dict[str, Any]
    legitimacy: Callable[[dict[str, Any]], tuple[bool | None, str, tuple[str, ...]]]
    adapters: dict[str, Callable[..., Any]]
    audit_path: str
    spent_store: SpentStore | None = None
    runtime: SealedRuntime = field(init=False)
    evidence: list[HostedEvidence] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        store = self.spent_store or InMemorySpentStore()
        # Copy adapters into a private registry; agent never sees these callables.
        owned = {name: fn for name, fn in self.adapters.items()}
        self.runtime = SealedRuntime(
            self.policy,
            audit_path=self.audit_path,
            legitimacy=self.legitimacy,
            spent_store=store,
        )
        self.runtime.seal(owned)
        # After seal, `owned` values are poisoned; live bodies only inside runtime.
        self.adapters = {k: poison_ref(k) for k in owned}

    def register_agent(self, agent_id: str, *, actor: str, stakeholder: str) -> None:
        self.runtime.register_agent(agent_id, actor=actor, stakeholder=stakeholder)

    def handle_intent(self, intent: Intent) -> HostedEvidence:
        with self._lock:
            ticket = self.runtime.admit(intent.agent_id)
            try:
                out = self.runtime.invoke(
                    ticket=ticket,
                    agent_id=intent.agent_id,
                    tool=intent.tool,
                    payload=intent.payload,
                    intent=intent.intent,
                    resource=intent.resource,
                )
                ev = HostedEvidence(
                    request_id=intent.request_id,
                    agent_id=intent.agent_id,
                    tool=intent.tool,
                    ok=True,
                    output=out,
                    sealed_evidence=self.runtime.evidence[-1].as_dict()
                    if self.runtime.evidence
                    else None,
                )
            except (SealedRefused, AdmissionError, Exception) as exc:
                sealed = None
                if self.runtime.evidence:
                    sealed = self.runtime.evidence[-1].as_dict()
                ev = HostedEvidence(
                    request_id=intent.request_id,
                    agent_id=intent.agent_id,
                    tool=intent.tool,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                    sealed_evidence=sealed,
                )
            self.evidence.append(ev)
            return ev

    def handle_wire(self, msg: dict[str, Any]) -> dict[str, Any]:
        intent = Intent.from_wire(msg)
        ev = self.handle_intent(intent)
        return {
            "v": PROTOCOL,
            "type": "result",
            "request_id": ev.request_id,
            "ok": ev.ok,
            "output": ev.output,
            "error": ev.error,
        }

    def handle_authenticated_wire(
        self,
        msg: dict[str, Any],
        *,
        agent_keys: dict[str, bytes],
        replay: ReplayWindow,
    ) -> dict[str, Any]:
        """Authenticate identity and freshness before admitting any Intent."""
        agent_id = msg.get("agent_id")
        if not isinstance(agent_id, str) or agent_id not in agent_keys:
            raise IPCAuthenticationError("unknown IPC agent identity")
        key = agent_keys[agent_id]
        verify_wire_auth(msg, key)
        replay.consume(agent_id, msg.get("nonce"), msg.get("issued_at_ms"))
        allowed_fields = {
            "v",
            "type",
            "request_id",
            "agent_id",
            "tool",
            "payload",
            "intent",
            "resource",
            "nonce",
            "issued_at_ms",
            "auth",
        }
        unexpected = set(msg) - allowed_fields
        if unexpected:
            raise IPCProtocolError(f"unexpected authenticated Intent fields: {sorted(unexpected)}")
        try:
            response = self.handle_wire(msg)
        except (KeyError, TypeError, ValueError) as exc:
            raise IPCProtocolError(f"invalid authenticated Intent: {exc}") from exc
        response["agent_id"] = agent_id
        return authenticate_wire(response, key)

    def serve_authenticated_socket(
        self,
        conn: socket.socket,
        *,
        agent_keys: dict[str, bytes],
        replay: ReplayWindow | None = None,
        timeout_s: float = DEFAULT_IPC_TIMEOUT_S,
        max_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        """Serve framed Intents on one pre-established socket until EOF/error."""
        window = replay or ReplayWindow()
        while True:
            try:
                msg = recv_frame(conn, max_bytes=max_bytes, timeout_s=timeout_s)
            except EOFError:
                return
            except (IPCFrameTooLarge, IPCTimeout, IPCProtocolError):
                return
            agent_id = msg.get("agent_id")
            key = agent_keys.get(agent_id) if isinstance(agent_id, str) else None
            try:
                response = self.handle_authenticated_wire(
                    msg, agent_keys=agent_keys, replay=window
                )
            except IPCError as exc:
                if key is None:
                    return
                response = authenticate_wire(
                    {
                        "v": PROTOCOL,
                        "type": "result",
                        "request_id": msg.get("request_id", ""),
                        "agent_id": agent_id,
                        "ok": False,
                        "output": None,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                    key,
                )
            try:
                conn.sendall(encode_frame(response, max_bytes=max_bytes))
            except (OSError, IPCError):
                return

    def serve_stdio(self) -> None:
        """Line-delimited JSON IPC on stdin/stdout (host side)."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("type") == "ping":
                    resp = {"v": PROTOCOL, "type": "pong"}
                else:
                    resp = self.handle_wire(msg)
            except Exception as exc:
                resp = {
                    "v": PROTOCOL,
                    "type": "result",
                    "request_id": "",
                    "ok": False,
                    "output": None,
                    "error": f"host_error: {exc}",
                }
            sys.stdout.write(json.dumps(resp, default=str) + "\n")
            sys.stdout.flush()


def poison_ref(name: str) -> Callable[..., Any]:
    def _dead(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError(
            f"adapter {name!r} is not available to agents; effects run only in AgentHost"
        )

    _dead.__name__ = f"host_only_{name}"
    return _dead


@dataclass
class AgentClient:
    """Untrusted side: can only send Intent JSON to the host process."""

    proc: subprocess.Popen[str]
    agent_id: str

    def request(
        self,
        tool: str,
        payload: dict[str, Any],
        intent: str,
        resource: str = "",
    ) -> dict[str, Any]:
        msg = Intent(
            agent_id=self.agent_id,
            tool=tool,
            payload=payload,
            intent=intent,
            resource=resource,
        ).to_wire()
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("host closed IPC")
        return json.loads(line)

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@dataclass
class AuthenticatedAgentClient:
    """Agent-side client for one authenticated, framed, synchronous IPC channel."""

    conn: socket.socket
    agent_id: str
    key: bytes
    timeout_s: float = DEFAULT_IPC_TIMEOUT_S
    max_bytes: int = MAX_FRAME_BYTES

    def request(
        self,
        tool: str,
        payload: dict[str, Any],
        intent: str,
        resource: str = "",
        *,
        request_id: str | None = None,
        nonce: str | None = None,
        issued_at_ms: int | None = None,
    ) -> dict[str, Any]:
        message = Intent(
            agent_id=self.agent_id,
            tool=tool,
            payload=payload,
            intent=intent,
            resource=resource,
            request_id=request_id or uuid.uuid4().hex,
        ).to_wire()
        message["nonce"] = nonce or uuid.uuid4().hex
        message["issued_at_ms"] = issued_at_ms or int(time.time() * 1000)
        signed = authenticate_wire(message, self.key)
        self.conn.settimeout(self.timeout_s)
        try:
            self.conn.sendall(encode_frame(signed, max_bytes=self.max_bytes))
        except TimeoutError as exc:
            raise IPCTimeout("IPC send deadline exceeded") from exc
        response = recv_frame(
            self.conn,
            max_bytes=self.max_bytes,
            timeout_s=self.timeout_s,
        )
        verify_wire_auth(response, self.key)
        if response.get("agent_id") != self.agent_id:
            raise IPCAuthenticationError("response agent identity mismatch")
        if response.get("request_id") != message["request_id"]:
            raise IPCProtocolError("response request_id mismatch")
        return response


def spawn_host(
    *,
    policy: dict[str, Any],
    agent_id: str,
    actor: str,
    stakeholder: str,
    host_script: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> AgentClient:
    """Start AgentHost in a child process; return an Intent-only client.

    The child loads ``agent_host_main`` which registers demo adapters. Production
    hosts should pass their own entrypoint script.
    """
    script = Path(host_script) if host_script else Path(__file__).with_name("_agent_host_main.py")
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    # Pass bootstrap config via env (no shared memory of callables).
    child_env["DECISION_OS_HOST_AGENT_ID"] = agent_id
    child_env["DECISION_OS_HOST_ACTOR"] = actor
    child_env["DECISION_OS_HOST_STAKEHOLDER"] = stakeholder
    child_env["DECISION_OS_HOST_POLICY"] = json.dumps(policy)
    proc = subprocess.Popen(
        [sys.executable, "-u", str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=child_env,
    )
    return AgentClient(proc=proc, agent_id=agent_id)


def locked_agent_docker_cmd(
    agent_script: str | Path,
    *,
    image: str | None = None,
    seccomp: str | Path | None = None,
    lock_script: str | Path | None = None,
) -> list[str]:
    """Build ``docker run … lock_and_run.py <agent>`` for TM-A profile.

    Does not start the container — caller runs it. See ``sandbox/README.md``.
    Host stays *outside* the agent container (IPC via stdin/stdout or network
    to Host is a deployment choice; default probe uses no network).
    """
    root = Path(__file__).resolve().parents[1]
    img = image or os.environ.get("AGENT_SANDBOX_IMAGE", "decision-os-agent:noambient-v1")
    agent = Path(agent_script).resolve()
    lock = (
        str(lock_script)
        if lock_script is not None
        else str(root / "sandbox" / "lock_and_run.py")
    )
    sc = (
        str(seccomp)
        if seccomp is not None
        else str(root / "sandbox" / "seccomp-agent-noambient-v1.json")
    )
    return [
        "docker",
        "run",
        "--rm",
        "-i",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--pids-limit=64",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={sc}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=8m",
        "-v",
        f"{agent}:/agent.py:ro",
        "-v",
        f"{lock}:/lock_and_run.py:ro",
        img,
        "python",
        "/lock_and_run.py",
        "/agent.py",
    ]


def authenticated_agent_docker_cmd(
    agent_script: str | Path,
    *,
    socket_dir: str | Path,
    key_file: str | Path,
    agent_id: str,
    image: str | None = None,
    seccomp: str | Path | None = None,
    lock_script: str | Path | None = None,
) -> list[str]:
    """Build the declared sandbox command for one pre-lock AF_UNIX channel."""
    root = Path(__file__).resolve().parents[1]
    img = image or os.environ.get("AGENT_SANDBOX_IMAGE", "decision-os-agent:noambient-v1")
    agent = Path(agent_script).resolve()
    ipc_dir = Path(socket_dir).resolve()
    key = Path(key_file).resolve()
    lock = Path(lock_script or root / "sandbox" / "lock_and_run.py").resolve()
    profile = Path(seccomp or root / "sandbox" / "seccomp-agent-ipc-v1.json").resolve()
    return [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--pids-limit=64",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={profile}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=8m",
        "--user",
        "65532:65532",
        "-e",
        f"DECISION_OS_AGENT_ID={agent_id}",
        "-e",
        "DECISION_OS_AGENT_SOCKET=/run/decision-os/agent.sock",
        "-e",
        "DECISION_OS_AGENT_KEY=/run/secrets/agent.key",
        "-v",
        f"{ipc_dir}:/run/decision-os:ro",
        "-v",
        f"{key}:/run/secrets/agent.key:ro",
        "-v",
        f"{agent}:/agent.py:ro",
        "-v",
        f"{lock}:/lock_and_run.py:ro",
        img,
        "python",
        "/lock_and_run.py",
        "/agent.py",
    ]


def agent_has_no_effect_handles(namespace: dict[str, Any]) -> bool:
    """Destructor helper: agent namespace must not contain live effect adapters."""
    banned = ("deploy_ranking", "set_price", "send_email", "wire_money", "httpx", "requests")
    for name in banned:
        obj = namespace.get(name)
        name_attr = getattr(obj, "__name__", "")
        if callable(obj) and not name_attr.startswith(("host_only_", "poisoned_")):
            return False
    return True
