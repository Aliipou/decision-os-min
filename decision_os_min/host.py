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

import json
import os
import subprocess
import sys
import tempfile
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sealed import AdmissionError, SealedRefused, SealedRuntime
from .spentstore import InMemorySpentStore, SpentStore

PROTOCOL = 1


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
        return Intent(
            agent_id=str(msg["agent_id"]),
            tool=str(msg["tool"]),
            payload=dict(msg.get("payload") or {}),
            intent=str(msg["intent"]),
            resource=str(msg.get("resource") or ""),
            request_id=str(msg.get("request_id") or ""),
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


def agent_has_no_effect_handles(namespace: dict[str, Any]) -> bool:
    """Destructor helper: agent namespace must not contain live effect adapters."""
    banned = ("deploy_ranking", "set_price", "send_email", "wire_money", "httpx", "requests")
    for name in banned:
        obj = namespace.get(name)
        if callable(obj) and not getattr(obj, "__name__", "").startswith(("host_only_", "poisoned_")):
            return False
    return True
