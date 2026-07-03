"""The forced path: a governed tool cannot execute without the kernel.

This is the adoption surface — the "one line" that turns Decision OS from an
optional library into the *path of least resistance*. You wrap a tool once; from
then on there is **no way to call it that bypasses the kernel**, because the
wrapped callable IS the governed tool. Removing governance means deleting the
wrapper and losing your audit trail — the friction runs the right direction.

    gov = Governor(policy, audit_path="audit.jsonl")

    @gov.tool("send_email", capability="tool:send_email", purpose="support_reply",
              data_labels=["customer_support"])
    def send_email(to: str, body: str) -> str:
        ...                      # only ever runs if the kernel permits it

    set_actor("agent:bot")       # admission/identity — set by your app per agent
    send_email(to="x", body="y") # routed through decide -> audit -> execute

The wrapper holds no authority: the kernel decides, this only makes the kernel
unavoidable. The core is untouched — `govern.py` only consumes it.
"""

from __future__ import annotations

import contextvars
import functools
import uuid
from collections.abc import Callable
from typing import Any

# The calling agent's identity. Your app sets this per request/agent (admission);
# the kernel decides authority from it. Default is a principal with no grants.
current_actor: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_actor", default="agent:unknown"
)


def set_actor(actor: str) -> contextvars.Token[str]:
    """Bind the current agent identity (returns a token to reset if you want)."""
    return current_actor.set(actor)


class GovernanceRefused(RuntimeError):
    """Raised when the kernel does not permit a governed tool call."""

    def __init__(self, verdict: str, reason: str | None) -> None:
        super().__init__(f"governance refused: {verdict} ({reason})")
        self.verdict = verdict
        self.reason = reason


class Governor:
    def __init__(self, policy: dict[str, Any], *, audit_path: str) -> None:
        from decision_os_min import DecisionOS  # lazy: DecisionOS lives in __init__

        self._dos = DecisionOS(policy, audit_path=audit_path)

    @property
    def public_key(self) -> str:
        return self._dos.kernel.public_key_hex()

    def tool(
        self,
        name: str,
        *,
        capability: str | None = None,
        purpose: str | None = None,
        data_labels: list[str] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: wrap a tool so every call is routed through the kernel. The
        tool's keyword arguments become the action payload."""

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(fn)
            def governed(**payload: Any) -> Any:
                action = {
                    "actor": current_actor.get(),
                    "tool": name,
                    "capability": capability or f"tool:{name}",
                    "action_purpose": purpose or "",
                    "data_labels": list(data_labels or []),
                    "payload": payload,
                    "nonce": uuid.uuid4().hex[:12],
                }
                outcome = self._dos.handle(action, {name: lambda p: fn(**p)})
                if not outcome.executed:
                    raise GovernanceRefused(outcome.verdict, outcome.refused_reason)
                return outcome.output

            governed.__wrapped_tool__ = name  # type: ignore[attr-defined]
            return governed

        return decorate

    def wrap(
        self,
        tools: dict[str, Callable[..., Any]],
        *,
        specs: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Callable[..., Any]]:
        """Govern a whole tool registry at once (e.g. an agent framework's tools).
        `specs[name]` may carry capability/purpose/data_labels per tool."""
        specs = specs or {}
        return {
            name: self.tool(name, **specs.get(name, {}))(fn) for name, fn in tools.items()
        }
