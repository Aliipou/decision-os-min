"""Decision OS gateway: put the kernel in front of every agent and every model.

The gateway is a *consumer* of the decision-os-min core, in the same way
``govern.py`` is. It never signs, mints or spends anything itself: every tool
call it sees becomes an ``Action`` that goes through ``Kernel.decide`` and
``Executor.execute``, and the effect (forwarding the call) only runs inside the
executor.

Two interception surfaces cover agents and models:

* ``mcp_proxy`` wraps any stdio MCP server. ``decision-os install`` rewrites the
  MCP config of every detected client (Claude Desktop, Claude Code, Cursor,
  VS Code, Windsurf, Gemini CLI, Codex, LM Studio, Kiro, Cline) so each server
  starts behind the proxy. One command, reversible with ``decision-os uninstall``.
* ``llm_proxy`` sits between an agent and its model API (OpenAI-compatible chat
  completions and Responses, Anthropic Messages). It gates the tool calls the
  model emits before the agent ever receives them, which also covers an agent's
  built-in tools that never touch MCP. ``decision-os run -- <agent>`` starts it
  and points the agent at it.

Policy is a small TOML file (allow / ask / deny rules) compiled into a trusted
``AuthorityPDP``; a deterministic guardrail pack runs as a veto-only evaluator;
``ask`` decisions wait for a human approval bound to the action fingerprint.
"""

from __future__ import annotations

__all__ = ["Gateway", "GovernResult"]


def __getattr__(name: str):  # lazy, so `python -m decision_os_min.gateway` stays light
    if name in {"Gateway", "GovernResult"}:
        from .engine import Gateway, GovernResult

        return {"Gateway": Gateway, "GovernResult": GovernResult}[name]
    raise AttributeError(name)
