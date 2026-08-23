"""Stdio AgentHost entrypoint — runs in the TRUSTED process.

Configured via env:
  DECISION_OS_HOST_POLICY (JSON)
  DECISION_OS_HOST_AGENT_ID / ACTOR / STAKEHOLDER
  DECISION_OS_HOST_AUDIT (optional path)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# Ensure package import when launched as a script path.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from decision_os_min.host import AgentHost  # noqa: E402


def _legit(action: dict) -> tuple[bool | None, str, tuple[str, ...]]:
    p = action.get("payload") or {}
    if p.get("dark_pattern"):
        return (False, "C1: deceptive", ("C1",))
    if p.get("unresolved"):
        return (None, "C6: defer", ("C6",))
    return (True, "ok", ())


def main() -> None:
    policy = json.loads(os.environ["DECISION_OS_HOST_POLICY"])
    agent_id = os.environ["DECISION_OS_HOST_AGENT_ID"]
    actor = os.environ["DECISION_OS_HOST_ACTOR"]
    stakeholder = os.environ["DECISION_OS_HOST_STAKEHOLDER"]
    audit = os.environ.get("DECISION_OS_HOST_AUDIT") or str(
        Path(tempfile.gettempdir()) / f"agent_host_{os.getpid()}.jsonl"
    )

    effects: list[str] = []

    def deploy_ranking(*, model: str, **kw: object) -> str:
        effects.append(model)
        return f"deployed:{model}"

    def audit_export(*, scope: str = "public") -> str:
        effects.append(scope)
        return f"audit:{scope}"

    host = AgentHost(
        policy=policy,
        legitimacy=_legit,
        adapters={"deploy_ranking": deploy_ranking, "audit_export": audit_export},
        audit_path=audit,
    )
    host.register_agent(agent_id, actor=actor, stakeholder=stakeholder)
    # Ready signal so client can sync (optional ping).
    sys.stdout.write(json.dumps({"v": 1, "type": "ready"}) + "\n")
    sys.stdout.flush()
    host.serve_stdio()


if __name__ == "__main__":
    main()
