"""TM-A ambient probes — must fail under agent-noambient-v1 sandbox.

Writes target durable paths (not /tmp) so --read-only without relying on tmpfs policy.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys


def try_direct_effects() -> dict[str, str]:
    out: dict[str, str] = {}

    # 1) filesystem — root of read-only container
    try:
        path = os.environ.get("AGENT_PROBE_PATH", "/agent_wrote.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("agent-bypass")
        out["filesystem"] = "WROTE"
    except Exception as exc:
        out["filesystem"] = f"BLOCKED:{type(exc).__name__}"

    # 2) network
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=0.5)
        s.close()
        out["network"] = "CONNECTED"
    except Exception as exc:
        out["network"] = f"BLOCKED:{type(exc).__name__}"

    # 3) subprocess / exec
    try:
        r = subprocess.run(
            [sys.executable, "-c", "print(1)"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        out["subprocess"] = "RAN" if r.returncode == 0 else f"RC:{r.returncode}"
    except Exception as exc:
        out["subprocess"] = f"BLOCKED:{type(exc).__name__}"

    # 4) credentials leakage markers
    leaked = [k for k in os.environ if k.startswith(("AWS_", "OPENAI_", "DECISION_OS_HOST_"))]
    out["credentials"] = f"LEAKED:{leaked}" if leaked else "ABSENT"

    return out


def main() -> None:
    report = {
        "profile": "agent-noambient-v1",
        "has_deploy_ranking": "deploy_ranking" in globals(),
        "direct_effects": try_direct_effects(),
    }
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
