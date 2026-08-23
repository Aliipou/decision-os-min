"""Untrusted agent worker — Intent IPC only. No effect adapters in this process.

Used by destructor tests and as a template for real agents.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path


def try_direct_effects() -> dict[str, str]:
    """Attempt ambient OS effects from the agent process (destructor probes)."""
    out: dict[str, str] = {}
    # 1) filesystem write in CWD / temp
    try:
        p = Path(os.environ.get("AGENT_PROBE_DIR", ".")) / "agent_wrote.txt"
        p.write_text("agent-bypass", encoding="utf-8")
        out["filesystem"] = "WROTE" if p.is_file() else "FAIL"
    except Exception as exc:
        out["filesystem"] = f"BLOCKED:{type(exc).__name__}"
    # 2) localhost connect
    try:
        s = socket.create_connection(("127.0.0.1", 9), timeout=0.3)
        s.close()
        out["network"] = "CONNECTED"
    except Exception as exc:
        out["network"] = f"BLOCKED_OR_REFUSED:{type(exc).__name__}"
    # 3) subprocess
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
    return out


def main() -> None:
    # Agent must NOT import host adapters or SealedRuntime tool bodies.
    # It only speaks JSON Intent on stdin/stdout to a separate host — here we
    # demonstrate the agent-side probe report for the test harness.
    report = {
        "has_deploy_ranking": "deploy_ranking" in globals(),
        "has_host_module_adapters": False,
        "direct_effects": try_direct_effects(),
    }
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
