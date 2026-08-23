"""Combined TM-H/TM-A boundary over a real locked Docker attach pipe."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from decision_os_min.host import AgentHost, locked_agent_docker_cmd
from decision_os_min.spentstore import InMemorySpentStore

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "sandbox" / "e2e_boundary_agent.py"
IMAGE = os.environ.get("AGENT_SANDBOX_IMAGE", "decision-os-agent:noambient-v1")

POLICY = {
    "grants": {"agent:e2e": ["tool:host_write_receipt"]},
    "purpose_bindings": {"ops": ["record"]},
    "default": "deny",
}


def _docker_required() -> None:
    available = shutil.which("docker") is not None
    if available:
        try:
            check = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )
            available = check.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            available = False
    if available:
        return
    if sys.platform.startswith("linux") and os.environ.get("CI"):
        pytest.fail("Docker is mandatory for the combined boundary test in Linux CI")
    pytest.skip("Docker daemon not available")


def _ensure_image() -> None:
    inspect = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if inspect.returncode == 0:
        return
    build = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            IMAGE,
            "-f",
            str(ROOT / "sandbox" / "Dockerfile.agent"),
            str(ROOT / "sandbox"),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        encoding="utf-8",
        errors="replace",
    )
    assert build.returncode == 0, build.stderr


@pytest.mark.tm_a
def test_locked_agent_intent_ipc_reaches_only_governed_host_effect(tmp_path):
    _docker_required()
    _ensure_image()
    receipt = tmp_path / "host-receipt.txt"

    def host_write_receipt(*, value: str) -> str:
        receipt.write_text(value, encoding="utf-8")
        return "receipt-recorded"

    host = AgentHost(
        policy=POLICY,
        legitimacy=lambda _action: (True, "ok", ()),
        adapters={"host_write_receipt": host_write_receipt},
        audit_path=str(tmp_path / "audit.jsonl"),
        bound_agent_id="sandbox-agent",
        spent_store=InMemorySpentStore(),
    )
    host.register_agent("sandbox-agent", actor="agent:e2e", stakeholder="ops")

    command = locked_agent_docker_cmd(AGENT, image=IMAGE)
    assert "--network=none" in command
    assert all("docker.sock" not in arg for arg in command)
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=ROOT,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    evidence: dict[str, Any] | None = None
    for line in process.stdout:
        stripped = line.strip()
        try:
            frame = json.loads(stripped)
        except json.JSONDecodeError:
            frame = None
        if isinstance(frame, dict) and frame.get("type") == "evidence":
            evidence = frame
            break
        process.stdin.write(host.handle_ipc_line(stripped) + "\n")
        process.stdin.flush()

    process.stdin.close()
    code = process.wait(timeout=180)
    stderr = process.stderr.read()
    assert code == 0, stderr
    assert "LOCKDOWN_FAIL" not in stderr
    assert evidence is not None

    assert evidence["governed"]["ok"] is True
    assert evidence["governed"]["output"] == "receipt-recorded"
    assert receipt.read_text(encoding="utf-8") == "governed-effect"
    assert len(host.evidence) == 1

    assert evidence["malformed"]["ok"] is False
    assert evidence["bypass"]["ok"] is False
    assert str(evidence["direct_adapter"]).startswith("BLOCKED:")

    direct = evidence["direct_effects"]
    for key in ("filesystem", "network", "exec", "fork", "mmap_exec", "mprotect_exec", "ptrace"):
        assert str(direct[key]).startswith("BLOCKED"), direct
    assert direct["credentials"] == "ABSENT"
