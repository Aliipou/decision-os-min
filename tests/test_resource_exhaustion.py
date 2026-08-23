"""Resource-exhaustion controls and bounded Docker attack evidence."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from decision_os_min.host import locked_agent_docker_cmd

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "sandbox" / "resource_exhaustion_probe.py"
IMAGE = "decision-os-agent:noambient-v1"


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run(mode: str, wall_timeout_s: int) -> tuple[subprocess.CompletedProcess[str], bool, float]:
    name = f"decision-os-resource-{uuid.uuid4().hex[:10]}"
    cmd = locked_agent_docker_cmd(
        PROBE,
        image=IMAGE,
        agent_args=(mode,),
        wall_timeout_s=wall_timeout_s,
    )
    cmd.remove("--rm")
    cmd[3:3] = ["--name", name]
    started = time.monotonic()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=wall_timeout_s + 15)
        elapsed = time.monotonic() - started
        inspect = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.OOMKilled}}", name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert inspect.returncode == 0, inspect.stderr
        return result, inspect.stdout.strip().lower() == "true", elapsed
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10)


def test_locked_command_declares_all_resource_controls():
    cmd = locked_agent_docker_cmd(PROBE, agent_args=("fd",), wall_timeout_s=7)
    for control in (
        "--pids-limit=64",
        "--memory=128m",
        "--memory-swap=128m",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
    ):
        assert control in cmd
    assert cmd[-7:] == [
        "timeout",
        "--signal=KILL",
        "7s",
        "python",
        "/lock_and_run.py",
        "/agent.py",
        "fd",
    ]


@pytest.mark.tm_a
def test_fork_thread_and_fd_attacks_are_blocked_or_limited():
    if not _docker_ok():
        pytest.skip("docker not available")
    for mode, expected in (("fork", "BLOCKED"), ("thread", "BLOCKED"), ("fd", "LIMITED")):
        result, oom_killed, _ = _run(mode, 10)
        assert result.returncode == 0, result.stderr
        evidence = json.loads(result.stdout.strip().splitlines()[-1])
        assert evidence["outcome"].startswith(expected), evidence
        assert oom_killed is False


@pytest.mark.tm_a
def test_memory_pressure_is_oom_killed():
    if not _docker_ok():
        pytest.skip("docker not available")
    result, oom_killed, _ = _run("memory", 10)
    assert result.returncode != 0
    assert oom_killed is True


@pytest.mark.tm_a
def test_cpu_loop_is_wall_killed_not_claimed_blocked():
    if not _docker_ok():
        pytest.skip("docker not available")
    result, oom_killed, elapsed = _run("cpu", 2)
    assert result.returncode != 0
    assert oom_killed is False
    assert 1.5 <= elapsed < 10
