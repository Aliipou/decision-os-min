"""TM-A OS isolation — claim slices, not bare TM-A PASS.

TM-A-v1 FS/NET: durable write + outbound net + creds.
TM-A full: also AgentCreatedProcess (post-bootstrap lock).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "sandbox" / "tm_a_probe.py"
LOCK = ROOT / "sandbox" / "lock_and_run.py"
SECCOMP = ROOT / "sandbox" / "seccomp-agent-noambient-v1.json"
DOCKERFILE = ROOT / "sandbox" / "Dockerfile.agent"
IMAGE = os.environ.get("AGENT_SANDBOX_IMAGE", "decision-os-agent:noambient-v1")


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ensure_agent_image() -> None:
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
        ["docker", "build", "-t", IMAGE, "-f", str(DOCKERFILE), str(ROOT / "sandbox")],
        capture_output=True,
        text=True,
        timeout=300,
        encoding="utf-8",
        errors="replace",
    )
    assert build.returncode == 0, build.stderr


def _run_locked_probe() -> tuple[int, str, str]:
    _ensure_agent_image()
    cmd = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={SECCOMP}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=8m",
        "-e",
        "AGENT_PROBE_PATH=/agent_wrote.txt",
        "-v",
        f"{PROBE}:/probe.py:ro",
        "-v",
        f"{LOCK}:/lock_and_run.py:ro",
        IMAGE,
        "python",
        "/lock_and_run.py",
        "/probe.py",
    ]
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    return r.returncode, r.stdout, r.stderr


@pytest.mark.tm_a
def test_tm_a_unsandboxed_probe_still_shows_ambient_risk(tmp_path):
    """Control: without sandbox, ambient FS write succeeds — TM-A is not free."""
    env = os.environ.copy()
    env["AGENT_PROBE_PATH"] = str(tmp_path / "agent_wrote.txt")
    r = subprocess.run(
        [sys.executable, str(PROBE)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        encoding="utf-8",
        errors="replace",
    )
    assert r.returncode == 0, r.stderr
    report = json.loads(r.stdout.strip().splitlines()[-1])
    d = report["direct_effects"]
    assert d["filesystem"] == "WROTE"
    assert d["credentials"] == "ABSENT"


@pytest.mark.tm_a
def test_tm_a_v1_fs_net_and_process_lock():
    """TM-A-v1 FS/NET + process-lock candidate: FS, net, subprocess BLOCKED."""
    if not _docker_ok():
        pytest.skip("docker not available")
    for path in (PROBE, LOCK, SECCOMP, DOCKERFILE):
        if not path.is_file():
            pytest.fail(f"missing {path}")

    code, stdout, stderr = _run_locked_probe()
    assert code == 0, f"stdout={stdout}\nstderr={stderr}"
    assert "LOCKDOWN_FAIL" not in stderr
    report = json.loads(stdout.strip().splitlines()[-1])
    d = report["direct_effects"]
    assert str(d["filesystem"]).startswith("BLOCKED"), d
    assert str(d["network"]).startswith("BLOCKED"), d
    assert str(d["subprocess"]).startswith("BLOCKED"), d
    assert d["credentials"] == "ABSENT", d


@pytest.mark.tm_a
def test_destructor_unlocked_container_still_allows_subprocess():
    """Destructor: without lock_and_run, subprocess still RAN (documents residual)."""
    if not _docker_ok():
        pytest.skip("docker not available")
    _ensure_agent_image()
    cmd = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={SECCOMP}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=8m",
        "-e",
        "AGENT_PROBE_PATH=/agent_wrote.txt",
        "-v",
        f"{PROBE}:/probe.py:ro",
        IMAGE,
        "python",
        "/probe.py",
    ]
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
        encoding="utf-8",
        errors="replace",
    )
    assert r.returncode == 0, r.stderr
    report = json.loads(r.stdout.strip().splitlines()[-1])
    assert report["direct_effects"]["subprocess"] == "RAN"
