"""TM-A OS isolation — ambient effects MUST be BLOCKED under declared profile.

TM-H tests remain in test_hosted_agent_plane.py and must stay green independently.
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
SCRIPT = ROOT / "sandbox" / "run_tm_a_probes.sh"
PROBE = ROOT / "sandbox" / "tm_a_probe.py"
SECCOMP = ROOT / "sandbox" / "seccomp-agent-noambient-v1.json"
IMAGE = os.environ.get("AGENT_SANDBOX_IMAGE", "python:3.12-slim-bookworm")


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


def _run_docker_probe() -> tuple[int, str, str]:
    """Invoke Docker directly (avoids Windows System32 bash + CRLF issues)."""
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
        cwd=str(ROOT),
    )
    return r.returncode, r.stdout, r.stderr


@pytest.mark.tm_a
def test_tm_a_unsandboxed_probe_still_shows_ambient_risk(tmp_path):
    """Control: without sandbox, at least one ambient probe often succeeds.

    Documents why TM-A is not automatic from TM-H.
    """
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
def test_tm_a_docker_sandbox_blocks_ambient_effects():
    """PASS criterion for OS-isolated agent under agent-noambient-v1 (FS+net)."""
    if not _docker_ok():
        pytest.skip("docker not available")
    if not PROBE.is_file() or not SECCOMP.is_file():
        pytest.fail("missing sandbox probe/seccomp files")

    code, stdout, stderr = _run_docker_probe()
    assert code == 0, f"stdout={stdout}\nstderr={stderr}"
    report = json.loads(stdout.strip().splitlines()[-1])
    d = report["direct_effects"]
    assert str(d["filesystem"]).startswith("BLOCKED"), d
    assert str(d["network"]).startswith("BLOCKED"), d
    assert d["credentials"] == "ABSENT", d
    # Residual: subprocess often still RAN — do not gate v1 on exec denial.
    assert "subprocess" in d
