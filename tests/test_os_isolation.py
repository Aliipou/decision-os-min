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


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


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
    )
    assert r.returncode == 0, r.stderr
    report = json.loads(r.stdout.strip().splitlines()[-1])
    d = report["direct_effects"]
    # On a normal developer OS, filesystem write to tmp_path should succeed.
    assert d["filesystem"] == "WROTE"
    # credentials should not include host markers in this bare probe
    assert d["credentials"] == "ABSENT"


@pytest.mark.tm_a
def test_tm_a_docker_sandbox_blocks_ambient_effects():
    """PASS criterion for OS-isolated agent under agent-noambient-v1."""
    if os.name == "nt" and not _docker_ok():
        pytest.skip("TM-A Docker profile requires Docker Engine (Linux CI)")
    if not _docker_ok():
        pytest.skip("docker not available")
    if not SCRIPT.is_file():
        pytest.fail("missing sandbox/run_tm_a_probes.sh")

    # Git Bash / WSL / Linux
    shell = shutil.which("bash") or shutil.which("bash.exe")
    if shell is None:
        pytest.skip("bash required to run sandbox script")

    r = subprocess.run(
        [shell, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(ROOT),
    )
    if r.returncode == 2:
        pytest.skip(r.stderr.strip() or "sandbox skipped")
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "TM-A PASS" in r.stdout or "TM-A PASS" in r.stderr or "ambient probes blocked" in (
        r.stdout + r.stderr
    )
