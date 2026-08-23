"""TM-A OS isolation — claim slices + non-exec destructor class.

TM-A-v1 FS/NET, AgentCreatedProcess, W^X/ptrace under lock_and_run.
TM-A full remains PARTIAL for breakout / Host / pure-Python logic bombs.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from decision_os_min.host import AgentHost, authenticated_agent_docker_cmd

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "sandbox" / "tm_a_probe.py"
LOCK = ROOT / "sandbox" / "lock_and_run.py"
SECCOMP = ROOT / "sandbox" / "seccomp-agent-noambient-v1.json"
DOCKERFILE = ROOT / "sandbox" / "Dockerfile.agent"
IMAGE = os.environ.get("AGENT_SANDBOX_IMAGE", "decision-os-agent:noambient-v1")
AUTHENTICATED_AGENT = ROOT / "sandbox" / "authenticated_intent_agent.py"
IPC_SECCOMP = ROOT / "sandbox" / "seccomp-agent-ipc-v1.json"

_BLOCK = (
    "filesystem",
    "network",
    "subprocess",
    "fork",
    "mmap_exec",
    "mprotect_exec",
    "ptrace",
)


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
        "--pids-limit=64",
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
def test_tm_a_locked_blocks_fs_net_process_and_non_exec():
    """Locked profile: FS/NET/exec/fork + W^X + ptrace BLOCKED."""
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
    for key in _BLOCK:
        assert str(d[key]).startswith("BLOCKED"), d
    assert d["credentials"] == "ABSENT", d


@pytest.mark.tm_a
def test_destructor_unlocked_still_allows_process_and_wx():
    """Without lock_and_run, exec/fork + W^X + ptrace still succeed."""
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
        "--pids-limit=64",
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
    d = json.loads(r.stdout.strip().splitlines()[-1])["direct_effects"]
    assert d["subprocess"] == "RAN"
    assert d["fork"] == "FORKED"
    assert d["mmap_exec"] == "MAPPED"
    assert d["mprotect_exec"] == "EXEC_GRANTED"
    assert d["ptrace"] == "ATTACHED"


@pytest.mark.tm_a
def test_real_sandbox_authenticated_intent_reaches_external_governed_host(tmp_path):
    """Linux/Docker proof: the inherited AF_UNIX FD is the sole agent effect path."""
    if not sys.platform.startswith("linux"):
        pytest.skip("native Linux bind-mounted Unix socket evidence")
    if not _docker_ok():
        if os.environ.get("CI"):
            pytest.fail("Docker is required for Linux CI boundary evidence")
        pytest.skip("docker not available")
    _ensure_agent_image()

    ipc_dir = tmp_path / "ipc"
    ipc_dir.mkdir()
    ipc_dir.chmod(0o777)
    key_file = tmp_path / "agent.key"
    key = os.urandom(32)
    key_file.write_bytes(key)
    key_file.chmod(0o644)
    effect_file = tmp_path / "host-effects.jsonl"
    socket_path = ipc_dir / "agent.sock"

    def legitimacy(action):
        if (action.get("payload") or {}).get("dark_pattern"):
            return (False, "C1: deceptive", ("C1",))
        return (True, "ok", ())

    def deploy_ranking(*, model: str, **_kw):
        with effect_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"model": model}) + "\n")
        return f"deployed:{model}"

    host = AgentHost(
        policy={
            "grants": {"agent:bot": ["tool:deploy_ranking"]},
            "purpose_bindings": {"ops": ["deploy"]},
            "default": "deny",
        },
        legitimacy=legitimacy,
        adapters={"deploy_ranking": deploy_ranking},
        audit_path=str(tmp_path / "host-audit.jsonl"),
    )
    host.register_agent("sandbox-bot", actor="agent:bot", stakeholder="ops")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o666)
    listener.listen(1)
    listener.settimeout(10)
    server_errors: list[Exception] = []

    def serve_external_host():
        try:
            conn, _ = listener.accept()
            with conn:
                host.serve_authenticated_socket(
                    conn,
                    agent_keys={"sandbox-bot": key},
                    timeout_s=5,
                )
        except Exception as exc:
            server_errors.append(exc)

    server = threading.Thread(target=serve_external_host)
    server.start()
    cmd = authenticated_agent_docker_cmd(
        AUTHENTICATED_AGENT,
        socket_dir=ipc_dir,
        key_file=key_file,
        agent_id="sandbox-bot",
        image=IMAGE,
        seccomp=IPC_SECCOMP,
        lock_script=LOCK,
    )
    run = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    server.join(timeout=10)
    listener.close()

    assert run.returncode == 0, f"stdout={run.stdout}\nstderr={run.stderr}"
    assert "LOCKDOWN_FAIL" not in run.stderr
    assert not server.is_alive()
    assert server_errors == []
    report = json.loads(run.stdout.strip().splitlines()[-1])
    assert report["denied"]["ok"] is False
    assert report["allowed"]["ok"] is True
    assert report["allowed"]["output"] == "deployed:sandbox-v1"
    assert report["replay"]["ok"] is False
    assert "IPCReplayError" in report["replay"]["error"]
    assert report["effect_handles"] is False
    for destructor in ("filesystem", "network", "subprocess", "fork"):
        assert report["direct_effects"][destructor].startswith("BLOCKED"), report
    effects = [json.loads(line) for line in effect_file.read_text(encoding="utf-8").splitlines()]
    assert effects == [{"model": "sandbox-v1"}]
