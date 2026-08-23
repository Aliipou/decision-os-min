"""Hosted Agent Enforcement Plane — process separation + governed IPC."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from decision_os_min.host import AgentHost, Intent, locked_agent_docker_cmd, spawn_host
from decision_os_min.spentstore import InMemorySpentStore

POLICY = {
    "grants": {
        "agent:bot": ["tool:deploy_ranking", "tool:audit_export"],
    },
    "purpose_bindings": {"ops": ["deploy", "audit"], "public": ["audit"]},
    "default": "deny",
}


def _legit(action):
    p = action.get("payload") or {}
    if p.get("dark_pattern"):
        return (False, "C1", ("C1",))
    return (True, "ok", ())


def test_h1_inprocess_host_governed_path(tmp_path):
    effects: list[str] = []

    def deploy_ranking(*, model: str, **kw):
        effects.append(model)
        return f"deployed:{model}"

    host = AgentHost(
        policy=POLICY,
        legitimacy=_legit,
        adapters={"deploy_ranking": deploy_ranking},
        audit_path=str(tmp_path / "a.jsonl"),
        spent_store=InMemorySpentStore(),
    )
    host.register_agent("bot-1", actor="agent:bot", stakeholder="ops")
    # Agent-visible adapters are poisoned.
    with pytest.raises(RuntimeError, match="not available to agents"):
        host.adapters["deploy_ranking"](model="x")

    ok = host.handle_intent(
        Intent("bot-1", "deploy_ranking", {"model": "v1"}, "deploy", "ranking")
    )
    assert ok.ok and ok.output == "deployed:v1"
    assert effects == ["v1"]

    bad = host.handle_intent(
        Intent(
            "bot-1",
            "deploy_ranking",
            {"model": "dark", "dark_pattern": True},
            "deploy",
            "ranking",
        )
    )
    assert bad.ok is False
    assert effects == ["v1"]


def test_h2_spawned_host_ipc_success_and_deny(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISION_OS_HOST_AUDIT", str(tmp_path / "host.jsonl"))
    client = spawn_host(
        policy=POLICY,
        agent_id="bot-1",
        actor="agent:bot",
        stakeholder="ops",
    )
    try:
        assert client.proc.stdout is not None
        ready = json.loads(client.proc.stdout.readline())
        assert ready.get("type") == "ready"

        r1 = client.request("deploy_ranking", {"model": "ok"}, "deploy", "ranking")
        assert r1["ok"] is True and r1["output"] == "deployed:ok"

        r2 = client.request(
            "deploy_ranking",
            {"model": "bad", "dark_pattern": True},
            "deploy",
            "ranking",
        )
        assert r2["ok"] is False
    finally:
        client.close()


def test_h3_untrusted_agent_has_no_tool_handles_and_probes_os(tmp_path):
    """TM-H: no adapters. Ambient OS success here is expected WITHOUT sandbox (not TM-A)."""
    probe = Path(__file__).resolve().parents[1] / "decision_os_min" / "_untrusted_agent_probe.py"
    env = os.environ.copy()
    env["AGENT_PROBE_DIR"] = str(tmp_path)
    r = subprocess.run(
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert r.returncode == 0, r.stderr
    report = json.loads(r.stdout.strip().splitlines()[-1])
    assert report["has_deploy_ranking"] is False
    assert "filesystem" in report["direct_effects"]
    # TM-A is enforced in test_os_isolation.py under Docker — not here.


def test_h4_agent_cannot_import_live_host_adapters_across_ipc():
    """Client only holds AgentClient — no deploy_ranking callable."""
    client = spawn_host(
        policy=POLICY,
        agent_id="bot-1",
        actor="agent:bot",
        stakeholder="ops",
    )
    try:
        assert not hasattr(client, "deploy_ranking")
        assert not callable(getattr(client, "adapters", None))
        assert client.proc.stdout is not None
        json.loads(client.proc.stdout.readline())  # ready
        r = client.request("audit_export", {"scope": "public"}, "audit", "audit")
        assert r["ok"] is True
    finally:
        client.close()


def test_h5_locked_agent_command_uses_declared_tm_a_boundary(tmp_path):
    """Production callers get the same lock path exercised by TM-A probes."""
    agent = tmp_path / "agent.py"
    agent.write_text("print('agent')\n", encoding="utf-8")

    cmd = locked_agent_docker_cmd(
        agent,
        image="agent:test",
        seccomp="/profiles/noambient.json",
        lock_script="/tcb/lock_and_run.py",
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in cmd
    assert "--network=none" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--pids-limit=64" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "--security-opt=seccomp=/profiles/noambient.json" in cmd
    assert "agent:test" in cmd
    assert cmd[-2:] == ["/lock_and_run.py", "/agent.py"]
