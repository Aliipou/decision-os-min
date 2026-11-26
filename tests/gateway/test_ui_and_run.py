from __future__ import annotations

import http.client
import json
import subprocess
import sys
import textwrap
import threading

import pytest
from test_llm_proxy import Upstream

from decision_os_min.gateway.approvals import ApprovalStore
from decision_os_min.gateway.policy import load_policy
from decision_os_min.gateway.ui import Dashboard


@pytest.fixture
def dash(policy_home):
    d = Dashboard(policy_home)
    srv = d.serve(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield d, srv.server_address[1]
    srv.shutdown()


def req(port, method, path, *, token=None, body=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}", "Content-Type": "application/json"}
    if token:
        headers["X-DOS-Token"] = token
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    r = c.getresponse()
    data = r.read()
    return r.status, data


def test_dashboard_requires_token_and_loopback_host(dash):
    d, port = dash
    assert req(port, "GET", "/")[0] == 403
    assert req(port, "GET", f"/?t={d.token}")[0] == 200
    assert req(port, "GET", f"/?t={d.token}", host="evil.example:80")[0] == 403
    assert req(port, "GET", "/api/state")[0] == 403
    status, data = req(port, "GET", "/api/state", token=d.token)
    assert status == 200 and json.loads(data)["mode"] == "enforce"
    assert req(port, "POST", "/api/mode", body={"mode": "observe"})[0] == 403


def test_dashboard_resolves_and_toggles_mode(dash, policy_home):
    d, port = dash
    store = ApprovalStore(policy_home)
    fp = "ab" * 32
    store.request(fp, {"client": "c", "server": "fs", "tool": "write_file", "rememberable": True})
    state = json.loads(req(port, "GET", "/api/state", token=d.token)[1])
    assert [p["id"] for p in state["pending"]] == [fp]
    status, _ = req(
        port,
        "POST",
        "/api/resolve",
        token=d.token,
        body={"id": fp, "decision": "approve", "remember": True},
    )
    assert status == 200 and store.is_approved(fp)
    assert d.learned.load() == {"c|fs|write_file": "allow"}
    assert req(port, "POST", "/api/mode", token=d.token, body={"mode": "observe"})[0] == 200
    assert load_policy(policy_home.policy).mode == "observe"
    assert req(port, "POST", "/api/mode", token=d.token, body={"mode": "chaos"})[0] == 400
    assert (
        req(port, "POST", "/api/forget", token=d.token, body={"key": "c|fs|write_file"})[0] == 200
    )
    assert d.learned.load() == {}


def test_run_wraps_an_agent_process(policy_home, tmp_path):
    from http.server import ThreadingHTTPServer

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    agent = tmp_path / "agent.py"
    agent.write_text(
        textwrap.dedent("""
        import json, os, urllib.request
        base = os.environ["OPENAI_BASE_URL"]
        req = urllib.request.Request(base + "/chat/completions", method="POST",
            data=json.dumps({"model": "gpt-x", "messages": []}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer k"})
        msg = json.loads(urllib.request.urlopen(req).read())["choices"][0]["message"]
        print(json.dumps({"tools": [t["function"]["name"] for t in msg.get("tool_calls", [])],
                          "agent": os.environ["DECISION_OS_AGENT"]}))
    """)
    )
    try:
        out = subprocess.run(
            [
                sys.executable,
                "-m",
                "decision_os_min.gateway",
                "--home",
                str(policy_home.root),
                "run",
                "--agent",
                "toy-agent",
                "--upstream",
                f"openai=http://127.0.0.1:{srv.server_address[1]}/v1",
                "--",
                sys.executable,
                str(agent),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        srv.shutdown()
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == {
        "tools": ["get_weather"],
        "agent": "toy-agent",
    }
    from decision_os_min.audit import HashLog

    tail = HashLog(policy_home.audit).entries()[-2:]
    assert {(e["actor"], e["tool"], e["verdict"]) for e in tail} == {
        ("agent:toy-agent", "llm/get_weather", "ALLOW"),
        ("agent:toy-agent", "llm/delete_repo", "DENY"),
    }
