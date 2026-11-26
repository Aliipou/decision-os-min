"""End to end: a real MCP client conversation through the proxy subprocess."""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from conftest import APPROVED, DENIED, Approver
from decision_os_min.audit import HashLog

FAKE = Path(__file__).with_name("fake_mcp_server.py")


class Client:
    def __init__(self, home, log_path, server="fs"):
        env = {**__import__("os").environ, "FAKE_MCP_LOG": str(log_path)}
        self.p = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "decision_os_min.gateway",
                "--home",
                str(home.root),
                "mcp-proxy",
                "--client",
                "pytest",
                "--server",
                server,
                "--",
                sys.executable,
                str(FAKE),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.q: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.n = 0

    def _read(self):
        for line in self.p.stdout:
            self.q.put(json.loads(line))

    def send(self, msg):
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def request(self, method, params=None, timeout=15):
        self.n += 1
        rid = self.n
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        return self.wait_for(lambda m: m.get("id") == rid and "method" not in m, timeout)

    def wait_for(self, pred, timeout=15):
        deadline = time.monotonic() + timeout
        stash = []
        try:
            while time.monotonic() < deadline:
                try:
                    m = self.q.get(timeout=0.1)
                except queue.Empty:
                    continue
                if pred(m):
                    return m
                stash.append(m)
            raise AssertionError(f"timed out; saw {stash}")
        finally:
            for m in stash:
                self.q.put(m)

    def call(self, name, args, timeout=15):
        return self.request("tools/call", {"name": name, "arguments": args}, timeout)

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


@pytest.fixture
def client(policy_home, tmp_path):
    c = Client(policy_home, tmp_path / "upstream.log")
    c.upstream_log = tmp_path / "upstream.log"
    init = c.request(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "fake"
    c.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    yield c
    c.close()


def _upstream_calls(c):
    try:
        return [json.loads(x) for x in c.upstream_log.read_text().splitlines()]
    except FileNotFoundError:
        return []


def _text(resp):
    return resp["result"]["content"][0]["text"]


def test_notifications_and_tools_list_hide_denied(client):
    note = client.wait_for(lambda m: m.get("method") == "notifications/message")
    assert note["params"]["data"] == "hello"
    tools = [t["name"] for t in client.request("tools/list")["result"]["tools"]]
    assert "delete_everything" not in tools and {"read_file", "write_file", "ask_roots"} <= set(
        tools
    )


def test_allowed_call_is_forwarded(client):
    r = client.call("read_file", {"path": "/tmp/a"})
    assert json.loads(_text(r)) == {"path": "/tmp/a"} and not r["result"].get("isError")
    assert _upstream_calls(client)[-1]["name"] == "read_file"


def test_denied_call_never_reaches_the_server(client):
    r = client.call("delete_everything", {})
    assert r["result"]["isError"] is True and "Decision OS blocked" in _text(r)
    r = client.call("read_file", {"path": "~/.ssh/id_rsa"})
    assert r["result"]["isError"] is True and "protected" in _text(r)
    assert [c["name"] for c in _upstream_calls(client)] == []


def test_annotation_hint_lets_unclassified_read_tool_run(client):
    client.request("tools/list")
    r = client.call("frobnicate", {})
    assert not r["result"].get("isError")


def test_ask_approve_and_deny(client, policy_home):
    with Approver(policy_home, APPROVED):
        r = client.call("write_file", {"path": "/tmp/x.txt", "content": "hi"})
    assert not r["result"].get("isError")
    with Approver(policy_home, DENIED):
        r = client.call("write_file", {"path": "/tmp/y.txt", "content": "hi"})
    assert r["result"]["isError"] is True and "denied by you" in _text(r)
    assert [c["arguments"]["path"] for c in _upstream_calls(client)] == ["/tmp/x.txt"]


def test_parallel_calls_and_server_initiated_requests(client):
    # a call waiting for approval must not block other traffic
    client.n += 1
    slow_id = client.n
    client.send(
        {
            "jsonrpc": "2.0",
            "id": slow_id,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "/tmp/slow"}},
        }
    )
    fast = client.call("read_file", {"path": "/tmp/fast"})
    assert json.loads(_text(fast)) == {"path": "/tmp/fast"}
    # server -> client request passes through, and the client's answer goes back
    client.n += 1
    rid = client.n
    client.send(
        {
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": "ask_roots", "arguments": {}},
        }
    )
    # ask_roots is unclassified -> ask; approve it from the store
    from decision_os_min.gateway.approvals import ApprovalStore
    from decision_os_min.gateway.paths import Home

    store = ApprovalStore(Home.resolve())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        pend = [p for p in store.pending() if p["tool"] == "ask_roots"]
        if pend:
            store.resolve(pend[0]["id"], APPROVED, by="test")
            break
        time.sleep(0.05)
    srv_req = client.wait_for(lambda m: m.get("method") == "roots/list")
    client.send(
        {"jsonrpc": "2.0", "id": srv_req["id"], "result": {"roots": [{"uri": "file:///w"}]}}
    )
    done = client.wait_for(lambda m: m.get("id") == rid)
    assert json.loads(_text(done)) == {"roots": [{"uri": "file:///w"}]}
    # cancel the slow one: no response is sent, and it never reaches the server
    client.send(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": slow_id, "reason": "user"},
        }
    )
    time.sleep(0.6)
    assert all(m.get("id") != slow_id for m in list(client.q.queue))
    assert "/tmp/slow" not in json.dumps(_upstream_calls(client))


def test_audit_records_every_outcome(client, policy_home):
    client.call("read_file", {"path": "/tmp/a"})
    client.call("delete_everything", {})
    entries = HashLog(policy_home.audit).entries()
    assert [(e["tool"], e["verdict"], e["executed"]) for e in entries[-2:]] == [
        ("fs/read_file", "ALLOW", True),
        ("fs/delete_everything", "DENY", False),
    ]
    assert HashLog(policy_home.audit).verify()


def test_bad_upstream_command_exits_cleanly(policy_home):
    p = subprocess.run(
        [
            sys.executable,
            "-m",
            "decision_os_min.gateway",
            "--home",
            str(policy_home.root),
            "mcp-proxy",
            "--client",
            "t",
            "--server",
            "x",
            "--",
            "definitely-not-a-command-xyz",
        ],
        input=b"",
        capture_output=True,
        timeout=20,
    )
    assert p.returncode == 127 and b"cannot start MCP server" in p.stderr


def test_replies_still_arrive_after_the_client_half_closes(policy_home):
    p = subprocess.run(
        [
            sys.executable,
            "-m",
            "decision_os_min.gateway",
            "--home",
            str(policy_home.root),
            "mcp-proxy",
            "--client",
            "t",
            "--server",
            "fs",
            "--",
            sys.executable,
            str(FAKE),
        ],
        input=b"\n".join(
            json.dumps(m).encode()
            for m in [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}},
                },
            ]
        )
        + b"\n",
        capture_output=True,
        timeout=30,
    )
    replies = {m["id"]: m for m in map(json.loads, p.stdout.decode().splitlines()) if "id" in m}
    assert set(replies) == {1, 2, 3}
    assert replies[3]["result"]["isError"] is True


def test_id_less_tools_call_is_never_forwarded(client):
    client.send(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "delete_everything", "arguments": {}},
        }
    )
    client.send(
        [
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"path": "/x"}},
            }
        ]
    )
    r = client.call("read_file", {"path": "/tmp/after"})  # the proxy is still healthy
    assert not r["result"].get("isError")
    assert [c["name"] for c in _upstream_calls(client)] == ["read_file"]


def test_resources_read_is_governed(client):
    ok = client.request("resources/read", {"uri": "file:///tmp/notes.txt"})
    assert ok["result"]["contents"][0]["text"] == "resource body"
    bad = client.request("resources/read", {"uri": "file:///etc/shadow"})
    assert bad["error"]["code"] == -32001 and "protected" in bad["error"]["message"]
    assert [c["arguments"]["uri"] for c in _upstream_calls(client)] == ["file:///tmp/notes.txt"]
