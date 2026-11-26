from __future__ import annotations

import json
import subprocess
import sys
import textwrap

from conftest import APPROVED, DENIED, Approver, write_policy
from decision_os_min.audit import HashLog
from decision_os_min.gateway.engine import Gateway


def _calls():
    seen = []

    def release(payload):
        seen.append(payload)
        return {"ok": True, "payload": payload}

    return seen, release


def test_allowed_call_runs_once_and_is_audited(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    res = gw.govern(server="fs", tool="read_file", arguments={"path": "/tmp/x"}, release=release)
    assert res.executed and res.verdict == "ALLOW"
    assert seen == [{"path": "/tmp/x"}]
    last = gw.log.tail(1)[0]
    assert (
        last["executed"] is True
        and last["tool"] == "fs/read_file"
        and last["actor"] == "agent:test"
    )


def test_denied_call_never_reaches_the_tool(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    res = gw.govern(server="fs", tool="delete_everything", arguments={}, release=release)
    assert not res.executed and res.verdict == "DENY" and "never" in res.reason
    assert seen == []
    assert gw.log.tail(1)[0]["executed"] is False


def test_argument_rule_allows_only_inside_the_glob(policy_home):
    gw = Gateway(client="test", home=policy_home, interactive=False)
    seen, release = _calls()
    assert gw.govern(
        server="fs", tool="write_file", arguments={"path": "/tmp/allowed/a.txt"}, release=release
    ).executed
    # path traversal is normalized before matching, so it falls back to "ask"
    res = gw.govern(
        server="fs",
        tool="write_file",
        arguments={"path": "/tmp/allowed/../elsewhere.txt"},
        release=release,
    )
    assert not res.executed and res.verdict == "DEFER"
    assert len(seen) == 1


def test_ask_then_approve_runs_exactly_that_call(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    with Approver(policy_home, APPROVED) as ap:
        res = gw.govern(
            server="fs", tool="write_file", arguments={"path": "/tmp/other.txt"}, release=release
        )
    assert res.executed and res.approval
    assert ap.seen and ap.seen[0]["tool"] == "write_file" and ap.seen[0]["rememberable"] is True
    assert seen == [{"path": "/tmp/other.txt"}]
    verdicts = [e["verdict"] for e in gw.log.tail(2)]
    assert verdicts == ["DEFER", "ALLOW"]
    # the approval unlocked that one action only: the next identical call asks again
    gw2 = Gateway(client="test", home=policy_home, interactive=False)
    again = gw2.govern(
        server="fs", tool="write_file", arguments={"path": "/tmp/other.txt"}, release=release
    )
    assert not again.executed and again.verdict == "DEFER"


def test_ask_then_deny(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    with Approver(policy_home, DENIED):
        res = gw.govern(
            server="fs", tool="write_file", arguments={"path": "/tmp/o.txt"}, release=release
        )
    assert not res.executed and "denied by you" in res.reason
    assert seen == []
    assert gw.log.tail(1)[0]["verdict"] == "DENY"


def test_ask_times_out_closed(fake_home):
    write_policy(fake_home, timeout=0.5)
    gw = Gateway(client="test", home=fake_home)
    seen, release = _calls()
    res = gw.govern(
        server="fs", tool="write_file", arguments={"path": "/tmp/t.txt"}, release=release
    )
    assert not res.executed and "timeout" in res.reason
    assert seen == []


def test_always_allow_is_remembered_but_explicit_deny_still_wins(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    with Approver(policy_home, APPROVED, remember=True):
        assert gw.govern(
            server="fs", tool="move_file", arguments={"a": 1}, release=release
        ).executed
    # remembered: no approval needed next time, different arguments included
    assert gw.govern(server="fs", tool="move_file", arguments={"a": 2}, release=release).executed
    gw.learned.remember("test", "fs", "delete_everything", "allow")
    assert not gw.govern(
        server="fs", tool="delete_everything", arguments={}, release=release
    ).executed


def test_limit_redacts_before_the_tool_sees_it(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    res = gw.govern(
        server="mail",
        tool="send_email",
        arguments={"to": "a@b.c", "password": "hunter2"},
        release=release,
    )
    assert res.executed and res.verdict == "LIMIT"
    assert seen == [{"to": "a@b.c", "password": "[REDACTED]"}]


def test_guardrails_veto_even_when_policy_allows(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    res = gw.govern(
        server="fs", tool="read_file", arguments={"path": "~/.ssh/id_ed25519"}, release=release
    )
    assert not res.executed and res.verdict == "DENY" and "protected" in res.reason
    res = gw.govern(
        server="mail",
        tool="send_email",
        arguments={"to": "x@y.z", "body": "key AKIAABCDEFGHIJKLMNOP"},
        release=release,
    )
    assert not res.executed and "AWS access key" in res.reason
    assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(gw.log.tail(5))  # never echoed into the log
    assert seen == []


def test_guardrail_ask_is_not_rememberable(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    with Approver(policy_home, APPROVED) as ap:
        res = gw.govern(
            server="shell",
            tool="read_output",
            arguments={"command": "git push --force origin main"},
            release=release,
        )
    assert res.executed
    assert ap.seen[0]["rememberable"] is False  # a guardrail asked, not the policy


def test_self_protection_cannot_be_observed_away(fake_home):
    write_policy(fake_home, 'mode = "observe"\nnotify = false\nopen_dashboard = false\n')
    gw = Gateway(client="test", home=fake_home)
    seen, release = _calls()
    res = gw.govern(
        server="fs",
        tool="write_file",
        arguments={"path": str(fake_home.root / "approvals" / "x.json")},
        release=release,
    )
    assert not res.executed and "self-protection" in res.reason
    res = gw.govern(
        server="fs", tool="write_file", arguments={"path": "~/.cursor/mcp.json"}, release=release
    )
    assert not res.executed
    # but ordinary asks and guardrail denies only get recorded in observe mode
    res = gw.govern(
        server="fs", tool="delete_file", arguments={"path": "~/.aws/credentials"}, release=release
    )
    assert res.executed and res.reason.startswith("observe:")


def test_policy_error_fails_closed_and_recovers(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    write_policy(policy_home, 'mode = "enforce"\nprofile = "wild"\n')
    res = gw.govern(server="fs", tool="read_file", arguments={}, release=release)
    assert not res.executed and "policy error" in res.reason
    write_policy(policy_home)
    assert gw.govern(server="fs", tool="read_file", arguments={}, release=release).executed


def test_non_json_arguments_are_refused(policy_home):
    gw = Gateway(client="test", home=policy_home)
    seen, release = _calls()
    assert not gw.govern(server="fs", tool="read_file", arguments=["x"], release=release).executed
    assert not gw.govern(
        server="fs", tool="read_file", arguments={"x": object()}, release=release
    ).executed
    assert seen == []


def test_audit_chain_holds_across_processes(policy_home):
    script = textwrap.dedent(f"""
        import sys
        from decision_os_min.gateway.engine import Gateway
        from decision_os_min.gateway.paths import Home
        gw = Gateway(client="p" + sys.argv[1], home=Home({str(policy_home.root)!r}))
        for i in range(20):
            gw.govern(server="fs", tool="read_file", arguments={{"i": i}}, release=lambda p: p)
    """)
    procs = [subprocess.Popen([sys.executable, "-c", script, str(n)]) for n in range(4)]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    log = HashLog(policy_home.audit)
    entries = log.entries()
    assert len(entries) == 80
    assert [e["seq"] for e in entries] == list(range(80))
    assert log.verify()
