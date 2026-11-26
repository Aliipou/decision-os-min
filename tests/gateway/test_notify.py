"""The approval notification carries an agent-chosen tool name: it must stay data."""

from __future__ import annotations

import json

import pytest

from decision_os_min.gateway.approvals import notify_command

EVIL = 'x$(Set-Content -Path pwned.txt -Value 1)"; do shell script "touch /tmp/p" --'


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_untrusted_text_never_reaches_the_script(platform):
    cmd, env = notify_command("Decision OS: approval needed", f"agent wants fs/{EVIL}", platform)
    assert cmd is not None
    script = cmd[cmd.index("-Command") + 1] if platform == "win32" else cmd[cmd.index("-e") + 1]
    assert "$(" not in script and "pwned" not in script and "touch" not in script
    if platform == "win32":
        assert env is not None and env["DECISION_OS_NOTIFY_BODY"].endswith(EVIL)
        assert all(EVIL not in part for part in cmd)
    else:
        assert cmd[-1].endswith(EVIL)  # an argv item, read via `item 2 of argv`


def test_body_is_truncated():
    cmd, env = notify_command("t", "b" * 500, "win32")
    assert env is not None and len(env["DECISION_OS_NOTIFY_BODY"]) == 200


def test_abandoned_request_is_not_offered_and_cannot_be_approved(fake_home):
    # The app killed the proxy mid-wait: the record stays "pending" with no waiter.
    from datetime import UTC, datetime, timedelta

    from decision_os_min.gateway.approvals import APPROVED, EXPIRED, ApprovalStore

    store = ApprovalStore(fake_home)
    ghost, live = "a" * 64, "b" * 64
    store.request(ghost, {"server": "fs", "tool": "write_file", "expires_in_s": 120})
    rec = store.get(ghost)
    rec["created"] = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    (fake_home.approvals / f"{ghost}.json").write_text(json.dumps(rec), encoding="utf-8")
    store.request(live, {"server": "fs", "tool": "write_file", "expires_in_s": 120})

    assert [r["id"] for r in store.pending()] == [live]
    assert store.resolve(ghost, APPROVED, by="cli")["status"] == EXPIRED
    assert store.resolve(live, APPROVED, by="cli")["status"] == APPROVED
