from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from decision_os_min.gateway.approvals import APPROVED, DENIED, ApprovalStore
from decision_os_min.gateway.paths import Home, write_private

BASE_POLICY = """
mode = "enforce"
profile = "balanced"
ask_timeout_seconds = {timeout}
notify = false
open_dashboard = false

[[rule]]
tool = "delete_everything"
decision = "deny"
reason = "never"

[[rule]]
server = "fs"
tool = "write_file"
args = {{ path = "/tmp/allowed/*" }}
decision = "allow"

[[rule]]
tool = "send_email"
decision = "allow"
redact = ["password"]

[[rule]]
server = "llm"
tool = "get_weather"
decision = "allow"

[[rule]]
server = "llm"
tool = "delete_repo"
decision = "deny"
reason = "repos are not deleted by agents"
"""


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Isolate HOME (so no real client config is ever touched) and the gateway home."""
    user = tmp_path / "user"
    user.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(user))
    monkeypatch.setenv("APPDATA", str(user / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(user / "AppData" / "Local"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(user / ".config"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    gw_home = user / ".decision-os"
    monkeypatch.setenv("DECISION_OS_HOME", str(gw_home))
    return Home(gw_home).ensure()


def write_policy(home: Home, text: str | None = None, *, timeout: float = 5) -> None:
    write_private(home.policy, text if text is not None else BASE_POLICY.format(timeout=timeout))
    # mtime granularity: make sure a rewrite in the same tick is seen as a change
    st = home.policy.stat()
    os.utime(home.policy, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))


@pytest.fixture
def policy_home(fake_home):
    write_policy(fake_home)
    return fake_home


class Approver:
    """Background thread that answers the first pending approval."""

    def __init__(
        self, home: Home, decision: str = APPROVED, remember: bool = False, delay: float = 0.1
    ) -> None:
        self.store = ApprovalStore(home)
        self.decision, self.remember, self.delay = decision, remember, delay
        self.seen: list[dict] = []
        self._t = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> Approver:
        self._t.start()
        return self

    def __exit__(self, *exc) -> None:
        self._t.join(timeout=10)

    def _run(self) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            pending = self.store.pending()
            if pending:
                time.sleep(self.delay)
                rec = pending[0]
                self.seen.append(rec)
                self.store.resolve(rec["id"], self.decision, by="test", remember=self.remember)
                return
            time.sleep(0.05)


__all__ = ["Approver", "APPROVED", "DENIED", "write_policy", "Path"]
