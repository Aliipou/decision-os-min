"""Human approval for ``ask`` decisions, bound to one exact action.

A pending request is a file named after the action fingerprint (the same sha256
the kernel signs into the decision). Approving it unlocks exactly that action:
same actor, tool, arguments and nonce. Any other call, including a retry with
one byte changed, has a different fingerprint and needs its own approval.

Resolution comes from the dashboard (``decision-os ui``) or the terminal
(``decision-os approve``). Both only write files here; they hold no keys.

Trust boundary, stated plainly: anything running as the same OS user can write
these files. The guardrails stop *governed tool calls* from touching this
directory, but a process outside the gateway is outside its reach. Run agents
under a separate user or in the provided sandbox when that matters.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .locking import file_lock
from .paths import Home, write_private

PENDING, APPROVED, DENIED, EXPIRED, CANCELLED = (
    "pending",
    "approved",
    "denied",
    "expired",
    "cancelled",
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ApprovalStore:
    def __init__(self, home: Home) -> None:
        self.home = home
        self.dir = home.approvals

    def _path(self, fp: str) -> Path:
        if not fp or not all(c in "0123456789abcdef" for c in fp):
            raise ValueError("approval id must be a hex fingerprint")
        return self.dir / f"{fp}.json"

    def get(self, fp: str) -> dict[str, Any] | None:
        try:
            return json.loads(self._path(fp).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            return None

    def status(self, fp: str) -> str | None:
        rec = self.get(fp)
        return rec.get("status") if rec else None

    def is_approved(self, fp: str) -> bool:
        return self.status(fp) == APPROVED

    def request(self, fp: str, info: dict[str, Any]) -> dict[str, Any]:
        rec = {"id": fp, "status": PENDING, "created": _now(), **info}
        with file_lock(self.home.locks / "approvals.lock"):
            existing = self.get(fp)
            if existing and existing.get("status") != PENDING:
                return existing
            write_private(self._path(fp), json.dumps(rec, indent=2))
        return rec

    def resolve(self, fp: str, decision: str, *, by: str, remember: bool = False) -> dict[str, Any]:
        if decision not in (APPROVED, DENIED):
            raise ValueError("decision must be 'approved' or 'denied'")
        with file_lock(self.home.locks / "approvals.lock"):
            rec = self.get(fp)
            if rec is None:
                raise KeyError(fp)
            if rec.get("status") != PENDING:
                return rec
            rec.update(status=decision, resolved=_now(), resolved_by=by, remember=remember)
            write_private(self._path(fp), json.dumps(rec, indent=2))
        if remember and rec.get("rememberable"):
            LearnedStore(self.home).remember(
                rec.get("client", "*"),
                rec["server"],
                rec["tool"],
                "allow" if decision == APPROVED else "deny",
            )
        return rec

    def _finish(self, fp: str, status: str) -> None:
        with file_lock(self.home.locks / "approvals.lock"):
            rec = self.get(fp)
            if rec and rec.get("status") == PENDING:
                rec.update(status=status, resolved=_now(), resolved_by="gateway")
                write_private(self._path(fp), json.dumps(rec, indent=2))

    def wait(
        self,
        fp: str,
        timeout_s: float,
        *,
        cancelled: threading.Event | None = None,
        poll_s: float = 0.2,
    ) -> str:
        deadline = time.monotonic() + timeout_s
        while True:
            st = self.status(fp)
            if st in (APPROVED, DENIED):
                return st
            if cancelled is not None and cancelled.is_set():
                self._finish(fp, CANCELLED)
                return CANCELLED
            if time.monotonic() >= deadline:
                self._finish(fp, EXPIRED)
                return EXPIRED
            time.sleep(poll_s)

    def pending(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if rec.get("status") == PENDING:
                out.append(rec)
        return sorted(out, key=lambda r: r.get("created", ""))

    def recent(self, n: int = 50) -> list[dict[str, Any]]:
        recs = []
        for p in self.dir.glob("*.json"):
            try:
                recs.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(recs, key=lambda r: r.get("created", ""), reverse=True)[:n]

    def prune(self, older_than_s: float = 7 * 24 * 3600) -> int:
        cutoff = time.time() - older_than_s
        n = 0
        for p in self.dir.glob("*.json"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
                    n += 1
            except OSError:
                pass
        return n


class LearnedStore:
    """'Always allow / always deny' choices made on the dashboard."""

    def __init__(self, home: Home) -> None:
        self.home = home
        self.path = home.learned
        self._cache: tuple[float, dict[str, str]] | None = None

    def load(self) -> dict[str, str]:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return {}
        if self._cache and self._cache[0] == mtime:
            return self._cache[1]
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            entries = {
                str(k): str(v)
                for k, v in data.get("decisions", {}).items()
                if v in ("allow", "deny")
            }
        except (OSError, json.JSONDecodeError, AttributeError):
            entries = {}
        self._cache = (mtime, entries)
        return entries

    def revision(self) -> str:
        try:
            return f"learned@{self.path.stat().st_mtime_ns}"
        except FileNotFoundError:
            return "learned@none"

    def remember(self, client: str, server: str, tool: str, decision: str) -> None:
        from .policy import learned_key

        with file_lock(self.home.locks / "learned.lock"):
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                data = {}
            decisions = data.setdefault("decisions", {})
            decisions[learned_key(client, server, tool)] = decision
            data["updated"] = _now()
            write_private(self.path, json.dumps(data, indent=2, sort_keys=True))
        self._cache = None

    def forget(self, key: str) -> bool:
        with file_lock(self.home.locks / "learned.lock"):
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                return False
            removed = data.get("decisions", {}).pop(key, None) is not None
            write_private(self.path, json.dumps(data, indent=2, sort_keys=True))
        self._cache = None
        return removed


# --------------------------------------------------------------- side effects


def notify(title: str, body: str) -> None:
    """Best-effort desktop notification. Never raises, never blocks."""
    body = body[:200]
    try:
        if sys.platform == "darwin":
            script = f"display notification {json.dumps(body)} with title {json.dumps(title)}"
            cmd = ["osascript", "-e", script]
        elif os.name == "nt":
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Shield;$n.Visible=$true;"
                f"$n.ShowBalloonTip(8000,{json.dumps(title)},{json.dumps(body)},'Warning');"
                "Start-Sleep -Seconds 9;$n.Dispose()"
            )
            cmd = ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps]
        elif shutil.which("notify-send"):
            cmd = ["notify-send", "--app-name=Decision OS", title, body]
        else:
            return
        subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=(os.name != "nt"),
        )
    except Exception:
        pass


def dashboard_info(home: Home) -> dict[str, Any] | None:
    try:
        return json.loads(home.ui.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def dashboard_token(home: Home) -> str:
    info = dashboard_info(home)
    if info and info.get("token"):
        return str(info["token"])
    token = uuid.uuid4().hex + uuid.uuid4().hex
    write_private(home.ui, json.dumps({"token": token}))
    return token


def _listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ensure_dashboard(
    home: Home, port: int, *, open_browser: bool, spawn: Callable[[list[str]], Any] | None = None
) -> str:
    """Start the dashboard in the background if nothing listens on ``port`` and
    return its URL. The browser is opened (best-effort) only when this call
    started the dashboard, so a burst of approvals does not open a burst of tabs."""
    token = dashboard_token(home)
    url = f"http://127.0.0.1:{port}/?t={token}"
    started = False
    if not _listening(port):
        started = True
        cmd = [
            sys.executable,
            "-m",
            "decision_os_min.gateway",
            "--home",
            str(home.root),
            "ui",
            "--port",
            str(port),
            "--no-browser",
        ]
        try:
            if spawn is not None:
                spawn(cmd)
            else:
                kwargs: dict[str, Any] = {
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                }
                if os.name == "nt":
                    kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED | NEW_GROUP
                else:
                    kwargs["start_new_session"] = True
                subprocess.Popen(cmd, **kwargs)
            for _ in range(25):
                if _listening(port):
                    break
                time.sleep(0.1)
        except Exception:
            pass
    if open_browser and started:
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass
    return url
