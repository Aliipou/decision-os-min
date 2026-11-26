"""The local dashboard: approvals, live activity, coverage, remembered choices.

Bound to 127.0.0.1 only. Every request needs the per-install token (in the URL
for the page, in a header for the API) and a loopback Host header, which blocks
cross-site requests and DNS rebinding from a web page in the same browser.
The dashboard holds no keys: approving writes an approval record, and the
kernel still decides and signs.
"""

from __future__ import annotations

import hmac
import json
import re
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ..audit import HashLog
from .approvals import APPROVED, DENIED, ApprovalStore, LearnedStore, dashboard_token
from .audit import LockedHashLog
from .paths import Home, write_private
from .policy import PolicyError, load_policy, parse_policy


class Dashboard:
    def __init__(self, home: Home) -> None:
        self.home = home.ensure()
        self.token = dashboard_token(self.home)
        self.approvals = ApprovalStore(self.home)
        self.learned = LearnedStore(self.home)
        self._coverage: tuple[float, Any] = (0.0, None)

    def coverage(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        if self._coverage[1] is not None and now - self._coverage[0] < 15:
            return self._coverage[1]
        from . import installer

        out = []
        for r in installer.run(self.home, "status"):
            if r.status == "missing":
                continue
            out.append(
                {
                    "client": r.client,
                    "path": str(r.path),
                    "governed": r.already,
                    "ungoverned": r.plain,
                    "remote": r.remote,
                    "status": r.status,
                    "message": r.message,
                }
            )
        self._coverage = (now, out)
        return out

    def state(self) -> dict[str, Any]:
        try:
            policy = load_policy(self.home.policy)
            mode, profile, err = policy.mode, policy.profile, None
        except PolicyError as exc:
            mode, profile, err = "?", "?", str(exc)
        log = LockedHashLog(self.home.audit, self.home.locks / "audit.lock")
        chain_ok = HashLog.verify(log) if self.home.audit.exists() else True
        return {
            "mode": mode,
            "profile": profile,
            "policy_error": err,
            "policy_path": str(self.home.policy),
            "pending": self.approvals.pending(),
            "decided": [r for r in self.approvals.recent(30) if r.get("status") != "pending"][:15],
            "audit": list(reversed(log.tail(150))),
            "chain_ok": chain_ok,
            "learned": self.learned.load(),
            "coverage": self.coverage(),
            "now": time.time(),
        }

    def set_mode(self, mode: str) -> None:
        text = self.home.policy.read_text(encoding="utf-8")
        new, n = re.subn(r'(?m)^(\s*mode\s*=\s*)"[^"]*"', rf'\g<1>"{mode}"', text, count=1)
        if n == 0:
            new = f'mode = "{mode}"\n' + text
        parse_policy(new)  # raises on invalid
        write_private(self.home.policy, new)

    def serve(self, port: int) -> ThreadingHTTPServer:
        dash = self

        class H(_Handler):
            d = dash

        srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        srv.daemon_threads = True
        return srv


class _Handler(BaseHTTPRequestHandler):
    d: Dashboard
    server_version = "DecisionOS"

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def _ok_host(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_address[1]  # type: ignore[index]
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: Any) -> None:
        self._send(status, json.dumps(obj, default=str).encode("utf-8"), "application/json")

    def _authorized_api(self) -> bool:
        tok = self.headers.get("X-DOS-Token") or ""
        return hmac.compare_digest(tok, self.d.token)

    def do_GET(self) -> None:
        if not self._ok_host():
            self._send(403, b"forbidden host", "text/plain")
            return
        url = urllib.parse.urlparse(self.path)
        if url.path == "/":
            t = urllib.parse.parse_qs(url.query).get("t", [""])[0]
            if not hmac.compare_digest(t, self.d.token):
                self._send(403, b"Open the dashboard with `decision-os ui`.", "text/plain")
                return
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif url.path == "/api/state":
            if not self._authorized_api():
                self._json(403, {"error": "token"})
                return
            self._json(200, self.d.state())
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        if not self._ok_host() or not self._authorized_api():
            self._json(403, {"error": "forbidden"})
            return
        length = min(int(self.headers.get("Content-Length") or 0), 65536)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "bad json"})
            return
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/api/resolve":
                decision = {"approve": APPROVED, "deny": DENIED}[body["decision"]]
                rec = self.d.approvals.resolve(
                    str(body["id"]), decision, by="dashboard", remember=bool(body.get("remember"))
                )
                self._json(200, rec)
            elif path == "/api/forget":
                self._json(200, {"removed": self.d.learned.forget(str(body["key"]))})
            elif path == "/api/mode":
                mode = body.get("mode")
                if mode not in ("enforce", "observe"):
                    raise ValueError("mode")
                self.d.set_mode(mode)
                self._json(200, {"mode": mode})
            else:
                self._json(404, {"error": "not found"})
        except (KeyError, ValueError, PolicyError) as exc:
            self._json(400, {"error": str(exc)})


def serve(home: Home, port: int, *, open_browser: bool = True) -> None:
    dash = Dashboard(home)
    srv = dash.serve(port)
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={dash.token}"
    print(f"Decision OS dashboard: {url}", flush=True)
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url, new=2)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


PAGE = (Path(__file__).with_name("dashboard.html")).read_text(encoding="utf-8")
