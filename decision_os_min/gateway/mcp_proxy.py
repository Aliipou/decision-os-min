"""A transparent stdio MCP proxy that gates every ``tools/call``.

    MCP client  <-- stdio -->  decision-os mcp-proxy  <-- stdio -->  real server

Everything is relayed byte-for-byte except:

* ``tools/call`` requests: each becomes a governed action. The forward to the
  real server is the effect, so it runs only inside ``Executor.execute``. A
  refused call is answered with an MCP tool result ``isError: true`` that tells
  the model why, so the agent can explain or adapt instead of hanging.
* ``tools/list`` responses: tool annotations are remembered as hints, and tools
  the policy hard-denies are removed so the model never sees them.

Server-initiated requests (sampling, roots, elicitation), notifications and
everything else pass through unchanged in both directions.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import IO, Any

from .engine import Gateway, slug

BLOCK_HINT = (
    "The user can review this in the Decision OS dashboard (`decision-os ui`) "
    "or change ~/.decision-os/policy.toml."
)


GATED = ("tools/call", "resources/read")


def _ungated_effect(msg: Any) -> bool:
    """A gated method without an id would reach the server unchecked (a server
    may still act on a notification). Such messages are dropped."""
    if isinstance(msg, dict) and msg.get("method") in GATED and "id" not in msg:
        sys.stderr.write(f"decision-os: dropped {msg.get('method')} sent without an id\n")
        return True
    return False


def _key(rid: Any) -> str:
    return json.dumps(rid, sort_keys=True)


def resolve_argv(argv: list[str]) -> list[str]:
    if len(argv) == 1 and " " in argv[0] and not os.path.exists(argv[0]):
        argv = shlex.split(argv[0], posix=(os.name != "nt"))
    if not argv:
        raise ValueError("no upstream command given")
    found = shutil.which(argv[0])
    return [found or argv[0], *argv[1:]]


def tool_hints(tool: dict[str, Any]) -> tuple[str, ...]:
    ann = tool.get("annotations")
    if not isinstance(ann, dict):
        return ()
    hints = []
    if ann.get("readOnlyHint") is True:
        hints.append("hint:readonly")
    if ann.get("destructiveHint") is True and ann.get("readOnlyHint") is not True:
        hints.append("hint:destructive")
    if ann.get("openWorldHint") is True:
        hints.append("hint:openworld")
    return tuple(hints)


class McpProxy:
    def __init__(
        self,
        gateway: Gateway,
        server: str,
        argv: list[str],
        *,
        client_in: IO[bytes] | None = None,
        client_out: IO[bytes] | None = None,
        max_parallel_calls: int = 8,
    ) -> None:
        self.gw = gateway
        self.server = slug(server)
        self.argv = resolve_argv(argv)
        self._in = client_in or sys.stdin.buffer
        self._out = client_out or sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._up_lock = threading.Lock()
        self._pending: dict[str, Future[dict[str, Any]]] = {}
        self._waiting: dict[str, threading.Event] = {}  # set to abort an approval wait
        self._cancelled: set[str] = set()  # explicit notifications/cancelled
        self._list_ids: set[str] = set()
        self._hints: dict[str, tuple[str, ...]] = {}
        self._state = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=max_parallel_calls, thread_name_prefix="dos-call"
        )
        self._done = threading.Event()
        self.proc: subprocess.Popen[bytes] | None = None

    # ------------------------------------------------------------- io
    def _to_client(self, data: bytes) -> None:
        with self._out_lock:
            try:
                self._out.write(data.rstrip(b"\r\n") + b"\n")
                self._out.flush()
            except (BrokenPipeError, ValueError, OSError):
                self._done.set()

    def _to_upstream(self, data: bytes) -> None:
        assert self.proc is not None and self.proc.stdin is not None
        with self._up_lock:
            try:
                self.proc.stdin.write(data.rstrip(b"\r\n") + b"\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    def _send_json(self, msg: dict[str, Any]) -> None:
        self._to_client(json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    # ------------------------------------------------------------- run
    def run(self) -> int:
        try:
            self.proc = subprocess.Popen(
                self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, bufsize=0
            )
        except OSError as exc:
            sys.stderr.write(f"decision-os: cannot start MCP server {self.argv!r}: {exc}\n")
            return 127
        up = threading.Thread(target=self._pump_upstream, name="dos-upstream", daemon=True)
        cl = threading.Thread(target=self._pump_client, name="dos-client", daemon=True)
        up.start()
        cl.start()
        self._done.wait()
        self._pool.shutdown(wait=True, cancel_futures=False)
        with self._out_lock:
            try:
                self._out.flush()
            except OSError:
                pass
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        return self.proc.returncode or 0

    def _pump_client(self) -> None:
        try:
            for raw in iter(self._in.readline, b""):
                if raw.strip():
                    self._on_client(raw)
        finally:
            # Client closed its side: abort approval waits (nobody can answer in
            # time), let in-flight calls finish and still write their replies,
            # since a half-closed client may still be reading, then stop the server.
            for ev in list(self._waiting.values()):
                ev.set()
            self._pool.shutdown(wait=True, cancel_futures=False)
            if self.proc and self.proc.stdin:
                try:
                    self.proc.stdin.close()
                except OSError:
                    pass
            self._done.set()

    def _pump_upstream(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                if raw.strip():
                    self._on_upstream(raw)
        finally:
            with self._state:
                pending = list(self._pending.items())
                self._pending.clear()
            for _, fut in pending:
                if not fut.done():
                    fut.set_exception(RuntimeError("the MCP server exited"))
            self._done.set()

    # ------------------------------------------------------------- client -> server
    def _on_client(self, raw: bytes) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            self._to_upstream(raw)
            return
        if isinstance(msg, list):  # JSON-RPC batch (2025-03-26 protocol)
            calls = [
                m for m in msg if isinstance(m, dict) and m.get("method") in GATED and "id" in m
            ]
            rest = [m for m in msg if m not in calls and not _ungated_effect(m)]
            for m in rest:
                self._track(m)
            if rest:
                self._to_upstream(json.dumps(rest).encode("utf-8"))
            for m in calls:
                self._submit_call(m)
            return
        if not isinstance(msg, dict):
            self._to_upstream(raw)
            return
        if msg.get("method") in GATED and "id" in msg:
            self._submit_call(msg)
            return
        if _ungated_effect(msg):
            return  # e.g. tools/call sent as a notification: never forwarded
        self._track(msg)
        self._to_upstream(raw)

    def _track(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            with self._state:
                self._list_ids.add(_key(msg["id"]))
        elif method == "notifications/cancelled":
            rid = (msg.get("params") or {}).get("requestId")
            self._cancelled.add(_key(rid))
            ev = self._waiting.get(_key(rid))
            if ev is not None:
                ev.set()

    def _submit_call(self, msg: dict[str, Any]) -> None:
        key = _key(msg["id"])
        self._waiting[key] = threading.Event()
        try:
            self._pool.submit(self._gate_call, msg)
        except RuntimeError:  # pool shut down
            self._waiting.pop(key, None)

    def _gate_call(self, msg: dict[str, Any]) -> None:
        rid = msg["id"]
        key = _key(rid)
        cancelled = self._waiting.get(key) or threading.Event()
        raw_params = msg.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        is_resource = msg.get("method") == "resources/read"
        if is_resource:
            name: Any = "resources/read"
            arguments: Any = {"uri": params.get("uri")}
        else:
            name = params.get("name")
            arguments = params.get("arguments")
        if not isinstance(name, str) or not name:
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32602, "message": "tools/call needs a tool name"},
                }
            )
            return

        def release(payload: dict[str, Any]) -> dict[str, Any]:
            fwd = dict(msg)
            if is_resource:
                fwd["params"] = {**params, "uri": payload.get("uri")}
            else:
                fwd["params"] = {**params, "arguments": payload}
            fut: Future[dict[str, Any]] = Future()
            with self._state:
                self._pending[key] = fut
            self._to_upstream(json.dumps(fwd, ensure_ascii=False).encode("utf-8"))
            return fut.result()

        try:
            res = self.gw.govern(
                server=self.server,
                tool=name,
                arguments=arguments,
                release=release,
                hints=self._hints.get(name, ()),
                cancelled=cancelled,
            )
        except Exception as exc:  # upstream died mid-call, or an unexpected bug: fail closed
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32603, "message": f"Decision OS: {exc}"},
                }
            )
            return
        finally:
            self._waiting.pop(key, None)
        if res.executed:
            out = dict(res.output)
            out["id"] = rid
            self._send_json(out)
            return
        if key in self._cancelled:
            self._cancelled.discard(key)
            return  # the client cancelled; MCP says no response is sent
        text = f"Decision OS blocked `{self.server}/{name}`: {res.reason}. {BLOCK_HINT}"
        if is_resource:
            self._send_json(
                {"jsonrpc": "2.0", "id": rid, "error": {"code": -32001, "message": text}}
            )
            return
        self._send_json(
            {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {"content": [{"type": "text", "text": text}], "isError": True},
            }
        )

    # ------------------------------------------------------------- server -> client
    def _on_upstream(self, raw: bytes) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            self._to_client(raw)
            return
        if isinstance(msg, dict) and "method" not in msg and "id" in msg:
            key = _key(msg["id"])
            with self._state:
                fut = self._pending.pop(key, None)
                is_list = key in self._list_ids
                self._list_ids.discard(key)
            if fut is not None:
                fut.set_result(msg)
                return
            if is_list:
                self._send_json(self._filter_tools(msg))
                return
        self._to_client(raw)

    def _filter_tools(self, msg: dict[str, Any]) -> dict[str, Any]:
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg
        tools: list[Any] = result["tools"]
        policy = self.gw.policy
        hide = bool(policy and policy.hide_denied_tools and policy.mode == "enforce")
        kept = []
        for t in tools:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                kept.append(t)
                continue
            hints = tool_hints(t)
            self._hints[t["name"]] = hints
            if hide and self.gw.static_decision(self.server, t["name"], hints) == "deny":
                continue
            kept.append(t)
        if len(kept) == len(tools):
            return msg
        out = dict(msg)
        out["result"] = {**result, "tools": kept}
        return out


def run(gateway: Gateway, server: str, argv: list[str]) -> int:
    """CLI entry. Exits the process directly: the stdin reader thread may still
    be blocked in readline() when the server goes away, and letting the
    interpreter finalize around it aborts with a buffered-IO lock error."""
    try:
        proxy = McpProxy(gateway, server, argv)
    except ValueError as exc:
        sys.stderr.write(f"decision-os: {exc}\n")
        return 2
    code = proxy.run()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
    os._exit(code)
