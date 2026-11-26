"""One-command install: wrap every stdio MCP server of every detected client.

``{"command": "npx", "args": ["-y", "server"]}`` becomes

    {"command": "<python>", "args": ["-P", "-m", "decision_os_min.gateway", "--home", "<home>",
     "mcp-proxy", "--client", "<client>", "--server", "<name>", "--", "npx", "-y", "server"]}

Every other key (env, cwd, type, disabled, client-specific fields) is kept.
The original entry is stored in ``state.json`` and every file is backed up before
it is written, so ``uninstall`` restores exactly what was there. Remote (HTTP/SSE)
servers are reported, not touched: the client runs their OAuth flow itself.

Writes are atomic (temp file + rename) and re-verified by parsing the result.
JSON files that contain comments are refused unless ``force_jsonc`` is set,
because rewriting them would drop the comments. Codex's TOML is edited in place
line-by-line, so its comments survive.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .clients import CLIENTS, ClientSpec
from .paths import Home, write_private

MODULE = "decision_os_min.gateway"
REMOTE_TYPES = {"http", "sse", "streamable-http", "streamablehttp", "streamable_http", "remote"}


@dataclass
class FileReport:
    client: str
    path: Path
    fmt: str
    status: str = "ok"  # ok | missing | unchanged | manual | error
    wrapped: list[str] = field(default_factory=list)
    unwrapped: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)
    plain: list[str] = field(default_factory=list)
    remote: list[str] = field(default_factory=list)
    message: str = ""


# ------------------------------------------------------------------ entries


def wrapper(
    home: Home, client: str, server: str, command: str, args: list[str], python: str | None = None
) -> tuple[str, list[str]]:
    # -P: never put the client's working directory on sys.path, so a stray (or
    # planted) ``decision_os_min`` folder there cannot replace the gateway.
    return python or sys.executable, [
        "-P",
        "-m",
        MODULE,
        "--home",
        str(home.root),
        "mcp-proxy",
        "--client",
        client,
        "--server",
        server,
        "--",
        command,
        *args,
    ]


def is_wrapped(command: Any, args: Any) -> bool:
    return isinstance(args, list) and MODULE in args and "mcp-proxy" in args and "--" in args


def unwrap_args(args: list[str]) -> tuple[str, list[str]]:
    i = args.index("--")
    rest = args[i + 1 :]
    if not rest:
        raise ValueError("wrapped entry has no original command")
    return rest[0], list(rest[1:])


def is_remote(entry: dict[str, Any]) -> bool:
    t = str(entry.get("type") or entry.get("transport") or "").lower()
    return t in REMOTE_TYPES or any(k in entry for k in ("url", "serverUrl", "httpUrl"))


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, respecting strings."""
    out, i, n, in_str, esc = [], 0, len(text), False, False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _indent(text: str) -> int | str:
    m = re.search(r"\n([ \t]+)\S", text)
    if not m:
        return 2
    ws = m.group(1)
    return "\t" if ws.startswith("\t") else len(ws)


def _server_tables(fmt: str, data: dict[str, Any]) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    out: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    key = "servers" if fmt == "servers" else "mcpServers"
    if isinstance(data.get(key), dict):
        out.append(((key,), data[key]))
    if fmt == "claude-code" and isinstance(data.get("projects"), dict):
        for proj, cfg in data["projects"].items():
            if (
                isinstance(cfg, dict)
                and isinstance(cfg.get("mcpServers"), dict)
                and cfg["mcpServers"]
            ):
                out.append((("projects", proj, "mcpServers"), cfg["mcpServers"]))
    return out


# ------------------------------------------------------------------ state


class State:
    def __init__(self, home: Home) -> None:
        self.home = home
        try:
            self.data = json.loads(home.state.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {}
        self.data.setdefault("version", 1)
        self.data.setdefault("entries", {})

    def key(self, path: Path, pointer: tuple[str, ...], name: str) -> str:
        return json.dumps([str(path), list(pointer), name])

    def remember(
        self, path: Path, pointer: tuple[str, ...], name: str, client: str, original: dict[str, Any]
    ) -> None:
        self.data["entries"][self.key(path, pointer, name)] = {
            "client": client,
            "original": original,
        }

    def original(self, path: Path, pointer: tuple[str, ...], name: str) -> dict[str, Any] | None:
        rec = self.data["entries"].get(self.key(path, pointer, name))
        return rec.get("original") if rec else None

    def forget(self, path: Path, pointer: tuple[str, ...], name: str) -> None:
        self.data["entries"].pop(self.key(path, pointer, name), None)

    def wrote(self, path: Path, text: str, backup: Path, prior_sha256: str) -> None:
        """Record a write. The backup stays eligible for a byte-exact restore only
        while nobody else has touched the file between our writes; otherwise
        uninstall falls back to unwrapping entry by entry."""
        files = self.data.setdefault("files", {})
        rec = files.get(str(path))
        if rec is None:
            rec = {"backup": str(backup)}  # the pre-Decision-OS original
        elif rec.get("written_sha256") != prior_sha256:
            rec["backup"] = None  # edited by someone else since
        rec["written_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        files[str(path)] = rec

    def file_record(self, path: Path) -> dict[str, Any] | None:
        return self.data.get("files", {}).get(str(path))

    def drop_file(self, path: Path) -> None:
        self.data.get("files", {}).pop(str(path), None)
        for k in [k for k in self.data["entries"] if json.loads(k)[0] == str(path)]:
            self.data["entries"].pop(k)

    def wrapped_paths(self) -> list[str]:
        return sorted({json.loads(k)[0] for k in self.data["entries"]})

    def save(self) -> None:
        self.data["python"] = sys.executable
        self.data["updated"] = datetime.now(UTC).isoformat()
        write_private(self.home.state, json.dumps(self.data, indent=2))


# ------------------------------------------------------------------ files


def _backup(home: Home, client: str, path: Path, stamp: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(path).strip("/\\"))
    dest = home.backups / stamp / client / safe
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    return dest


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.dos-{os.getpid()}.tmp")
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = 0o600
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


def _process_json(
    home: Home,
    state: State,
    spec_id: str,
    path: Path,
    fmt: str,
    *,
    action: str,
    dry_run: bool,
    force_jsonc: bool,
    stamp: str,
    python: str | None,
) -> FileReport:
    rep = FileReport(spec_id, path, fmt)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        rep.status = "missing"
        return rep
    except OSError as exc:
        rep.status, rep.message = "error", str(exc)
        return rep
    if not text.strip():
        rep.status = "unchanged"
        return rep
    try:
        data = json.loads(text)
        has_comments = False
    except json.JSONDecodeError:
        try:
            data = json.loads(strip_jsonc(text))
            has_comments = True
        except json.JSONDecodeError as exc:
            rep.status, rep.message = "error", f"not valid JSON: {exc}"
            return rep
    if not isinstance(data, dict):
        rep.status, rep.message = "error", "top level is not an object"
        return rep
    original = copy.deepcopy(data)
    changed = False
    state_ops: list[Any] = []  # applied only once the file is really written
    for pointer, servers in _server_tables(fmt, data):
        label = "" if len(pointer) == 1 else f"[{pointer[1]}] "
        for name, entry in list(servers.items()):
            if not isinstance(entry, dict):
                continue
            tag = f"{label}{name}"
            cmd, args = entry.get("command"), entry.get("args")
            wrapped = is_wrapped(cmd, args)
            if action == "status":
                if is_remote(entry):
                    rep.remote.append(tag)
                elif wrapped:
                    rep.already.append(tag)
                elif isinstance(cmd, str):
                    rep.plain.append(tag)
                continue
            if action == "install":
                if is_remote(entry):
                    rep.remote.append(tag)
                    continue
                if wrapped:
                    rep.already.append(tag)
                    continue
                if not isinstance(cmd, str) or not cmd:
                    continue
                if args is not None and not (
                    isinstance(args, list) and all(isinstance(a, str) for a in args)
                ):
                    rep.message = f"{tag}: args is not a list of strings; skipped"
                    continue
                new_cmd, new_args = wrapper(home, spec_id, name, cmd, list(args or []), python)
                state_ops.append(
                    (state.remember, (path, pointer, name, spec_id, copy.deepcopy(entry)))
                )
                entry["command"], entry["args"] = new_cmd, new_args
                rep.wrapped.append(tag)
                changed = True
            elif action == "uninstall" and wrapped:
                orig = state.original(path, pointer, name)
                try:
                    o_cmd, o_args = unwrap_args(list(args or []))
                except ValueError as exc:
                    rep.message = f"{tag}: {exc}"
                    continue
                if orig and orig.get("command") == o_cmd and list(orig.get("args") or []) == o_args:
                    restored = {
                        **entry,
                        **{k: v for k, v in orig.items() if k in ("command", "args")},
                    }
                    if "args" not in orig:
                        restored.pop("args", None)
                else:
                    restored = {**entry, "command": o_cmd, "args": o_args}
                servers[name] = restored
                state_ops.append((state.forget, (path, pointer, name)))
                rep.unwrapped.append(tag)
                changed = True
    if action == "status" or not changed:
        rep.status = "unchanged" if action != "status" else "ok"
        return rep
    if has_comments and not force_jsonc:
        rep.status = "manual"
        rep.message = (
            "file contains comments, which a rewrite would drop; "
            "re-run with --force-jsonc (a backup is kept) or wrap by hand"
        )
        if action == "install":
            rep.plain, rep.wrapped = rep.wrapped, []
        rep.unwrapped = []
        return rep
    new_text = json.dumps(data, indent=_indent(text), ensure_ascii=False)
    if text.endswith("\n"):
        new_text += "\n"
    reparsed = json.loads(new_text)
    if _strip_servers(reparsed, fmt) != _strip_servers(original, fmt):
        rep.status, rep.message = (
            "error",
            "verification failed: non-server content changed; not written",
        )
        return rep
    if not dry_run:
        _commit(home, state, spec_id, path, new_text, stamp, action)
        for fn, fargs in state_ops:
            fn(*fargs)
    return rep


def _commit(
    home: Home, state: State, spec_id: str, path: Path, new_text: str, stamp: str, action: str
) -> None:
    prior = hashlib.sha256(path.read_bytes()).hexdigest()
    backup = _backup(home, spec_id, path, stamp)
    _atomic_write(path, new_text)
    if action == "install":
        state.wrote(path, new_text, backup, prior)
    else:
        state.data.get("files", {}).pop(str(path), None)


def _restore_exact(state: State, path: Path) -> bool:
    """If the file is byte-for-byte what we last wrote, put the original back
    verbatim (formatting, comments and key order included)."""
    rec = state.file_record(path)
    if not rec or not rec.get("backup") or not rec.get("written_sha256"):
        return False
    try:
        current = path.read_bytes()
        backup = Path(rec["backup"]).read_bytes()
    except OSError:
        return False
    if hashlib.sha256(current).hexdigest() != rec["written_sha256"]:
        return False
    _atomic_write(path, backup.decode("utf-8"))
    state.drop_file(path)
    return True


def _strip_servers(data: dict[str, Any], fmt: str) -> dict[str, Any]:
    d = copy.deepcopy(data)
    for pointer, _ in _server_tables(fmt, d):
        node: Any = d
        for k in pointer[:-1]:
            node = node[k]
        node[pointer[-1]] = {
            name: {k: v for k, v in e.items() if k not in ("command", "args")}
            if isinstance(e, dict)
            else e
            for name, e in node[pointer[-1]].items()
        }
    return d


# -------------------------------------------------------------- codex toml


def _toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def _toml_array(items: list[str]) -> str:
    return "[" + ", ".join(_toml_str(x) for x in items) + "]"


def _header_rx(name: str) -> re.Pattern[str]:
    q = re.escape(name)
    return re.compile(rf"""^\s*\[\s*mcp_servers\s*\.\s*(?:{q}|"{q}"|'{q}')\s*\]\s*(?:#.*)?$""")


def _statement_end(lines: list[str], start: int) -> int:
    """Index of the last line of a (possibly multi-line) key = value statement."""
    depth, in_str, quote = 0, False, ""
    for j in range(start, len(lines)):
        line = lines[j]
        k = line.index("=") + 1 if j == start else 0
        while k < len(line):
            c = line[k]
            if in_str:
                if c == "\\" and quote == '"':
                    k += 2
                    continue
                if c == quote:
                    in_str = False
            elif c in "\"'":
                in_str, quote = True, c
            elif c == "#":
                break
            elif c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
            k += 1
        if depth <= 0 and not in_str:
            return j
    return len(lines) - 1


def _edit_codex_server(lines: list[str], name: str, command: str, args: list[str] | None) -> bool:
    rx = _header_rx(name)
    start = next((i for i, line in enumerate(lines) if rx.match(line)), None)
    if start is None:
        return False
    end = next(
        (i for i in range(start + 1, len(lines)) if re.match(r"^\s*\[", lines[i])), len(lines)
    )
    cmd_i = next((i for i in range(start + 1, end) if re.match(r"^\s*command\s*=", lines[i])), None)
    if cmd_i is None:
        return False
    args_i = next((i for i in range(start + 1, end) if re.match(r"^\s*args\s*=", lines[i])), None)
    indent = re.match(r"^(\s*)", lines[cmd_i]).group(1)  # type: ignore[union-attr]
    nl = "\r\n" if lines[cmd_i].endswith("\r\n") else "\n"
    cmd_end = _statement_end(lines, cmd_i)
    new_cmd = [f"{indent}command = {_toml_str(command)}{nl}"]
    if args_i is not None:
        args_end = _statement_end(lines, args_i)
        new_args = [] if args is None else [f"{indent}args = {_toml_array(args)}{nl}"]
        spans = sorted([(cmd_i, cmd_end, new_cmd), (args_i, args_end, new_args)], reverse=True)
        for a, b, repl in spans:
            lines[a : b + 1] = repl
    else:
        lines[cmd_i : cmd_end + 1] = new_cmd + (
            [] if args is None else [f"{indent}args = {_toml_array(args)}{nl}"]
        )
    return True


def _process_codex(
    home: Home,
    state: State,
    spec_id: str,
    path: Path,
    *,
    action: str,
    dry_run: bool,
    stamp: str,
    python: str | None,
) -> FileReport:
    rep = FileReport(spec_id, path, "codex")
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        rep.status = "missing"
        return rep
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        rep.status, rep.message = "error", f"not valid TOML: {exc}"
        return rep
    servers = data.get("mcp_servers")
    if not isinstance(servers, dict):
        rep.status = "unchanged" if action != "status" else "ok"
        return rep
    lines = text.splitlines(keepends=True)
    expected: dict[str, tuple[str, list[str] | None]] = {}
    state_ops: list[Any] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        cmd, args = entry.get("command"), entry.get("args")
        wrapped = is_wrapped(cmd, args)
        if "url" in entry:
            rep.remote.append(name)
            continue
        if action == "status":
            if isinstance(cmd, str):
                (rep.already if wrapped else rep.plain).append(name)
            continue
        if action == "install":
            if wrapped:
                rep.already.append(name)
                continue
            if not isinstance(cmd, str):
                rep.message = f"{name}: uses an inline transport table; wrap by hand"
                continue
            new_cmd, new_args = wrapper(home, spec_id, name, cmd, list(args or []), python)
            if not _edit_codex_server(lines, name, new_cmd, new_args):
                rep.status = "manual"
                rep.message = f"{name}: not a plain [mcp_servers.{name}] table; wrap by hand"
                return rep
            orig_entry = {"command": cmd, **({"args": args} if args is not None else {})}
            state_ops.append((state.remember, (path, ("mcp_servers",), name, spec_id, orig_entry)))
            expected[name] = (new_cmd, new_args)
            rep.wrapped.append(name)
        elif action == "uninstall" and wrapped:
            o_cmd, o_args = unwrap_args(list(args or []))
            orig = state.original(path, ("mcp_servers",), name)
            keep_args: list[str] | None = o_args
            if orig and orig.get("command") == o_cmd and "args" not in orig and not o_args:
                keep_args = None
            if not _edit_codex_server(lines, name, o_cmd, keep_args):
                rep.status, rep.message = "manual", f"{name}: could not locate its table"
                return rep
            state_ops.append((state.forget, (path, ("mcp_servers",), name)))
            expected[name] = (o_cmd, keep_args)
            rep.unwrapped.append(name)
    if action == "status" or not expected:
        rep.status = "ok" if action == "status" else "unchanged"
        return rep
    new_text = "".join(lines)
    try:
        new_data = tomllib.loads(new_text)
    except tomllib.TOMLDecodeError as exc:
        rep.status, rep.message = "error", f"edit produced invalid TOML ({exc}); not written"
        return rep
    check_old, check_new = copy.deepcopy(data), copy.deepcopy(new_data)
    for name, (cmd, args) in expected.items():
        got = check_new["mcp_servers"].get(name, {})
        if got.get("command") != cmd or got.get("args") != args:
            rep.status, rep.message = "error", f"verification failed for {name}; not written"
            return rep
        for d in (check_old, check_new):
            d["mcp_servers"][name].pop("command", None)
            d["mcp_servers"][name].pop("args", None)
    if check_old != check_new:
        rep.status, rep.message = (
            "error",
            "verification failed: other settings changed; not written",
        )
        return rep
    if not dry_run:
        _commit(home, state, spec_id, path, new_text, stamp, action)
        for fn, fargs in state_ops:
            fn(*fargs)
    return rep


# ------------------------------------------------------------------ driver


def run_status_names(home: Home, state: State, spec_id: str, path: Path, fmt: str) -> list[str]:
    if fmt == "codex":
        rep = _process_codex(
            home, state, spec_id, path, action="status", dry_run=True, stamp="", python=None
        )
    else:
        rep = _process_json(
            home,
            state,
            spec_id,
            path,
            fmt,
            action="status",
            dry_run=True,
            force_jsonc=True,
            stamp="",
            python=None,
        )
    return rep.already


def targets(
    clients: list[str] | None = None, project: Path | None = None
) -> list[tuple[ClientSpec, Path, str]]:
    out = []
    for spec in CLIENTS:
        if clients and spec.id not in clients:
            continue
        if project is not None:
            for rel, fmt in spec.project:
                out.append((spec, project / rel, fmt))
        else:
            for p in spec.paths():
                out.append((spec, p, spec.fmt))
    return out


def run(
    home: Home,
    action: str,
    *,
    clients: list[str] | None = None,
    project: Path | None = None,
    dry_run: bool = False,
    force_jsonc: bool = False,
    python: str | None = None,
) -> list[FileReport]:
    if action not in ("install", "uninstall", "status"):
        raise ValueError(action)
    home.ensure()
    state = State(home)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    reports = []
    seen: set[Path] = set()
    for spec, path, fmt in targets(clients, project):
        if path in seen:
            continue
        seen.add(path)
        if action == "uninstall" and not dry_run and path.exists():
            before = run_status_names(home, state, spec.id, path, fmt)
            if before and _restore_exact(state, path):
                reports.append(
                    FileReport(
                        spec.id,
                        path,
                        fmt,
                        unwrapped=before,
                        message="(original restored byte for byte)",
                    )
                )
                continue
        if fmt == "codex":
            rep = _process_codex(
                home,
                state,
                spec.id,
                path,
                action=action,
                dry_run=dry_run,
                stamp=stamp,
                python=python,
            )
        else:
            rep = _process_json(
                home,
                state,
                spec.id,
                path,
                fmt,
                action=action,
                dry_run=dry_run,
                force_jsonc=force_jsonc,
                stamp=stamp,
                python=python,
            )
        reports.append(rep)
    if action != "status" and not dry_run:
        state.save()
    return reports
