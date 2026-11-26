"""install / uninstall across every config shape, in a fake HOME."""

from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path

from decision_os_min.gateway import cli, installer
from decision_os_min.gateway.installer import is_wrapped, strip_jsonc, unwrap_args

DESKTOP = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/w"],
        },
        "github": {
            "command": "docker",
            "args": ["run", "-i", "ghcr.io/github/github-mcp-server"],
            "env": {"GITHUB_TOKEN": "x"},
        },
        "linear": {"url": "https://mcp.linear.app/sse"},
    },
    "globalShortcut": "Ctrl+Space",
}

CLAUDE_CODE = {
    "numStartups": 7,
    "mcpServers": {"memory": {"type": "stdio", "command": "npx", "args": ["-y", "@mcp/memory"]}},
    "projects": {
        "/w/app": {
            "mcpServers": {"db": {"command": "uvx", "args": ["mcp-db"]}},
            "allowedTools": [],
        },
        "/w/empty": {"mcpServers": {}},
    },
}

VSCODE_JSONC = """{
  // my servers
  "servers": {
    "playwright": { "type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest"], },
    "remote": { "type": "http", "url": "https://example.com/mcp" }
  },
  "inputs": []
}
"""

CODEX = """# Codex config
model = "gpt-5"

[mcp_servers.context7]
command = "npx"   # docs
args = [
  "-y",
  "@upstash/context7-mcp",
]

[mcp_servers.context7.env]
DEBUG = "1"

[mcp_servers."my-shell"]
command = "/usr/local/bin/shell-mcp"

[mcp_servers.remote]
url = "https://mcp.example.com/mcp"

[profiles.fast]
model = "gpt-5-mini"
"""


def _setup(user: Path) -> dict[str, Path]:
    paths = {
        "desktop": user / ".config" / "Claude" / "claude_desktop_config.json",
        "code": user / ".claude.json",
        "cursor": user / ".cursor" / "mcp.json",
        "vscode": user / ".config" / "Code" / "User" / "mcp.json",
        "codex": user / ".codex" / "config.toml",
    }
    for p in paths.values():
        p.parent.mkdir(parents=True, exist_ok=True)
    # the fake HOME mirrors the platform layout the client registry expects
    if sys.platform == "darwin":
        app = user / "Library" / "Application Support"
    elif os.name == "nt":
        app = user / "AppData" / "Roaming"
    else:
        app = None
    if app is not None:
        paths["desktop"] = app / "Claude" / "claude_desktop_config.json"
        paths["vscode"] = app / "Code" / "User" / "mcp.json"
        for k in ("desktop", "vscode"):
            paths[k].parent.mkdir(parents=True, exist_ok=True)
    paths["desktop"].write_text(json.dumps(DESKTOP, indent=2) + "\n")
    paths["code"].write_text(json.dumps(CLAUDE_CODE))
    paths["cursor"].write_text(
        json.dumps({"mcpServers": {"fs": {"command": "npx -y fs-mcp"}}}, indent=4)
    )
    paths["vscode"].write_text(VSCODE_JSONC)
    paths["codex"].write_text(CODEX)
    return paths


def _reports(home, action, **kw):
    return {r.client: r for r in installer.run(home, action, **kw) if r.status != "missing"}


def test_install_wraps_every_stdio_server_and_keeps_everything_else(fake_home):
    user = Path.home()
    paths = _setup(user)
    originals = {k: p.read_bytes() for k, p in paths.items()}
    reps = _reports(fake_home, "install")

    assert sorted(reps["claude-desktop"].wrapped) == ["filesystem", "github"]
    assert reps["claude-desktop"].remote == ["linear"]
    d = json.loads(paths["desktop"].read_text())
    gh = d["mcpServers"]["github"]
    assert gh["command"] == sys.executable and gh["env"] == {"GITHUB_TOKEN": "x"}
    assert unwrap_args(gh["args"]) == ("docker", ["run", "-i", "ghcr.io/github/github-mcp-server"])
    assert "--client" in gh["args"] and "claude-desktop" in gh["args"]
    assert d["mcpServers"]["linear"] == {"url": "https://mcp.linear.app/sse"}
    assert d["globalShortcut"] == "Ctrl+Space"
    assert paths["desktop"].read_text().startswith('{\n  "mcpServers"')  # indentation kept

    assert sorted(reps["claude-code"].wrapped) == ["[/w/app] db", "memory"]
    cc = json.loads(paths["code"].read_text())
    assert cc["numStartups"] == 7 and cc["projects"]["/w/app"]["allowedTools"] == []
    assert cc["mcpServers"]["memory"]["type"] == "stdio"

    assert reps["vscode"].status == "manual" and "comments" in reps["vscode"].message
    assert reps["vscode"].plain == ["playwright"]
    assert paths["vscode"].read_bytes() == originals["vscode"]  # untouched

    assert sorted(reps["codex"].wrapped) == ["context7", "my-shell"]
    assert reps["codex"].remote == ["remote"]
    codex_text = paths["codex"].read_text()
    assert (
        "# Codex config" in codex_text
        and "# docs" not in codex_text.split("[mcp_servers.context7.env]")[1]
    )
    cx = tomllib.loads(codex_text)
    assert cx["mcp_servers"]["context7"]["env"] == {"DEBUG": "1"}
    assert cx["profiles"]["fast"]["model"] == "gpt-5-mini"
    assert is_wrapped(
        cx["mcp_servers"]["my-shell"]["command"], cx["mcp_servers"]["my-shell"]["args"]
    )
    assert unwrap_args(cx["mcp_servers"]["my-shell"]["args"]) == ("/usr/local/bin/shell-mcp", [])

    # idempotent
    again = _reports(fake_home, "install")
    assert all(not r.wrapped for r in again.values())
    assert sorted(again["claude-desktop"].already) == ["filesystem", "github"]

    # byte-for-byte restore when nothing else touched the files
    out = _reports(fake_home, "uninstall")
    for k in ("desktop", "code", "cursor", "codex"):
        assert paths[k].read_bytes() == originals[k], k
    assert "byte for byte" in out["claude-desktop"].message


def test_uninstall_after_the_app_edited_its_config_unwraps_entry_by_entry(fake_home):
    paths = _setup(Path.home())
    _reports(fake_home, "install")
    d = json.loads(paths["desktop"].read_text())
    d["mcpServers"]["added-later"] = {"command": "node", "args": ["srv.js"]}
    d["globalShortcut"] = "Alt+Space"
    paths["desktop"].write_text(json.dumps(d))
    _reports(fake_home, "uninstall", clients=["claude-desktop"])
    after = json.loads(paths["desktop"].read_text())
    assert after["mcpServers"]["filesystem"] == DESKTOP["mcpServers"]["filesystem"]
    assert after["mcpServers"]["github"] == DESKTOP["mcpServers"]["github"]
    assert after["mcpServers"]["added-later"] == {"command": "node", "args": ["srv.js"]}
    assert after["globalShortcut"] == "Alt+Space"


def test_cursor_command_string_and_codex_args_absent_round_trip(fake_home):
    paths = _setup(Path.home())
    _reports(fake_home, "install", clients=["cursor", "codex"])
    cur = json.loads(paths["cursor"].read_text())["mcpServers"]["fs"]
    assert unwrap_args(cur["args"]) == ("npx -y fs-mcp", [])  # split by the proxy at launch
    # simulate an edit elsewhere so uninstall must unwrap semantically
    paths["codex"].write_text(paths["codex"].read_text() + "\n# touched\n")
    _reports(fake_home, "uninstall", clients=["codex"])
    cx = tomllib.loads(paths["codex"].read_text())
    assert cx["mcp_servers"]["my-shell"] == {
        "command": "/usr/local/bin/shell-mcp"
    }  # no args key invented
    assert cx["mcp_servers"]["context7"]["args"] == ["-y", "@upstash/context7-mcp"]


def test_force_jsonc_and_dry_run(fake_home):
    paths = _setup(Path.home())
    before = {k: p.read_bytes() for k, p in paths.items()}
    _reports(fake_home, "install", dry_run=True)
    assert {k: p.read_bytes() for k, p in paths.items()} == before
    rep = _reports(fake_home, "install", clients=["vscode"], force_jsonc=True)["vscode"]
    assert rep.wrapped == ["playwright"] and rep.remote == ["remote"]
    v = json.loads(paths["vscode"].read_text())
    assert v["servers"]["playwright"]["type"] == "stdio" and v["inputs"] == []
    backups = list(fake_home.backups.rglob("*mcp.json"))
    assert backups and backups[0].read_text() == VSCODE_JSONC


def test_project_install(fake_home, tmp_path):
    proj = tmp_path / "proj"
    (proj / ".cursor").mkdir(parents=True)
    (proj / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"pg": {"command": "uvx", "args": ["pg-mcp"]}}})
    )
    (proj / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"pg": {"command": "uvx", "args": ["pg-mcp"]}}})
    )
    reps = _reports(fake_home, "install", project=proj)
    assert reps["claude-code"].wrapped == ["pg"] and reps["cursor"].wrapped == ["pg"]
    # wrapped project configs become self-protected
    from decision_os_min.gateway.engine import self_protected_paths

    assert proj / ".mcp.json" in self_protected_paths(fake_home)


def test_jsonc_stripper():
    assert json.loads(strip_jsonc('{"a": "x // not a comment", /* c */ "b": [1,2,],}')) == {
        "a": "x // not a comment",
        "b": [1, 2],
    }


def test_cli_install_status_uninstall(fake_home, capsys):
    _setup(Path.home())
    assert cli.main(["install"]) == 0
    out = capsys.readouterr().out
    assert "Decision OS governs 7 MCP server(s) across 4 app(s)." in out
    assert fake_home.policy.exists() and fake_home.key.exists()
    assert cli.main(["status"]) == 0
    assert "governed  2" in capsys.readouterr().out
    assert cli.main(["doctor"]) in (0, 1)  # upstream commands like npx may be absent here
    assert cli.main(["uninstall"]) == 0
    assert "Restored 7 MCP server(s)" in capsys.readouterr().out
