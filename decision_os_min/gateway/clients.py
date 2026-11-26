"""Known MCP clients and where each keeps its server list.

Each client is one of four shapes:

* ``mcpServers`` : ``{"mcpServers": {name: {command, args, env}}}`` (most clients)
* ``servers``    : VS Code's ``{"servers": {...}}``
* ``claude-code``: ``~/.claude.json``: top-level ``mcpServers`` plus
  ``projects[<path>].mcpServers``
* ``codex``      : Codex ``config.toml`` with ``[mcp_servers.<name>]`` tables
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


def _home() -> Path:
    return Path.home()


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA") or (_home() / "AppData" / "Roaming"))


def _app_support() -> Path:
    """Per-user application data dir: Roaming on Windows, Application Support
    on macOS, XDG config on Linux."""
    if os.name == "nt":
        return _appdata()
    if sys.platform == "darwin":
        return _home() / "Library" / "Application Support"
    return Path(os.environ.get("XDG_CONFIG_HOME") or (_home() / ".config"))


def _vscode_user_dirs() -> list[Path]:
    base = _app_support()
    return [base / name / "User" for name in ("Code", "Code - Insiders", "VSCodium")]


def _claude_desktop() -> list[Path]:
    paths = [_app_support() / "Claude" / "claude_desktop_config.json"]
    if os.name == "nt":  # MSIX installs keep a virtualized copy
        local = Path(os.environ.get("LOCALAPPDATA") or (_home() / "AppData" / "Local"))
        paths += sorted(
            (local / "Packages").glob(
                "Claude_*/LocalCache/Roaming/Claude/claude_desktop_config.json"
            )
        )
    return paths


def _codex() -> list[Path]:
    root = (
        Path(os.environ["CODEX_HOME"]).expanduser()
        if os.environ.get("CODEX_HOME")
        else _home() / ".codex"
    )
    return [root / "config.toml"]


def _copilot() -> list[Path]:
    root = (
        Path(os.environ["COPILOT_HOME"]).expanduser()
        if os.environ.get("COPILOT_HOME")
        else _home() / ".copilot"
    )
    return [root / "mcp-config.json"]


@dataclass(frozen=True)
class ClientSpec:
    id: str
    name: str
    fmt: str
    paths: Callable[[], list[Path]]
    project: tuple[tuple[str, str], ...] = ()  # (relative path, fmt) inside a project
    restart_hint: str = ""


CLIENTS: tuple[ClientSpec, ...] = (
    ClientSpec(
        "claude-desktop",
        "Claude Desktop",
        "mcpServers",
        _claude_desktop,
        restart_hint="quit and reopen Claude Desktop",
    ),
    ClientSpec(
        "claude-code",
        "Claude Code",
        "claude-code",
        lambda: [_home() / ".claude.json"],
        project=((".mcp.json", "mcpServers"),),
        restart_hint="start a new Claude Code session",
    ),
    ClientSpec(
        "cursor",
        "Cursor",
        "mcpServers",
        lambda: [_home() / ".cursor" / "mcp.json"],
        project=((".cursor/mcp.json", "mcpServers"),),
        restart_hint="Cursor reloads MCP config automatically",
    ),
    ClientSpec(
        "vscode",
        "VS Code",
        "servers",
        lambda: [d / "mcp.json" for d in _vscode_user_dirs()],
        project=((".vscode/mcp.json", "servers"),),
        restart_hint="run 'MCP: List Servers' and restart them",
    ),
    ClientSpec("copilot", "GitHub Copilot CLI", "mcpServers", _copilot),
    ClientSpec(
        "windsurf",
        "Windsurf",
        "mcpServers",
        lambda: [_home() / ".codeium" / "windsurf" / "mcp_config.json"],
        restart_hint="refresh MCP servers in Windsurf",
    ),
    ClientSpec(
        "gemini-cli",
        "Gemini CLI",
        "mcpServers",
        lambda: [_home() / ".gemini" / "settings.json"],
        project=((".gemini/settings.json", "mcpServers"),),
    ),
    ClientSpec(
        "codex", "OpenAI Codex", "codex", _codex, project=((".codex/config.toml", "codex"),)
    ),
    ClientSpec(
        "lm-studio",
        "LM Studio",
        "mcpServers",
        lambda: [_home() / ".lmstudio" / "mcp.json", _home() / ".cache" / "lm-studio" / "mcp.json"],
    ),
    ClientSpec(
        "kiro",
        "Kiro",
        "mcpServers",
        lambda: [_home() / ".kiro" / "settings" / "mcp.json"],
        project=((".kiro/settings/mcp.json", "mcpServers"),),
    ),
    ClientSpec(
        "amazon-q",
        "Amazon Q Developer",
        "mcpServers",
        lambda: [_home() / ".aws" / "amazonq" / "mcp.json"],
    ),
    ClientSpec(
        "cline",
        "Cline",
        "mcpServers",
        lambda: [
            d / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json"
            for d in _vscode_user_dirs()
        ],
    ),
    ClientSpec(
        "roo-code",
        "Roo Code",
        "mcpServers",
        lambda: [
            d / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json"
            for d in _vscode_user_dirs()
        ],
    ),
)

CLIENT_IDS = tuple(c.id for c in CLIENTS)


def get(client_id: str) -> ClientSpec:
    for c in CLIENTS:
        if c.id == client_id:
            return c
    raise KeyError(f"unknown client {client_id!r}; known: {', '.join(CLIENT_IDS)}")


def all_config_paths() -> list[Path]:
    """Every global client config path, existing or not (for self-protection)."""
    out: list[Path] = []
    for c in CLIENTS:
        try:
            out += c.paths()
        except OSError:
            continue
    return out
