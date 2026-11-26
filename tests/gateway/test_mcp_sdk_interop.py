"""Interop with the official MCP Python SDK on both ends of the proxy.

    mcp.ClientSession  --stdio-->  decision-os mcp-proxy  --stdio-->  mcp FastMCP server

Skipped when the `mcp` package is not installed (it is not a dependency).
"""

from __future__ import annotations

import asyncio
import json
import sys
import textwrap

import pytest

mcp = pytest.importorskip("mcp")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from conftest import APPROVED, Approver  # noqa: E402

SERVER = textwrap.dedent("""
    try:                                   # mcp >= 2
        from mcp.server.mcpserver import MCPServer as App
    except ImportError:                    # mcp 1.x
        from mcp.server.fastmcp import FastMCP as App
    from mcp.types import ToolAnnotations

    app = App("notes")
    NOTES = {"todo": "buy milk"}

    @app.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def read_note(name: str) -> str:
        return NOTES.get(name, "")

    @app.tool()
    def write_note(name: str, text: str) -> str:
        NOTES[name] = text
        return "saved"

    @app.tool()
    def delete_everything() -> str:
        NOTES.clear()
        return "gone"

    @app.tool()
    def run_command(command: str) -> str:
        return "would run: " + command

    if __name__ == "__main__":
        app.run()
""")


def _text(result) -> str:
    return " ".join(getattr(c, "text", "") for c in result.content)


def _err(result) -> bool:  # `isError` in mcp 1.x, `is_error` in 2.x
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


async def _session(home, server_py, fn):
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "decision_os_min.gateway",
            "--home",
            str(home.root),
            "mcp-proxy",
            "--client",
            "sdk",
            "--server",
            "notes",
            "--",
            sys.executable,
            str(server_py),
        ],
    )
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return await fn(s)


def test_official_sdk_client_and_server_through_the_proxy(policy_home, tmp_path):
    server_py = tmp_path / "notes_server.py"
    server_py.write_text(SERVER)

    async def scenario(s: ClientSession):
        tools = sorted(t.name for t in (await s.list_tools()).tools)
        read = await s.call_tool("read_note", {"name": "todo"})
        denied = await s.call_tool("delete_everything", {})
        catastrophic = await s.call_tool("run_command", {"command": "rm -rf ~"})
        return tools, read, denied, catastrophic

    tools, read, denied, catastrophic = asyncio.run(_session(policy_home, server_py, scenario))
    assert "delete_everything" not in tools and "read_note" in tools
    assert not _err(read) and _text(read) == "buy milk"
    assert _err(denied) and "Decision OS blocked" in _text(denied)
    assert _err(catastrophic) and "recursive delete" in _text(catastrophic)


def test_official_sdk_write_with_approval(policy_home, tmp_path):
    server_py = tmp_path / "notes_server.py"
    server_py.write_text(SERVER)

    async def scenario(s: ClientSession):
        w = await s.call_tool("write_note", {"name": "todo", "text": "buy oat milk"})
        r = await s.call_tool("read_note", {"name": "todo"})
        return w, r

    with Approver(policy_home, APPROVED) as ap:
        w, r = asyncio.run(_session(policy_home, server_py, scenario))
    assert not _err(w) and _text(w) == "saved"
    assert _text(r) == "buy oat milk"
    assert ap.seen[0]["tool"] == "write_note"
    assert json.loads(ap.seen[0]["arguments_preview"]) == {"name": "todo", "text": "buy oat milk"}
