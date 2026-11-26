"""A minimal stdio MCP server for proxy tests. Logs every tools/call it receives."""

from __future__ import annotations

import json
import os
import sys

LOG = os.environ.get("FAKE_MCP_LOG")
TOOLS = [
    {"name": "read_file", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
    {"name": "write_file", "inputSchema": {"type": "object"}},
    {"name": "delete_everything", "inputSchema": {"type": "object"}},
    {
        "name": "frobnicate",
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True},
    },
    {"name": "ask_roots", "inputSchema": {"type": "object"}},
]


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    waiting_roots = None
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method = msg.get("method")
        if method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fake", "version": "1"},
                    },
                }
            )
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = msg["params"]
            if LOG:
                with open(LOG, "a") as f:
                    f.write(json.dumps(p) + "\n")
            if p["name"] == "ask_roots":
                waiting_roots = msg["id"]
                send({"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"})
                continue
            send(
                {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(p.get("arguments"))}]
                    },
                }
            )
        elif msg.get("id") == "srv-1" and "result" in msg:  # client answered roots/list
            send(
                {
                    "jsonrpc": "2.0",
                    "id": waiting_roots,
                    "result": {"content": [{"type": "text", "text": json.dumps(msg["result"])}]},
                }
            )
        elif method == "resources/read":
            if LOG:
                with open(LOG, "a") as f:
                    f.write(
                        json.dumps({"name": "resources/read", "arguments": msg["params"]}) + "\n"
                    )
            send(
                {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {
                        "contents": [{"uri": msg["params"]["uri"], "text": "resource body"}]
                    },
                }
            )
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        elif method and method.startswith("notifications/"):
            if method == "notifications/initialized":
                send(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {"level": "info", "data": "hello"},
                    }
                )


if __name__ == "__main__":
    main()
