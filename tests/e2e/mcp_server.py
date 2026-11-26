"""Minimal stdio MCP server used as the governed target in the end-to-end check.

Every tools/call that reaches it is appended to $E2E_SERVER_LOG, so the test can
prove that blocked calls never arrived.
"""

import json
import os
import sys

LOG = os.environ.get("E2E_SERVER_LOG", "e2e-server.log")
STR = {"type": "string"}
TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file",
        "inputSchema": {"type": "object", "properties": {"path": STR}, "required": ["path"]},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "write_file",
        "description": "Write a file",
        "inputSchema": {"type": "object", "properties": {"path": STR, "content": STR}},
    },
    {
        "name": "run_command",
        "description": "Run a shell command",
        "inputSchema": {"type": "object", "properties": {"command": STR}},
    },
]


def reply(id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    msg.update({"error": error} if error else {"result": result})
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def call(name, args):
    with open(LOG, "a") as f:
        f.write(f"EXECUTED {name} {json.dumps(args)}\n")
    if name == "read_file":
        with open(os.path.expanduser(args["path"])) as f:
            return f.read()
    if name == "write_file":
        with open(os.path.expanduser(args["path"]), "w") as f:
            f.write(args.get("content", ""))
        return "ok"
    return "(not run) " + args["command"]


for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    method, id_ = msg.get("method"), msg.get("id")
    if id_ is None:
        continue
    if method == "initialize":
        version = msg["params"].get("protocolVersion", "2025-06-18")
        info = {"name": "e2e", "version": "1"}
        reply(id_, {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": info})
    elif method == "tools/list":
        reply(id_, {"tools": TOOLS})
    elif method == "tools/call":
        try:
            text = call(msg["params"]["name"], msg["params"].get("arguments", {}))
            reply(id_, {"content": [{"type": "text", "text": text}]})
        except Exception as exc:
            reply(id_, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
    else:
        reply(id_, error={"code": -32601, "message": "unknown method"})
