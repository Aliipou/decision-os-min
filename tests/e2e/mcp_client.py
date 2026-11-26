"""Launch an MCP server exactly as an app's config file says, then call tools.

mcp_client.py CONFIG KEY.PATH '[["tool", {"arg": 1}], ...]'
mcp_client.py CONFIG KEY.PATH @calls.json
"""

import json
import os
import subprocess
import sys
import threading

cfg_path, key, raw = sys.argv[1], sys.argv[2], sys.argv[3]
if raw.startswith("@"):
    with open(raw[1:], encoding="utf-8") as f:
        raw = f.read()
calls = json.loads(raw)
with open(cfg_path, encoding="utf-8") as f:
    entry = json.load(f)
for part in key.split("."):
    entry = entry[part]
print("LAUNCH:", entry["command"], entry.get("args"))
env = {**os.environ, **entry["env"]} if entry.get("env") else None
proc = subprocess.Popen(
    [entry["command"], *entry.get("args", [])],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env=env,
)
threading.Thread(target=lambda: [sys.stderr.write(ln) for ln in proc.stderr], daemon=True).start()


def send(msg):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", **msg}) + "\n")
    proc.stdin.flush()


def rpc(id_, method, params, timeout=60):
    send({"id": id_, "method": method, "params": params})
    box = {}
    reader = threading.Thread(target=lambda: box.setdefault("line", proc.stdout.readline()))
    reader.start()
    reader.join(timeout)
    return json.loads(box["line"]) if box.get("line") else {"TIMEOUT": True}


client = {"name": "e2e", "version": "1"}
rpc(0, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": client})
send({"method": "notifications/initialized"})
tools = rpc(1, "tools/list", {}).get("result", {}).get("tools", [])
print("TOOLS:", [t["name"] for t in tools])
for n, (name, args) in enumerate(calls, start=2):
    r = rpc(n, "tools/call", {"name": name, "arguments": args})
    if "result" in r:
        text = " ".join(c.get("text", "") for c in r["result"].get("content", []))[:160]
        status = "ERROR" if r["result"].get("isError") else "OK"
        print(f"CALL {name} {args} -> {status}: {text}")
    else:
        print(f"CALL {name} {args} -> {r}")
proc.stdin.close()
proc.terminate()
