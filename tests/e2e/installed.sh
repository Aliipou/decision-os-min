#!/usr/bin/env bash
# End-to-end check of what a user actually gets: the one-line installer, run on
# a built wheel, in a throwaway HOME, then real MCP clients launched exactly as
# their config files say. Run it from the repo root on purpose: the source tree
# must not be what makes it work.
#
#   python -m pip wheel --no-deps -w dist . && bash tests/e2e/installed.sh dist/*.whl
set -euo pipefail
WHEEL="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
E2E="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$E2E/../.." && pwd)"

export HOME="$(mktemp -d)"
export PATH="$HOME/.local/bin:$PATH"
export E2E_SERVER_LOG="$HOME/server.log"
fails=0
check() { if grep -qF -- "$2" <<<"$3"; then echo "  pass  $1"; else echo "  FAIL  $1 (wanted: $2)"; fails=$((fails + 1)); fi; }

PY="$(command -v python3)"
export XDG_CONFIG_HOME="$HOME/.config"  # CI runners set their own
case "$(uname -s)" in
  Darwin) APPDIR="$HOME/Library/Application Support" ;;
  *) APPDIR="$XDG_CONFIG_HOME" ;;
esac
mkdir -p "$APPDIR/Claude" "$HOME/.ssh" "$HOME/work"
echo "PRIVATE KEY" > "$HOME/.ssh/id_rsa"
echo "hello from notes" > "$HOME/work/notes.txt"
DESKTOP="$APPDIR/Claude/claude_desktop_config.json"
echo "{\"mcpServers\": {\"files\": {\"command\": \"$PY\", \"args\": [\"$E2E/mcp_server.py\"]}}}" > "$DESKTOP"
echo "{\"numStartups\": 3, \"mcpServers\": {\"tools\": {\"command\": \"$PY\", \"args\": [\"$E2E/mcp_server.py\"]}}}" > "$HOME/.claude.json"
before="$(cat "$DESKTOP" "$HOME/.claude.json" | sha256sum)"

echo "== install.sh on $(basename "$WHEEL")"
DECISION_OS_SRC="$WHEEL" sh "$REPO/install.sh"
decision-os doctor

call() { (cd "$REPO" && "$PY" "$E2E/mcp_client.py" "$1" "$2" "$3" 2>/dev/null); }

echo "== enforcement, launched from the repo root"
out="$(call "$DESKTOP" mcpServers.files '[
 ["read_file", {"path": "'"$HOME"'/work/notes.txt"}],
 ["read_file", {"path": "~/.ssh/id_rsa"}],
 ["run_command", {"command": "rm -rf /"}],
 ["write_file", {"path": "'"$HOME"'/work/t.txt", "content": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]
]')"
echo "$out"
check "Claude Desktop server launched through the gateway" "'mcp-proxy', '--client', 'claude-desktop'" "$out"
check "tools listed through the proxy" "TOOLS: ['read_file', 'write_file', 'run_command']" "$out"
check "read-only call runs" "-> OK: hello from notes" "$out"
check "credential path blocked" "protected credentials path" "$out"
check "catastrophic command blocked" "recursive delete" "$out"
check "secret in arguments blocked" "contains a GitHub token" "$out"
out="$(call "$HOME/.claude.json" mcpServers.tools '[["run_command", {"command": "rm -rf ~"}]]')"
check "Claude Code server launched through the gateway" "'mcp-proxy', '--client', 'claude-code'" "$out"
check "Claude Code governed too" "recursive delete" "$out"

echo "== human approval"
call "$DESKTOP" mcpServers.files '[["write_file", {"path": "'"$HOME"'/work/a.txt", "content": "approved"}]]' >"$HOME/a.out" &
sleep 5; echo a | decision-os approve >/dev/null; wait
check "approved write runs" "approved" "$(cat "$HOME/work/a.txt" 2>/dev/null)"
call "$DESKTOP" mcpServers.files '[["write_file", {"path": "'"$HOME"'/work/b.txt", "content": "no"}]]' >"$HOME/b.out" &
sleep 5; echo d | decision-os approve >/dev/null; wait
check "denied write refused" "denied by you" "$(cat "$HOME/b.out")"
[ ! -e "$HOME/work/b.txt" ] && echo "  pass  denied write left no file" || { echo "  FAIL  denied write ran"; fails=$((fails + 1)); }

echo "== only allowed calls reached the server"
cat "$E2E_SERVER_LOG"
n="$(grep -c EXECUTED "$E2E_SERVER_LOG")"
[ "$n" = 2 ] && echo "  pass  2 executions (1 read, 1 approved write)" || { echo "  FAIL  $n executions"; fails=$((fails + 1)); }
check "audit chain verifies" "chain verified" "$(decision-os audit --verify)"

echo "== uninstall"
decision-os uninstall
[ "$(cat "$DESKTOP" "$HOME/.claude.json" | sha256sum)" = "$before" ] \
  && echo "  pass  configs restored byte for byte" || { echo "  FAIL  configs differ"; fails=$((fails + 1)); }

echo; [ "$fails" = 0 ] && echo "all end-to-end checks passed" || { echo "$fails end-to-end check(s) failed"; exit 1; }
