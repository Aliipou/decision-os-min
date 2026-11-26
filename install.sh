#!/bin/sh
# Decision OS one-line installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/Aliipou/decision-os-min/product/one-click/install.sh | sh
#
# Installs the `decision-os` command in its own environment (uv, else pipx,
# else pip --user), then runs `decision-os install`, which wraps every MCP
# server of every detected app. Extra arguments go to `decision-os install`:
#
#   sh install.sh --observe          record what would happen, block nothing
#   sh install.sh --profile strict   every tool call asks until you allow it
#
# Environment overrides: DECISION_OS_REF (branch or tag), DECISION_OS_SRC
# (any pip-installable source, e.g. a local checkout).
# Undo everything with `decision-os uninstall`.
set -eu

REF="${DECISION_OS_REF:-product/one-click}"
SRC="${DECISION_OS_SRC:-https://github.com/Aliipou/decision-os-min/archive/refs/heads/${REF}.zip}"

say() { printf '%s\n' "$*"; }
fail() { say "decision-os installer: $*" >&2; exit 1; }

find_cli() {
  if command -v decision-os >/dev/null 2>&1; then command -v decision-os; return 0; fi
  for d in "${UV_TOOL_BIN_DIR:-}" "${PIPX_BIN_DIR:-}" "$HOME/.local/bin"; do
    if [ -n "$d" ] && [ -x "$d/decision-os" ]; then say "$d/decision-os"; return 0; fi
  done
  return 1
}

say "Installing Decision OS from $SRC"
if command -v uv >/dev/null 2>&1; then
  uv tool install --force "decision-os-min @ $SRC"
  BIN="$(uv tool dir --bin 2>/dev/null || true)"
  [ -n "$BIN" ] && [ -x "$BIN/decision-os" ] && CLI="$BIN/decision-os"
elif command -v pipx >/dev/null 2>&1; then
  pipx install --force "$SRC"
else
  PY="$(command -v python3 || command -v python || true)"
  [ -n "$PY" ] || fail "needs Python 3.11+ (or uv: https://docs.astral.sh/uv/)"
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || fail "needs Python 3.11 or newer; found $("$PY" --version 2>&1)"
  "$PY" -m pip install --user --upgrade "$SRC" || \
    "$PY" -m pip install --user --upgrade --break-system-packages "$SRC"
fi

CLI="${CLI:-$(find_cli || true)}"
[ -n "$CLI" ] || fail "installed, but decision-os is not on PATH; add ~/.local/bin to PATH and run: decision-os install"

say ""
"$CLI" install "$@"
case ":$PATH:" in
  *":$(dirname "$CLI"):"*) ;;
  *) say ""; say "Add $(dirname "$CLI") to your PATH to use the decision-os command directly." ;;
esac
