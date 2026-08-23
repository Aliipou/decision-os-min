#!/usr/bin/env bash
# TM-A probes under agent-noambient-v1 + post-bootstrap lock (process + W^X).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECCOMP="$ROOT/sandbox/seccomp-agent-noambient-v1.json"
PROBE="$ROOT/sandbox/tm_a_probe.py"
LOCK="$ROOT/sandbox/lock_and_run.py"
IMAGE="${AGENT_SANDBOX_IMAGE:-decision-os-agent:noambient-v1}"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not available" >&2
  exit 2
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" -f "$ROOT/sandbox/Dockerfile.agent" "$ROOT/sandbox"
fi

OUT="$(docker run --rm \
  --read-only \
  --network=none \
  --cap-drop=ALL \
  --pids-limit=64 \
  --memory=128m \
  --cpus=1.0 \
  --ulimit=nofile=64:64 \
  --security-opt=no-new-privileges \
  --security-opt="seccomp=$SECCOMP" \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m \
  -e AGENT_PROBE_PATH=/agent_wrote.txt \
  -v "$PROBE:/probe.py:ro" \
  -v "$LOCK:/lock_and_run.py:ro" \
  "$IMAGE" \
  python /lock_and_run.py /probe.py)"

echo "$OUT"
python - "$OUT" <<'PY'
import json, sys

report = json.loads(sys.argv[1])
d = report["direct_effects"]
errors = []
for key in ("filesystem", "network", "subprocess", "fork", "thread", "mmap_exec", "mprotect_exec", "ptrace"):
    val = d.get(key, "")
    if not str(val).startswith("BLOCKED"):
        errors.append(f"{key}={val} (want BLOCKED*)")
if d.get("credentials") != "ABSENT":
    errors.append(f"credentials={d.get('credentials')}")
if not str(d.get("fd_limit", "")).startswith("LIMITED:"):
    errors.append(f"fd_limit={d.get('fd_limit')} (want LIMITED:*)")
if errors:
    print("TM-A FAIL:", "; ".join(errors), file=sys.stderr)
    sys.exit(1)
print("TM-A lock PASS: FS+NET+process/thread+FD+W^X+ptrace constrained")
PY
