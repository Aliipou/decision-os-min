#!/usr/bin/env bash
# Run TM-A ambient probes inside agent-noambient-v1.
# Exit 0 only if filesystem, network, and subprocess are BLOCKED and credentials ABSENT.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECCOMP="$ROOT/sandbox/seccomp-agent-noambient-v1.json"
PROBE="$ROOT/sandbox/tm_a_probe.py"
IMAGE="${AGENT_SANDBOX_IMAGE:-python:3.12-slim-bookworm}"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not available" >&2
  exit 2
fi

OUT="$(docker run --rm \
  --read-only \
  --network=none \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --security-opt="seccomp=$SECCOMP" \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m \
  -e AGENT_PROBE_PATH=/agent_wrote.txt \
  -v "$PROBE:/probe.py:ro" \
  "$IMAGE" \
  python /probe.py)"

echo "$OUT"
python - "$OUT" <<'PY'
import json, sys

report = json.loads(sys.argv[1])
d = report["direct_effects"]
errors = []
for key in ("filesystem", "network", "subprocess"):
    val = d.get(key, "")
    if not str(val).startswith("BLOCKED"):
        errors.append(f"{key}={val} (want BLOCKED*)")
if d.get("credentials") != "ABSENT":
    errors.append(f"credentials={d.get('credentials')}")
if errors:
    print("TM-A FAIL:", "; ".join(errors), file=sys.stderr)
    sys.exit(1)
print("TM-A PASS: ambient probes blocked")
PY
