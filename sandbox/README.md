# OS isolation profile: `agent-noambient-v1`

## Guarantees (when suite PASS)

Under Docker flags + seccomp profile in this directory, the untrusted agent MUST NOT:

| Probe | Expected (v1) |
|---|---|
| Durable filesystem write (`AGENT_PROBE_PATH`) | BLOCKED (`--read-only`) |
| Outbound `socket.connect` | BLOCKED (`--network=none` + seccomp) |
| Product credentials in env | ABSENT |
| Host effect adapters | ABSENT (not mounted) |

| Probe | Residual (not a v1 PASS gate) |
|---|---|
| `subprocess` / `execve` of image binaries | Often still **RAN** — blocking `execve` in seccomp also blocks container start |

## Non-guarantees

- Kernel exploits / container breakout
- Compromised Host
- Windows native isolation without Docker (local Windows = Docker Desktop or skip)
- Full denial of `exec` inside the image (needs stronger runtime: gVisor / nested jail — next harden)
## How to run

```bash
./sandbox/run_tm_a_probes.sh
```

CI: workflow job `tm-a-isolation` on `ubuntu-latest`.
