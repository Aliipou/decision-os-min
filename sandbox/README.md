# OS isolation profile: `agent-noambient-v1`

## Guarantees (when suite PASS)

Under Docker flags + seccomp profile in this directory, the untrusted agent MUST NOT:

| Probe | Expected |
|---|---|
| Write outside allowed tmp (and preferably any durable write) | BLOCKED |
| `socket.connect` / outbound network | BLOCKED |
| Spawn subprocess / `exec` | BLOCKED |
| See product credentials in env | absent |
| Hold host effect adapters | absent |

IPC to Host (stdin/stdout or mounted socket) remains allowed **from the test harness
perspective** by running Host *outside* the agent container.

## Non-guarantees

- Kernel exploits / container breakout
- Compromised Host
- Windows native isolation (this profile is **Linux/Docker**; Windows = PARTIAL)
- Perfect denial of all syscalls not listed (profile is minimal, not a full Chrome sandbox)

## How to run

```bash
./sandbox/run_tm_a_probes.sh
```

CI: workflow job `tm-a-isolation` on `ubuntu-latest`.
