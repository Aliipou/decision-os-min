# OS isolation profile: `agent-noambient-v1` (+ optional process lock)

## Claim slices (do not say bare “TM-A PASS”)

| Slice | Expected |
|---|---|
| **TM-A-v1 FS/NET** | Durable write BLOCKED; outbound net BLOCKED; product creds ABSENT |
| **TM-A full** | Above **and** `subprocess` BLOCKED via post-bootstrap lock |

## How it works

```text
runc execve(python)          # allowed (container must boot)
  → lock_and_run.py          # trusted
  → seccomp deny execve* + NO_NEW_PRIVS
  → tm_a_probe / agent       # untrusted
```

Docker flags: `--read-only --network=none --cap-drop=ALL --security-opt=no-new-privileges`
plus start seccomp (connect/bind deny) + agent image with `libseccomp2`.

## How to run

```bash
docker build -t decision-os-agent:noambient-v1 -f sandbox/Dockerfile.agent sandbox/
./sandbox/run_tm_a_probes.sh
```

## Residual (even if subprocess BLOCKED)

- In-process RCE without exec (mmap, memory corruption)
- Kernel / container breakout
- Compromised Host
- Trust in `lock_and_run.py` as TCB in the agent image

See `docs/SUBPROCESS_BOUNDARY.md`.
