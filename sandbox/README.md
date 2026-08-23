# OS isolation profile: `agent-noambient-v1` + `lock_and_run`

## Claim slices — never write bare “TM-A PASS”

| Slice | Locked evidence | Unlocked destructor |
|---|---|---|
| **TM-A-v1 FS/NET** | FS write + outbound net **BLOCKED**; product creds **ABSENT** | FS often `WROTE` on host |
| **AgentCreatedProcess** | `subprocess`/`execve` and `fork` **BLOCKED** | `RAN` / `FORKED` |
| **Non-exec W^X / ptrace** | `mmap_exec` / `mprotect_exec` / `ptrace` **BLOCKED** | `MAPPED` / `EXEC_GRANTED` / `ATTACHED` |
| **TM-A full** | **PARTIAL** | breakout / Host / out-of-profile |

## Lifecycle

```text
runc execve(python)                 # container must boot
  → warm-import stdlib .so
  → lock_and_run: NO_NEW_PRIVS + seccomp
       deny execve/execveat
       deny fork/vfork/clone/clone3
       deny mmap/mprotect when PROT_EXEC
       deny ptrace / process_vm_* 
  → untrusted agent / probe
```

Docker/runtime controls: `--read-only --network=none --cap-drop=ALL
--pids-limit=64 --memory=128m --memory-swap=128m --cpus=0.5
--ulimit=nofile=64:64 --security-opt=no-new-privileges`, plus an in-container
`timeout --signal=KILL 10s` wall supervisor.
plus start seccomp (connect/bind) + image with `libseccomp2`.

Helper: `decision_os_min.host.locked_agent_docker_cmd(agent.py)`.

## Run

```bash
docker build -t decision-os-agent:noambient-v1 -f sandbox/Dockerfile.agent sandbox/
./sandbox/run_tm_a_probes.sh
pytest -m tm_a tests/test_os_isolation.py
pytest -m tm_a tests/test_resource_exhaustion.py
```

## Resource-exhaustion evidence

The probes are bounded or container-confined and clean up descriptors/children.
Post-lock fork and thread loops are **BLOCKED** by seccomp; descriptor pressure is
**LIMITED** by `RLIMIT_NOFILE`; memory pressure is **KILLED** by cgroup OOM; a CPU
loop is CPU-quota **LIMITED** while running and **KILLED** by the wall supervisor.
A timeout proves termination for the tested command, not universal sandbox safety.

## Residuals (why TM-A full ≠ PASS)

- Kernel / container breakout
- Compromised Host
- Pure-Python use of APIs warmed before lock that are not consequential OS effects
- New native `.so` after lock fails by design (warm list is TCB-adjacent)
- Host/kernel denial-of-service and deployments that omit the canonical controls

See `docs/THREAT_MODELS.md`, `docs/SUBPROCESS_BOUNDARY.md`.
