# OS isolation profile: `agent-noambient-v1` + `lock_and_run`

## Claim slices — never write bare “TM-A PASS”

| Slice | Locked evidence | Unlocked destructor |
|---|---|---|
| **TM-A-v1 FS/NET** | FS write + outbound net **BLOCKED**; product creds **ABSENT** | FS often `WROTE` on host |
| **AgentCreatedProcess** | `subprocess` **BLOCKED** | `RAN` |
| **Non-exec W^X / ptrace** | `mmap_exec` / `mprotect_exec` / `ptrace` **BLOCKED** | `MAPPED` / `EXEC_GRANTED` / `ATTACHED` |
| **TM-A full** | **PARTIAL** | breakout / Host / out-of-profile |

## Lifecycle

```text
runc execve(python)                 # container must boot
  → warm-import stdlib .so
  → lock_and_run: NO_NEW_PRIVS + seccomp
       deny execve/execveat
       deny mmap/mprotect when PROT_EXEC
       deny ptrace / process_vm_* 
  → untrusted agent / probe
```

Docker flags: `--read-only --network=none --cap-drop=ALL --security-opt=no-new-privileges`
plus start seccomp (connect/bind) + image with `libseccomp2`.

Helper: `decision_os_min.host.locked_agent_docker_cmd(agent.py)`.

## Run

```bash
docker build -t decision-os-agent:noambient-v1 -f sandbox/Dockerfile.agent sandbox/
./sandbox/run_tm_a_probes.sh
pytest -m tm_a tests/test_os_isolation.py
```

## Residuals (why TM-A full ≠ PASS)

- Kernel / container breakout
- Compromised Host
- Pure-Python use of APIs warmed before lock that are not consequential OS effects
- New native `.so` after lock fails by design (warm list is TCB-adjacent)

See `docs/THREAT_MODELS.md`, `docs/SUBPROCESS_BOUNDARY.md`.
