# OS isolation profile: `agent-noambient-v1` + `lock_and_run`

## Claim slices — never write bare “TM-A PASS”

| Slice | Locked evidence | Unlocked destructor |
|---|---|---|
| **TM-A-v1 FS/NET** | FS write + outbound net **BLOCKED**; product creds **ABSENT** | FS often `WROTE` on host |
| **AgentCreatedProcess** | `subprocess`/`execve` and `fork` **BLOCKED** | `RAN` / `FORKED` |
| **Thread / FD exhaustion** | thread creation **BLOCKED**; FD open loop **LIMITED** | thread runs without lock |
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

Docker flags: `--read-only --network=none --cap-drop=ALL --pids-limit=64
--memory=128m --cpus=1.0 --ulimit=nofile=64:64
--security-opt=no-new-privileges`
plus start seccomp (connect/bind) + image with `libseccomp2`.

Helper: `decision_os_min.host.locked_agent_docker_cmd(agent.py)`.

## Intentionally allowed IPC

The combined boundary test allows exactly the container's inherited Docker
attach **stdin/stdout byte streams**, carrying one line-delimited JSON Intent
request and one result per exchange. The trusted test runner and `AgentHost`
remain host processes; no host source, adapter, credential, Unix socket, or
Docker socket is mounted into the container.

This does not reopen arbitrary network: the agent still runs with
`--network=none`, the attach streams are already-open file descriptors rather
than a network interface, and the host parser accepts only protocol-v1 Intent
objects. Malformed frames and an `adapter_call` bypass frame are rejected.
`tests/test_e2e_agent_boundary.py` proves the governed host write and all ambient
destructors in one locked session.

## Run

```bash
docker build -t decision-os-agent:noambient-v1 -f sandbox/Dockerfile.agent sandbox/
./sandbox/run_tm_a_probes.sh
pytest -m tm_a tests/test_os_isolation.py tests/test_e2e_agent_boundary.py
```

## Residuals (why TM-A full ≠ PASS)

- Kernel / container breakout
- Compromised Host
- Pure-Python use of APIs warmed before lock that are not consequential OS effects
- New native `.so` after lock fails by design (warm list is TCB-adjacent)
- Memory and CPU cgroups are configured bounds, not proof against every
  denial-of-service or side channel; wall-time supervision remains deployment
  responsibility.

See `docs/THREAT_MODELS.md`, `docs/SUBPROCESS_BOUNDARY.md`.
