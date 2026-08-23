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
  → optional trusted connect to /run/decision-os/agent.sock
  → lock_and_run: NO_NEW_PRIVS + seccomp
       deny connect/connectat/bind  # inherited AF_UNIX FD remains usable
       deny execve/execveat
       deny fork/vfork/clone/clone3
       deny mmap/mprotect when PROT_EXEC
       deny ptrace / process_vm_* 
  → untrusted agent / probe
```

Docker flags: `--read-only --network=none --cap-drop=ALL --pids-limit=64
--security-opt=no-new-privileges`
plus a start seccomp profile + image with `libseccomp2`.

Two start profiles exist without changing the post-bootstrap lock:

- `seccomp-agent-noambient-v1.json` denies all connect/bind from container start
  for agents that need no IPC.
- `seccomp-agent-ipc-v1.json` permits only the trusted launcher to perform the
  pre-lock AF_UNIX connect (bind remains denied). Untrusted code starts after
  `lock_and_run` denies all further connects. This profile must be paired with
  `--network=none`; the sole mounted channel is `/run/decision-os/agent.sock`.

Helper: `decision_os_min.host.locked_agent_docker_cmd(agent.py)`.

## Run

```bash
docker build -t decision-os-agent:noambient-v1 -f sandbox/Dockerfile.agent sandbox/
./sandbox/run_tm_a_probes.sh
pytest -m tm_a tests/test_os_isolation.py
```

The final TM-A test starts a real Docker/Linux agent and an external AgentHost,
proves a governed adapter writes host-only effect state exactly once, then runs
filesystem, outbound-network, subprocess, fork, replay, and legitimacy-denial
destructors. On Linux CI, missing Docker is a failure rather than a skip.

## Residuals (why TM-A full ≠ PASS)

- Kernel / container breakout
- Compromised Host
- Theft of an agent's own per-agent IPC key permits impersonating that identity
  (it does not grant another identity or bypass policy)
- In-memory replay state is process-local; multi-host deployments require a
  shared bounded nonce store before accepting the same identity on several hosts
- Pure-Python use of APIs warmed before lock that are not consequential OS effects
- New native `.so` after lock fails by design (warm list is TCB-adjacent)

See `docs/THREAT_MODELS.md`, `docs/SUBPROCESS_BOUNDARY.md`.
