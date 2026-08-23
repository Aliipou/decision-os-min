# Hosted Agent Enforcement Plane v1

## Canonical claim (use this — nothing stronger)

> A hosted enforcement architecture that places untrusted agents outside the
> trusted effect plane and requires consequential effects to cross a mandatory
> legitimacy, authority, and policy-enforcement boundary.

## Forbidden claims

- “Fully non-bypassable AI infrastructure”
- “We secured Python”
- Bare **“TM-A PASS”** — always name the slice

## Architecture

```text
Untrusted Docker/Linux agent                 External trusted AgentHost
────────────────────────────                 ──────────────────────────
read-only root, no capabilities              owns per-agent 256-bit key
--network=none                               owns effect adapters/credentials
trusted launcher connects one AF_UNIX socket
then seccomp denies connect/bind/fork/exec
inherited FD: framed + HMAC Intent  ───────► identity/freshness/replay check
                                             Admission → legitimacy
                                             AuthGate/decision kernel → PEP
                                             real effect adapter (only here)
```

## The one allowed channel

`/run/decision-os/agent.sock` is the only declared agent boundary channel. The
socket directory is mounted read-only into the agent container. `lock_and_run.py`
(trusted bootstrap) connects it before loading agent code, duplicates it to FD 3,
then installs seccomp rules denying every later `connect`, `connectat`, `bind`,
process creation, executable mappings, and ptrace. The untrusted script receives
only that already-connected FD and its own per-agent key file.

The container always uses `--network=none`; arbitrary outbound IP networking
therefore remains unavailable during bootstrap as well as after lockdown. The
AgentHost, audit path, effect state, adapters, and product credentials are not
mounted into the agent.

Authenticated IPC v1 is canonical JSON inside a four-byte big-endian length
frame. The host enforces a 64 KiB frame limit and a complete-frame deadline,
requires a per-agent HMAC-SHA256 over every Intent, binds the authenticated
`agent_id`, checks a timestamp window, and consumes a bounded nonce before Intent
parsing. Responses are also authenticated and bound to `agent_id` and
`request_id`. Unknown identities, bad MACs, stale messages, replay, malformed
Intents, oversized frames, and partial-frame timeouts fail closed before
admission/effect.

## Evidence

| Property | Threat model | Status | Evidence |
|---|---|---|---|
| Host-registered effect ⇒ chain | **TM-H** | **PASS** | `tests/test_hosted_agent_plane.py` |
| Agent has no tool/adapter handles | **TM-H** | **PASS** | h3/h4 |
| IPC-only path to host effects | **TM-H** | **PASS** | h2/h4 |
| Framing / identity / replay / size / deadline | **TM-H IPC v1** | **PASS** | `tests/test_authenticated_ipc.py` |
| Sandboxed agent → authenticated IPC → real effect | **TM-H + declared TM-A slices** | **PASS** | Linux/Docker test in `tests/test_os_isolation.py` |
| Durable FS write + outbound net + ambient creds | **TM-A-v1 FS/NET** | **PASS** | `tests/test_os_isolation.py` |
| AgentCreatedProcess after `lock_and_run` | **TM-A process** | **PASS** | unlocked exec=`RAN`, fork=`FORKED` |
| W^X + ptrace after lock | **TM-A non-exec** | **PASS** | unlocked still `MAPPED`/`EXEC_GRANTED`/`ATTACHED` |
| Full `DirectEffect(Agent)=∅` | **TM-A full** | **PARTIAL** | breakout / Host / out-of-profile |

See [`THREAT_MODELS.md`](THREAT_MODELS.md), [`SUBPROCESS_BOUNDARY.md`](SUBPROCESS_BOUNDARY.md).

## Next milestone

Only if residuals demand it: gVisor / Host native TCB.  
Do not declare bare TM-A PASS.

## Ladder

| Layer | Status |
|---|---|
| FDK alone | governance library |
| FDK + AuthGate + PEP | governance runtime |
| SealedRuntime | enforced execution surface (in-process) |
| **Hosted agent plane** | **infrastructure architecture (this)** |
| OS FS/NET + process + W^X lock | **PASS** under declared profile |
| Absolute DirectEffect=∅ | **PARTIAL** |
| TCB + OS/CPU enforcement | future / optional |
