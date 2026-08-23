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
Untrusted Agent Process              Trusted AgentHost Process
──────────────────────              ─────────────────────────
Intent JSON only (IPC)   ──────►    Admission
no tool callables                   FDK legitimacy (mandatory)
no effect adapters                  AuthGate / decision kernel
                                    PEP (arm-gated)
                                    Effect adapters (only here)
```

## Evidence

| Property | Threat model | Status | Evidence |
|---|---|---|---|
| Host-registered effect ⇒ chain | **TM-H** | **PASS** | `tests/test_hosted_agent_plane.py` |
| Agent has no tool/adapter handles | **TM-H** | **PASS** | h3/h4 |
| IPC-only path to host effects | **TM-H** | **PASS** | h2/h4 |
| Durable FS write + outbound net + ambient creds | **TM-A-v1 FS/NET** | **PASS** | `tests/test_os_isolation.py` |
| AgentCreatedProcess after `lock_and_run` | **TM-A process** | **PASS** | unlocked exec=`RAN`, fork=`FORKED` |
| W^X + ptrace after lock | **TM-A non-exec** | **PASS** | unlocked still `MAPPED`/`EXEC_GRANTED`/`ATTACHED` |
| Locked agent → Intent IPC → governed host effect | **TM-H + named TM-A slices** | **PASS** | `tests/test_e2e_agent_boundary.py` |
| Full `DirectEffect(Agent)=∅` | **TM-A full** | **PARTIAL** | breakout / Host / out-of-profile |

See [`THREAT_MODELS.md`](THREAT_MODELS.md), [`SUBPROCESS_BOUNDARY.md`](SUBPROCESS_BOUNDARY.md).

The combined test's sole intentional channel is Docker attach stdin/stdout
carrying protocol-v1 JSONL. `AgentHost` and its adapter stay on the host. No
network interface or host/Docker socket is exposed to the container, so this
request/response pipe is not a general outbound transport.

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
