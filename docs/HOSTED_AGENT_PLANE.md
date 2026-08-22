# Hosted Agent Enforcement Plane v1

## Canonical claim (use this — nothing stronger)

> A hosted enforcement architecture that places untrusted agents outside the
> trusted effect plane and requires consequential effects to cross a mandatory
> legitimacy, authority, and policy-enforcement boundary.

## Forbidden claims

- “Fully non-bypassable AI infrastructure”
- “We secured Python”
- “DirectEffect(Agent)=∅” (full) while subprocess still runs
- Bare **“TM-A PASS”** — always say **TM-A-v1 FS/NET** vs **TM-A full**

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
| AgentCreatedProcess after `lock_and_run` | **TM-A process lock** | **PASS** (Linux/Docker) | same; unlocked destructor still `RAN` |
| Full `DirectEffect(Agent)=∅` | **TM-A full** | **PARTIAL** | non-exec in-process / breakout residuals |

See [`THREAT_MODELS.md`](THREAT_MODELS.md), [`SUBPROCESS_BOUNDARY.md`](SUBPROCESS_BOUNDARY.md).

## Next milestone

Attack the process-lock residual classes (in-process non-exec, lock bypass).
Do not declare bare TM-A PASS. Only then revisit Host native TCB.

## Ladder

| Layer | Status |
|---|---|
| FDK alone | governance library |
| FDK + AuthGate + PEP | governance runtime |
| SealedRuntime | enforced execution surface (in-process) |
| **Hosted agent plane** | **infrastructure architecture (this)** |
| OS FS/NET isolation (v1) | **PASS** slice |
| OS process-creation isolation | **PARTIAL** — open research |
| TCB + OS/CPU enforcement | security system primitive (future) |
