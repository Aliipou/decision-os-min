# Hosted Agent Enforcement Plane v1

## Canonical claim (use this — nothing stronger)

> A hosted enforcement architecture that places untrusted agents outside the
> trusted effect plane and requires consequential effects to cross a mandatory
> legitimacy, authority, and policy-enforcement boundary.

## Forbidden claims

- “Fully non-bypassable AI infrastructure”
- “We secured Python”
- “DirectEffect(Agent)=∅ on every OS without sandbox”

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

Conceptual shift:

```text
was:  Agent → (hopefully uses) Governance
now:  Agent → Host → Governance → Effect
```

The agent no longer owns the execution path for host-registered effects.

## Evidence

| Property | Threat model | Status | Evidence |
|---|---|---|---|
| Host-registered effect ⇒ chain | **TM-H** | **PASS** | `tests/test_hosted_agent_plane.py` |
| Agent has no tool/adapter handles | **TM-H** | **PASS** | h3/h4 |
| IPC-only path to host effects | **TM-H** | **PASS** | h2/h4 |
| DirectEffect(Agent)=∅ (FS/net/exec) | **TM-A** | **Linux/Docker suite** — local without Docker = skip | `sandbox/`, `tests/test_os_isolation.py` |

See [`THREAT_MODELS.md`](THREAT_MODELS.md). Do not mix TM-H PASS with TM-A.

## Components

| # | Item | Status |
|---|---|---|
| 1–7 | Host + IPC + FDK/AuthGate/PEP/adapters | done |
| 8 | OS sandbox `agent-noambient-v1` | Linux/Docker CI — Windows local = skip |
| 9–10 | Audit + destructor tests (TM-H) | done |

## Next milestone

Break TM-A with real ambient attacks; harden `agent-noambient-v1` until they stay BLOCKED.
Only then revisit native TCB (maybe Rust) for Host compromise resistance.

## Ladder

| Layer | Status |
|---|---|
| FDK alone | governance library |
| FDK + AuthGate + PEP | governance runtime |
| SealedRuntime | enforced execution surface (in-process) |
| **Hosted agent plane** | **infrastructure architecture (this)** |
| TCB + OS/CPU enforcement | security system primitive (future) |
