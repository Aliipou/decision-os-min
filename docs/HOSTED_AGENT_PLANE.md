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

| Property | Status | Evidence |
|---|---|---|
| Host-registered effect ⇒ Admission∧Legitimacy∧Authority∧PEP | **PASS** | `tests/test_hosted_agent_plane.py` h1/h2 |
| Agent has no tool/adapter handles | **PASS** | h3/h4 |
| IPC-only path to host effects | **PASS** | h2/h4 |
| DirectEffect(Agent)=∅ for ambient OS (socket/open/subprocess) | **PARTIAL** | h3 records WROTE/CONNECTED without OS jail — needs seccomp/container |

## Components

| # | Item | Status |
|---|---|---|
| 1 | AgentHost | done — `decision_os_min/host.py` |
| 2 | Untrusted agent subprocess | done — IPC client + probe |
| 3 | Mandatory FDK | done — via SealedRuntime |
| 4 | Mandatory AuthGate | done — via SealedRuntime |
| 5 | Mandatory PEP | done — arm-gated executor |
| 6 | Effect adapters on host only | done |
| 7 | IPC boundary | done — line JSON stdio |
| 8 | OS sandbox | **not done** — next milestone |
| 9 | End-to-end audit | done |
| 10 | Destructor tests | done |

## Next milestone (OS isolation)

Until DirectEffect probes are BLOCKED by the OS/container:

- do not upgrade claim from PARTIAL ambient to PASS
- Linux: seccomp / landlock / network namespace
- Windows: honest PARTIAL or Job Object / AppContainer research

## Ladder

| Layer | Status |
|---|---|
| FDK alone | governance library |
| FDK + AuthGate + PEP | governance runtime |
| SealedRuntime | enforced execution surface (in-process) |
| **Hosted agent plane** | **infrastructure architecture (this)** |
| TCB + OS/CPU enforcement | security system primitive (future) |
