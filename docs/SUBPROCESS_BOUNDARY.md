# Subprocess Boundary — Derivation From Failure

**Date:** 2026-08-23  
**Trigger evidence:** under `agent-noambient-v1` Docker flags alone:

```text
filesystem: BLOCKED
network:    BLOCKED
credentials: ABSENT
subprocess: RAN
```

**Rule:** Do not weaken TM-A. `AgentCreatedProcess` stays in `DirectEffect`.  
**Rule:** Do not claim bare TM-A PASS. See `THREAT_MODELS.md` claim slices.

---

## What failed (precisely)

```text
seccomp deny execve at container start
        ↓
runc cannot execve(/usr/local/bin/python)
        ↓
container never boots
```

This does **not** prove “subprocess cannot be blocked.”  
It proves: **naive execve denial at bootstrap conflicts with container lifecycle.**

Target property:

```text
TrustedBootstrapAllowed ∧ (AgentCreatedProcess ⇒ blocked)
```

---

## Options compared

| # | Mechanism | Property gained | Residual bypasses | Complexity | Portability | TCB impact | Test strategy |
|---|---|---|---|---|---|---|---|
| 1 | **Seccomp after bootstrap** (trusted entry locks, then runs agent) | Blocks further `execve`/`execveat` in same PID | mmap+shellcode, interpreter-only RCE, kernel bugs; must trust entry | Low | Linux + libseccomp | Small trusted entry in agent image | Probe after lock: subprocess MUST BLOCKED |
| 2 | Nested sandbox (nsjail/bwrap) | New mount/pid/user + optional seccomp for child | Escape nested jail; outer still has exec for launcher | Medium | Linux; extra binary | Launcher + jail binary | Child probe inside nest |
| 3 | Separate agent container/process | Already Host↔Agent split | Inside agent container, subprocess still free unless (1)/(2) | Low (already have) | High | Host TCB unchanged | Does not close RAN alone |
| 4 | gVisor / runsc | Stronger syscall interception | Runtime bugs; not everywhere | High | Limited hosts | Large external TCB | Same probes under runsc |
| 5 | Namespaces/capabilities only | Shrink privilege | **Does not block exec of image bins** | Low | High | Small | Will still show subprocess RAN |
| 6 | Dedicated supervisor (fork → lock child → run agent) | Clear trust cut; parent can die | Same class as (1) if child locked | Low–med | Linux | Supervisor binary/script | Destructor in child only |

### Minimum candidate (chosen to implement next)

**#1 post-bootstrap seccomp via trusted entrypoint** (same idea as #6 without a second language).

Why minimum:

- Fits the failure mode (lifecycle-aware).
- Smallest new TCB: one lock module + libseccomp in agent image.
- Does not require gVisor or rewriting Host.
- Falsifiable: if probe still `RAN` after lock, architecture revises (not the test).

Not chosen by default: gVisor (#4) — stronger but not minimum.  
Not sufficient alone: #3 and #5 — already know subprocess RAN.

---

## Candidate design

```text
docker start
   → python trusted_entry.py   # execve allowed (Docker default / permissive start)
   → trusted_entry installs seccomp(filter: deny execve, execveat) + NO_NEW_PRIVS
   → trusted_entry runpy's untrusted agent/probe
   → agent subprocess/exec → BLOCKED
```

Trusted: `sandbox/lock_and_run.py` (+ libseccomp).  
Untrusted: agent module / `tm_a_probe.py` body after handoff.

---

## Implemented candidate result (2026-08-23)

`sandbox/lock_and_run.py` (warm imports → seccomp):

```text
locked:   FS/NET/subprocess/fork/mmap_exec/mprotect_exec/ptrace = BLOCKED*
unlocked: subprocess=RAN, fork=FORKED, mmap_exec=MAPPED,
          mprotect_exec=EXEC_GRANTED, ptrace=ATTACHED
```

**Tradeoff:** after W^X lock, new native `.so` loads fail (must warm before lock).

**TM-A full** stays PARTIAL (breakout / Host / out-of-profile).
See `THREAT_MODELS.md`.
