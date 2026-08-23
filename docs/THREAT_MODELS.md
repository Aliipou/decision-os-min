# Threat Models — Formal Split (Frozen)

**Status:** Locked 2026-08-23 (updated after W^X / ptrace lock evidence)  
**Source of truth:** this file + `HOSTED_AGENT_PLANE.md` + `SUBPROCESS_BOUNDARY.md`

Do **not** mix TM-H and TM-A. Do **not** write bare **“TM-A PASS”**.

---

## TM-H — Host-registered product effects

**Evidence:** **PASS** — `tests/test_hosted_agent_plane.py`

**Claim:** Hosted enforcement plane for host-registered effects.

---

## TM-A — Agent must not create consequential direct effects

**Full invariant (unchanged):**

```text
DirectEffect(Agent) = ∅
```

### Claim slices

| Slice | Meaning | Status |
|---|---|---|
| **TM-A-v1 FS/NET** | Durable FS write + outbound net + ambient product creds | **PASS** |
| **AgentCreatedProcess** | `execve` + `fork/vfork/clone/clone3` after `lock_and_run` | **PASS** |
| **Thread / FD exhaustion** | clone-denial + `nofile=64` under declared profile | **PASS** for tested probes |
| **Memory / CPU bounds** | Docker cgroups (`128m`, `1.0 CPU`) | **CONFIGURED**, not universal DoS proof |
| **Non-exec W^X / ptrace** | `mmap`/`mprotect` PROT_EXEC + `ptrace` after lock | **PASS** |
| **TM-A full** | Zero residual DirectEffect (breakout, Host, logic bombs) | **PARTIAL** |

**Evidence (`tests/test_os_isolation.py`):**

```text
locked:   FS/NET/subprocess/fork/thread/mmap_exec/mprotect_exec/ptrace = BLOCKED*
          fd_limit = LIMITED:*
unlocked: subprocess=RAN, fork=FORKED, mmap_exec=MAPPED,
          mprotect_exec=EXEC_GRANTED, ptrace=ATTACHED
```

**Lifecycle note:** warm-import stdlib `.so` **before** W^X lock; after lock, new executable mappings fail (intentional — blocks late native loads).

**Allowed claim:**

> TM-A OS isolation under `agent-noambient-v1` + `lock_and_run` (FS/NET/process/W^X/ptrace).

**Forbidden:** bare “TM-A PASS” / “fully non-bypassable”.

### Remaining residuals (why TM-A full ≠ PASS)

- Container/kernel breakout
- Compromised Host (TM-H/TM-K)
- Pure-Python abuse of **already-warmed** APIs that are not consequential OS effects
- Anything outside the declared Docker+lock profile (e.g. raw Windows without Docker)

---

## Roadmap

```text
1. TM-H freeze                         ← done
2. TM-A claim slices                   ← done
3. AgentCreatedProcess + W^X lock      ← done (this evidence)
4. Optional: Host native TCB / gVisor  ← only if residuals demand it
```
