# Threat Models — Formal Split (Frozen)

**Status:** Locked 2026-08-23 (claim naming revised after subprocess residual)  
**Source of truth for claims:** this file + `HOSTED_AGENT_PLANE.md` + `ARCHITECTURE_DERIVATION.md`

Do **not** mix TM-H and TM-A in outreach or CI badges.  
Do **not** write bare **“TM-A PASS”** — always qualify the slice.

---

## TM-H — Host-registered product effects

**Adversary:** Untrusted agent that may be malicious, but product effects (tools,
adapters, credentials for the product) live only in the Host.

**Invariant:**

```text
∀ host-registered effect e:
  Executed(e) ⇒ Admission ∧ Legitimacy ∧ Authority ∧ PEP
```

**Evidence today:** **PASS** — `tests/test_hosted_agent_plane.py`, SealedRuntime destructors.

**Claim language:**

> Hosted enforcement plane for host-registered effects.

---

## TM-A — Agent must not create consequential direct effects

**Adversary:** Untrusted agent process with whatever ambient OS rights the
deployment left it.

**Full invariant (unchanged — do not weaken):**

```text
DirectEffect(Agent) = ∅
```

under the declared sandbox profile. **Subprocess / agent-created processes remain
in scope.** Removing them from the definition to green a test is forbidden.

### Claim slices (required naming)

| Slice | Meaning | Status today |
|---|---|---|
| **TM-A-v1 FS/NET** | No durable FS write + no outbound network + no ambient product credentials | **PASS** under Docker `agent-noambient-v1` |
| **AgentCreatedProcess** | After trusted `lock_and_run` seccomp | **PASS** under same profile + lock (destructor: unlocked still `RAN`) |
| **TM-A full** | Full `DirectEffect(Agent)=∅` (incl. non-exec in-process RCE) | **PARTIAL** — residuals: mmap/shellcode-class, breakout, Host compromise |

**Evidence:**

- Control (no sandbox): FS `WROTE`
- Docker flags only (no lock): FS/NET BLOCKED, subprocess **RAN**
- Docker + `lock_and_run.py`: FS/NET/subprocess **BLOCKED** (`tests/test_os_isolation.py`)

**Allowed claim language:**

> TM-A-v1 FS/NET + AgentCreatedProcess lock under `agent-noambient-v1`.

**Forbidden:** bare “TM-A PASS” (implies zero residual DirectEffect).

---

## What we will not claim

| Phrase | Allowed? |
|---|---|
| TM-A PASS (unqualified) | **No** while full DirectEffect is PARTIAL |
| Fully non-bypassable AI infrastructure | No |
| We secured Python | No |
| Trusted execution infrastructure | No until TM-A full PASS + documented residual |
| Rust makes it secure | No — Rust is optional host hardening later |

---

## Roadmap (frozen order)

```text
1. Freeze Hosted Plane (TM-H)                    ← done
2. Formalize TM-H / TM-A + claim slices          ← this file
3. Close AgentCreatedProcess (lifecycle-aware)   ← next — see SUBPROCESS_BOUNDARY.md
4. Only then: Host native TCB (maybe Rust)
```
