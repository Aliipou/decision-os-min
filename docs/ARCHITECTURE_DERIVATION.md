# Architecture Derivation — From Invariant to Minimum Mechanism

**Date:** 2026-08-23  
**Mode:** Analysis only (no implementation in this document)  
**Rule:** Treat SealedRuntime / Host / Rust as *hypotheses*, not answers.

---

## Research question (restated)

> What is the **minimum architectural mechanism** that makes consequential
> execution impossible unless it passes legitimacy ∧ authority ∧ enforcement?

Formal target:

```text
∀ consequential effect e:
  Executed(e) ⇒ Admission(e) ∧ Legitimacy(e) ∧ Authority(e) ∧ Enforcement(e)

¬Governed(e) ⇒ ¬Executed(e)
```

**Critical clarification:** “consequential effect” must be scoped by threat model.
Without a scope, the universal claim is not achievable on a general-purpose OS.

---

# Phase 1 — Attack the problem (trust model)

### 1. What is trusted today?

| Component | Evidence | Trust class |
|---|---|---|
| `SealedRuntime` / PEP / admission / M5 binding | `sealed.py`, destructor PASS on sealed surface | **PARTIALLY TRUSTED** (trusted *if* caller only uses `invoke`) |
| FDK axioms / inference | `freedom-decision-kernel` | **OUTSIDE TCB as morality**; **PARTIALLY TRUSTED** as reference semantics |
| AuthGate / decision kernel authority | `kernel.py`, AuthGate Rust TCB in `freedom-kernel-work` | Authority: **PARTIALLY TRUSTED** in Python; Rust path claims TRUSTED |
| AgentHost (Python) | `host.py` | **PARTIALLY TRUSTED** host for *registered* effects |
| Agent / LLM / orchestration | apps, subprocess probe | **UNTRUSTED** |
| Ambient Python/OS (`open`, `socket`, `subprocess`, `getattr`) | destructor / probe: ambient WRITE succeeds | **UNTRUSTED capability plane** |
| OS kernel | platform | **TRUSTED** (external) |

### 2. What is untrusted?

The agent, any code sharing its memory, any retained tool handle, any ambient OS API available to that process, and any caller that can skip `invoke`/`AgentHost`.

### 3. Where can consequential effects originate?

1. **Governed adapters** registered into `seal()` / AgentHost — mediated.  
2. **Ambient OS APIs** in the same process — *not* mediated.  
3. **Introspection** (`object.__getattribute__(cell, "_fn")`) — recovers body; still in-process.  
4. **Unsealed `DecisionOS.handle` / `Governor`** — mediation optional.  
5. **Credentials/network already held by the process** — effect without your adapters.

### 4. What is the actual effect boundary?

Not FDK. Not AuthGate. Not even PEP in the library sense.

The real boundary is:

```text
whatever can cause I/O / mutation / external action
```

In current deployable form that is:

- Python callables (adapters), and  
- OS syscalls available to the process.

Library governance sits *above* that boundary unless the OS/process denies ambient effects.

### 5. Can Python be part of the trusted boundary?

**Yes, as a host language**, if and only if:

- the *untrusted agent cannot share that process*, or  
- the process has **no ambient effect capabilities** relevant to the threat model.

**No**, if untrusted agent and enforcement co-reside with full CPython + OS APIs.  
Repo evidence: `freedom-kernel-work/README.md` — “Python as the security boundary … **bypassable**”.  
Repo evidence: `docs/BYPASS_INVARIANTS.md` — ambient Python **FAIL**.

### 6. Can untrusted agent and enforcement safely coexist in one process?

**No**, for the universal invariant.

Same address space ⇒ reflection, import, ctypes, raw sockets. Object sealing cannot remove OS ambient authority. Destructor residual: `getattr(_fn)` still executes.

### 7. Is object sealing sufficient?

**Sufficient for:** sealed-surface invariant (tools that entered `seal()`).  
**Insufficient for:** `¬Governed ⇒ ¬Executed` over all consequential effects.  
Evidence: sealed PASS + ambient FAIL (`BYPASS_INVARIANTS.md`).

### 8. Is process isolation sufficient?

**Sufficient for host-registered effects** if adapters live only in the host and agent has Intent-IPC only (`HOSTED_AGENT_PLANE.md` h2/h4 PASS).

**Insufficient alone** for ambient OS effects *inside the agent process* (h3: filesystem often `WROTE` without jail).

### 9. Is OS isolation required?

**Required** iff the threat model includes “agent must not create *any* consequential side effect by itself.”

**Not required** iff the threat model is narrowed to: “agent must not trigger *host-registered product effects* except via governance.”

### 10. Is a kernel/TCB (e.g. Rust) required?

**Not required to close the ambient-bypass class.** That class is closed by **removing effect capability from the agent’s trust domain** (process + OS), not by rewriting FDK in Rust.

Rust/TCB becomes valuable when you need: memory safety of the *host*, smaller TCB, formal proofs, crypto hygiene — **hardening of the trusted plane**, not the *minimum* fix for co-process bypass.

### 11. What does “non-bypassable” mean?

Must pick a threat model:

| Threat model TM | Meaningful “non-bypassable”? |
|---|---|
| **TM-S:** Adversary limited to sealed/hosted APIs | Yes — already largely PASS |
| **TM-H:** Adversary is untrusted process w/o product credentials; host holds effects | Yes iff adapters-only-on-host + no creds in agent |
| **TM-A:** Adversary has full user-process OS rights | Only with OS sandbox / capability OS; else **impossible** as absolute claim |
| **TM-K:** Adversary compromises host/OS | Out of scope without hardware/TEE |

**Verdict (Phase 1):**  
Under **TM-A** (same process / full OS), the original absolute claim is **not meaningfully achievable**.  
Under **TM-H**, it **is** achievable. Under **TM-S**, SealedRuntime already approximates it.

---

# Phase 2 — Candidate architectures

| ID | Pattern | One line |
|---|---|---|
| A | Library | Agent calls FDK/AuthGate/PEP voluntarily |
| B | SealedRuntime | In-process; only sealed tools mediated |
| C | Hosted process | Agent IPC → host governance → effects |
| D | Sandboxed agent | C + OS denies ambient effects in agent |
| E | Systems TCB (e.g. Rust host) | Trusted plane memory-safe / minimal TCB |
| F | Capability OS | Kernel refuses effect without capability |

---

# Phase 3 — Comparison (repo-informed)

Scores: 0 fail / 1 weak / 2 adequate / 3 strong for the *universal* invariant.  
Practicality scored for *shipping this repo*.

| Property | A Lib | B Seal | C Host | D Sandbox | E TCB | F Cap-OS |
|---|---:|---:|---:|---:|---:|---:|
| Agent isolation | 0 | 0 | 2 | 3 | 2–3 | 3 |
| Non-bypassability (TM-A) | 0 | 0 | 1 | 3 | 2 | 3 |
| Non-bypassability (TM-H) | 0 | 1 | 3 | 3 | 3 | 3 |
| Memory safety of enforcement | 1 | 1 | 1 | 1 | 3 | 2 |
| Effect isolation (product adapters) | 0 | 2 | 3 | 3 | 3 | 3 |
| Performance | 3 | 3 | 2 | 1–2 | 2 | 2 |
| Deployment complexity | 3 | 3 | 2 | 1 | 1 | 0 |
| Auditability | 2 | 3 | 3 | 3 | 3 | 2 |
| Formal verification readiness | 1 | 1 | 1 | 1 | 3 | 2 |
| Portability | 3 | 3 | 3 | 1–2 | 2 | 0–1 |
| Minimal TCB | 3 | 2 | 2 | 2 | 3* | 2 |
| Practicality *here* | 3 | 3 | 3 | 2 | 2 | 0 |
| Research novelty (governance split) | 2 | 2 | 2 | 2 | 1 | 1 |

\*TCB is “minimal” only if you refuse to put FDK philosophy / LLM / apps inside it.

**Repo anchors:** B proven PASS/FAIL split; C partially shipped (`host.py`); E foreshadowed by AuthGate Rust TCB; F not present.

---

# Phase 4 — Minimum sufficient architecture

### Bypass class that actually bites

```text
Ambient effect capability in the untrusted trust domain
```

Not: “missing axiom #8”.  
Not: “FDK not in Rust”.  
Not: “need more sealing macros”.

### Minimum mechanism that closes it (by claim scope)

**If claim = TM-H (host-registered / product effects):**

```text
MINIMUM = C (Hosted process)
  + effect adapters only on host
  + no product credentials in agent
  + mandatory Admission∧FDK∧AuthGate∧PEP on host
```

SealedRuntime is the **in-host** enforcement surface; Host is the **trust-domain** move.  
Rust is **optional hardening**, not minimum.

**If claim = TM-A (no consequential self-effect by agent):**

```text
MINIMUM = C + D
  (hosted plane AND OS sandbox / no ambient effect rights)
```

Without D, DirectEffect(Agent)≠∅ (probe evidence).

**If claim = compromise-resistant host (TM-K lite):**

```text
C + D + E (minimal Rust/native TCB for admission, binding, PEP, spent-store)
```

Still not “everything in Rust.” FDK *reference semantics* can stay Python; enforcement path in TCB must match differentially.

### Explicit non-conclusions

- **Proposed “everything important in Rust” is not forced by the bypass class.**  
- **More axioms do not help.**  
- **Absolute non-bypassability on a general OS without sandbox is not achievable.**

---

# Phase 5 — Challenge each design (concrete attacks)

| Arch | Attack that works | Why |
|---|---|---|
| A Library | Call tool / `open()` / HTTP directly | Governance optional |
| B Sealed | `open()`; `getattr(cell,"_fn")`; never-sealed callable | Co-process ambient + reflection |
| C Host only | In agent: `socket.connect`, `open`, `subprocess` | Host doesn’t mediate agent’s OS |
| C Host | Steal host credentials if misplaced in agent env | Deployment error |
| D Sandbox | Escape / misconfigured allowlist; kernel bugs | Residual OS risk — document |
| E TCB alone (no domain split) | If agent still in TCB process with OS rights | Wrong placement |
| F Cap-OS | Not available here; wrong stack | Impractical for this project now |

**Confused deputy / replay / ticket forgery / binding:** already largely closed *on sealed/hosted governed path* by existing destructors — do not confuse that success with TM-A.

---

# Phase 6 — Derived architecture (recommendation)

## 1. Recommended architecture (hybrid, minimum-sufficient)

```text
                    ┌─── TM-A boundary (OS) ───┐
UNTRUSTED AGENT     │  no product creds        │
  (LLM, planners)   │  no adapters             │
        │ Intent    │  restricted FS/net/exec  │
        ▼           └──────────────────────────┘
   IPC only
        ▼
TRUSTED HOST PROCESS (may be Python today; Rust later for TCB shrink)
        │
        ├ Admission (signed, spent)
        ├ Legitimacy (FDK semantics — reference may stay Python)
        ├ Authority (AuthGate)
        ├ PEP + decision binding (M5)
        ├ Audit
        └ Effect adapters ONLY HERE
                ▼
         External world
```

**Name the claim correctly:**

> **Hosted agent enforcement plane**  
> (with OS isolation as the upgrade path from PARTIAL → stronger TM-A)

Not: “trusted execution infrastructure” until OS isolation + (optional) native TCB evidence exists.  
Not: “sealed enforcement surface” alone as the product claim — that is an *inner* mechanism.

## 2. Why sufficient

| Bypass class | Closed by |
|---|---|
| Skip FDK on product tools | Host mandatory chain |
| Tool handle in agent | No adapters in agent |
| Sealed co-process reflection | Separate process (C) |
| Ambient OS in agent (TM-A) | Sandbox (D) |
| Verdict/action swap | Existing M5 + PEP binding |
| Replay tickets/tokens | Spent-store |

## 3. Why simpler fails

- **A/B:** ambient + optional mediation (repo FAIL).  
- **C alone:** ambient in agent (h3 PARTIAL).  
- **E without C:** rewriting language doesn’t remove co-process OS.  
- **F:** not the near-term stack.

## 4. What must move across the trust boundary

| Move into trusted host | Keep out of TCB |
|---|---|
| Effect adapters, credentials, spent-store, PEP arming, admission verify, authority mint, legitimacy *enforcement call* | LLM, planners, UI, research compass, axiom *philosophy*, most SDKs |
| Later (optional E): crypto verify, spent-store, PEP chokepoint in Rust | Full FDK ontology UX, Python reference FDK for differential tests |

## 5. Minimal TCB (if/when native)

Inside TCB: admission verify, legitimacy verdict *check* (or verified digest), authority decision, binding, PEP, spent-store, adapter dispatch gate.  
Outside: Python FDK as **reference semantics**, agents, apps.

## 6. Repo changes (when implementing — not now)

| Change | Why |
|---|---|
| Treat `host.py` + OS sandbox as the product boundary | Closes domain split |
| Keep `sealed.py` as in-host mechanism | Already works |
| Do **not** expand axioms | Wrong problem |
| Optional: thin Rust host chokepoint | Hardening, not minimum |
| Differential FDK tests if Rust legitimacy lands | Preserve semantics |
| Expand h3 until DirectEffect probes are BLOCKED | Evidence for TM-A |

## 7. What must NOT change

- Legitimacy ⊥ Authority  
- Frozen A1–A7 research semantics / FREEZE discipline  
- Veto-only legitimacy  
- Claim discipline in `POSITIONING` / `HOSTED_AGENT_PLANE`

## 8. Machine-testable invariants

```text
I1  HostEffect ⇒ Admission ∧ Legitimacy ∧ Authority ∧ PEP     (TM-H)
I2  Agent process has no adapter callables / no product secrets
I3  Agent ambient DirectEffect ∈ {∅} under declared sandbox     (TM-A)
I4  FDK_ref(input) = FDK_enforce(input) when dual impl exists
I5  Legitimacy DENY ⇒ no host effect
I6  Binding(action, legitimacy, authority) intact or refuse
```

## 9. Required adversarial tests

Already: sealed destructors, NovaPulse, hosted h1–h4.  
Still required for architecture proof:

- Agent ambient: open/socket/subprocess/ctypes → must BLOCK under D  
- Agent cannot import host adapters  
- Malformed/replayed IPC  
- Host credential absence in agent env  
- Sandbox escape attempts (document residual)

---

# Phase 7 — Implementation stance (deferred)

Per instruction: **do not implement in this step.**

When implementing, order by evidence gap:

1. Harden **claim text** to TM-H (already largely done).  
2. Add **OS isolation** until I3 is empirically PASS (closes real remaining hole).  
3. Only then consider **Rust minimum TCB** for host chokepoint (E) — optional.  
4. Never start from “rewrite FDK in Rust” as the first move.

---

# Final answers to the mandated questions

### Research

Can legitimacy/authority separation survive a real boundary?  
**Yes** — keep FDK vs AuthGate; move *effect ownership* across the boundary, not the philosophy.

### Engineering

Can an untrusted agent produce a consequential *host* effect without the chain?  
**No** on current hosted path (evidence PASS).  
Can it produce *some* consequential OS effect without the chain?  
**Yes**, without sandbox (evidence PARTIAL/FAIL).

### Security (remaining attacks)

Sandbox escape; host compromise; stolen host credentials; supply-chain in host; TOCTOU in adapters; anything TM-K.

### Infrastructure claim (strongest supported)

```text
hosted agent enforcement plane          ✅ (TM-H) — supported
+ OS-isolated untrusted agent           ⚠ PARTIAL — not yet evidenced as PASS
sealed enforcement surface              ✅ inner mechanism, not the product claim
trusted execution infrastructure        ❌ not yet — needs D (+ optional E) evidence
```

### Bottom line (correct answer, not confirmation)

```text
Current in-process sealed architecture CANNOT satisfy the universal
¬Governed ⇒ ¬Executed claim under TM-A.

The minimum sufficient fix is NOT “more Rust” and NOT “more axioms”.
It is: separate trust domains (hosted effects) + OS isolation of the agent
for ambient effects.

Rust TCB is an optional hardening of the trusted host, not the minimum
mechanism that closes the bypass class that actually broke the claim.
```
