# Threat Models — Formal Split (Frozen)

**Status:** Locked 2026-08-23  
**Source of truth for claims:** this file + `HOSTED_AGENT_PLANE.md` + `ARCHITECTURE_DERIVATION.md`

Do **not** mix TM-H and TM-A in outreach or CI badges.

---

## TM-H — Host-registered product effects

**Adversary:** Untrusted agent that may be malicious, but product effects (tools,
adapters, credentials for the product) live only in the Host.

**Invariant:**

```text
∀ host-registered effect e:
  Executed(e) ⇒ Admission ∧ Legitimacy ∧ Authority ∧ PEP
```

**In scope:** deploy_ranking, audit_export, DB/HTTP adapters owned by Host, etc.  
**Out of scope:** whether the agent can `open()` a scratch file in its own FS.

**Evidence today:** PASS — `tests/test_hosted_agent_plane.py`, SealedRuntime destructors.

**Claim language:**

> Hosted enforcement plane for host-registered effects.

---

## TM-A — Agent must not create consequential direct effects

**Adversary:** Untrusted agent process with whatever ambient OS rights the
deployment left it.

**Invariant:**

```text
DirectEffect(Agent) = ∅
```

under the **declared** sandbox profile (filesystem write, arbitrary network,
subprocess/exec, access to product credentials / host adapters).

**In scope:** `open`/`write`, `socket.connect`, `subprocess`, env secrets, importing
host adapters.  
**Out of scope:** compromising the Host or the OS kernel (TM-K).

**Evidence today:**
- Without sandbox: FAIL — ambient probes succeed (`tm_a_probe.py` control).
- With `agent-noambient-v1` (Docker): **FS write + network** MUST be BLOCKED; credentials ABSENT.
- **Residual gap (real):** `subprocess`/`execve` of image binaries often still **RAN** — blocking `execve` in seccomp also prevents container start. Not a v1 PASS gate; next harden (gVisor / nested jail), not more Python sealing.

**Claim language (only after suite PASS on declared platform):**

> OS-isolated untrusted agent under profile `agent-noambient-v1`.

---

## What we will not claim

| Phrase | Allowed? |
|---|---|
| Fully non-bypassable AI infrastructure | No |
| We secured Python | No |
| Trusted execution infrastructure | No until TM-A PASS + documented residual |
| Rust makes it secure | No — Rust is optional host hardening later |

---

## Roadmap (frozen order)

```text
1. Freeze Hosted Plane (TM-H)     ← done
2. Formalize TM-H / TM-A          ← this file
3. Break TM-A with real attacks, then harden sandbox until they FAIL
4. Only then: which Host pieces need a smaller native TCB (maybe Rust)
```

**Next engineering step is TM-A sandbox experiments — not a Rust rewrite.**
