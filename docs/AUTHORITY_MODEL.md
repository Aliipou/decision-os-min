# Authority model — policy decision vs executable authority

This is the formal answer to the sharpest critique of the Decision OS: *"the
boundary between deciding and executing is ambiguous. `decision-os-min` now
separates two kinds of trust:

- A selected **Authority PDP** (built-in, Cedar, or OPA) is trusted to produce a
  policy verdict. If compromised, it can grant policy authorization.
- The **kernel is the sole execution authority**: only it can canonicalize that
  verdict into a signed, action-bound executable decision and mint a one-time
  token.

That distinction permits standard policy ecosystems without creating a second
signer/minter or a second path to effects.

## The authority graph

| Component | May emit policy verdict? | May sign/mint executable authority? | May execute effect? | Holds signing key? |
|---|:--:|:--:|:--:|:--:|
| **Admission Gate** | reject entry only | ❌ | ❌ | ❌ |
| **Legitimacy PDP** | DENY-only | ❌ | ❌ | ❌ |
| **Authority PDP** (built-in/Cedar/OPA) | ✅ trusted grant/deny | ❌ | ❌ | ❌ |
| **Kernel** | canonical composition | ✅ **sole component** | ❌ | ✅ |
| **PEP** | ❌ | ❌ | ✅ only with signed decision + unspent token | ❌ |
| **Audit log** | ❌ | ❌ | ❌ | ❌ |

Canonical pipeline (two *distinct* gate names — never "AuthGate" twice):

```text
Agent → Admission → Legitimacy(DENY-only) ─┐
                    Authority PDP ──────────┴→ Kernel sign/mint → PEP → Effect → Audit
```

There is one row with a ✅ in the **sign/mint** column. PDP replacement changes
policy semantics, not the execution chokepoint.

## Why a trusted PDP is not a second minting authority

Cedar/OPA can return ALLOW, but their adapters receive only an action copy and
return a bounded canonical result. Returned `signature`, `token_id`,
`action_binding`, payload, containment, or adapter fields are stripped. The
kernel applies host-owned LIMIT/CONTAIN behavior, composes legitimacy, then
creates the only signature/token. A PDP call alone cannot reach a tool.

## Security invariants (formal, each with its proof)

Let `K` = kernel signing key (exists only in the kernel process). Let a *verdict*
be one of ALLOW/DENY/LIMIT/CONTAIN/DEFER.

- **INV-1 — Single source of executable authority.** An effect runs only if it is
  authorized by a decision signed under `K`. No PDP can manufacture that
  signature. *Proof:* `test_forged_decision_refused`, `test_tampering_signed_token_id_breaks_signature`.
- **INV-2 — Mandatory mediation.** No tool executes without a valid decision *and*
  an unspent capability token. *Proof:* `test_deny_blocks`, and the executor's
  verify-then-spend path in `execute.py`.
- **INV-3 — One-time authorization.** Each decision's capability is consumable
  exactly once; replay is refused. *Proof:* `test_replayed_token_refused`.
- **INV-4 — Effect is bound to the decision.** Every side effect is bound, before
  execution, to a signature over the *security-relevant content of that action*; a
  decision cannot be re-attached to a different action. *Proof:*
  `test_confused_deputy_refused` (+ `action_fingerprint` in `kernel.py`).
- **INV-5 — Advice is not authority.** An ordinary advisor may only make a verdict *more*
  restrictive; it can never author a verdict or loosen a DENY. *Proof:*
  `test_advisory_never_loosens_a_deny`, `test_advisor_plugin_can_only_tighten`.
- **INV-6 — Pipeline order.** Hard-deny gates (capability, purpose) are evaluated
  **before** advisory-driven containment, so an unauthorized action is denied
  outright rather than sandbox-run — advice cannot upgrade a DENY into a CONTAIN.
  *Proof:* the ordering in `kernel._evaluate` and
  `test_advisory_never_loosens_a_deny`.

The Python reference enforces these with runtime checks. Cedar/OPA become part
of the policy trust base when selected, while the Host/kernel/PEP remain the
execution TCB. This repository does not contain an in-repo Rust binding.

## What this does NOT prove

The authority model is sound *given* the threat model. It says nothing about
whether the model is **useful** — that only real deployment, independent use, and
an empirical comparison against OPA/Cedar can establish. The remaining risk is not
the authority design; it is proving the design earns its place. That is validation
work, not more design.
