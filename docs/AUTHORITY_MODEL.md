# Authority model — who may decide, who may only advise, who may only enforce

This is the formal answer to the sharpest critique of the Decision OS: *"the
boundary between deciding and analyzing is ambiguous — is there one authority or
several?"* In `decision-os-min` the answer is unambiguous and enforced in code:
**exactly one component may produce a verdict.** Everything else advises, enforces,
or records — never decides.

## The authority graph

| Component | May DECIDE (emit a verdict)? | May EXECUTE an effect? | May WRITE audit? | Holds the signing key? |
|---|:--:|:--:|:--:|:--:|
| **Admission** (capability grants; a future AuthGate) | ❌ | ❌ | ❌ | ❌ |
| **Advisor** (FDK / ML / research) | ❌ *advice only* | ❌ | ❌ | ❌ |
| **Kernel** | ✅ **sole authority** | ❌ | ❌ | ✅ (Ed25519, kernel-only) |
| **Executor / PEP** | ❌ | ✅ *only vs a signed decision + unspent token* | ❌ | ❌ (verify only) |
| **Audit log** | ❌ | ❌ | append-only | ❌ |

There is **one** row with a ✅ in the "DECIDE" column. That is the whole safety
argument.

## "Why does AuthGate appear twice?" — it doesn't decide twice

In the full pipeline `AuthGate` shows up at two points, and this is the naming
confusion worth killing:

- **Admission** (front): *"may this principal enter the system at all?"* — identity
  / authentication. It can only **reject entry**; it cannot allow an action.
- **PEP** (back): *"enforce the kernel's already-signed decision before the side
  effect."* — it can only **refuse or carry out** what the kernel decided.

**Neither is an authority.** One gate guards the door, the other guards the effect;
the *decision* between them belongs solely to the kernel. Calling both "AuthGate"
invites the "dual decision layer" misreading — so in `decision-os-min` they are
named distinctly (admission = capability grants in the policy; enforcement =
`Executor`), and only the `Kernel` decides.

## Security invariants (formal, each with its proof)

Let `K` = kernel signing key (exists only in the kernel process). Let a *verdict*
be one of ALLOW/DENY/LIMIT/CONTAIN/DEFER.

- **INV-1 — Single source of authority.** An effect runs only if it is authorized
  by a decision signed under `K`. No non-kernel component can manufacture that
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
- **INV-5 — Advice is not authority.** An advisor may only make a verdict *more*
  restrictive; it can never author a verdict or loosen a DENY. *Proof:*
  `test_advisory_never_loosens_a_deny`, `test_advisor_plugin_can_only_tighten`.
- **INV-6 — Pipeline order.** Hard-deny gates (capability, purpose) are evaluated
  **before** advisory-driven containment, so an unauthorized action is denied
  outright rather than sandbox-run — advice cannot upgrade a DENY into a CONTAIN.
  *Proof:* the ordering in `engine._evaluate` and the property test that first
  caught the violation.

All six hold **in-process** (single interpreter, transport-attacker + insider
threat model — see `THREAT_MODEL.md`). They are enforced by runtime signature
checks, not by convention or static analysis alone.

## What this does NOT prove

The authority model is sound *given* the threat model. It says nothing about
whether the model is **useful** — that only real deployment, independent use, and
an empirical comparison against OPA/Cedar can establish. The remaining risk is not
the authority design; it is proving the design earns its place. That is validation
work, not more design.
