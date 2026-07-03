# Threat model

> Reference core: [`decision_os_min/`](../decision_os_min). See also
> [WHY.md](WHY.md) · [ARCHITECTURE.md](ARCHITECTURE.md) ·
> [TRUST_MODEL.md](TRUST_MODEL.md) · [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) ·
> [README](../README.md)

This document states what `decision-os-min` defends and what it does not.
Claims are conservative and grounded in the code; each counter-measure has a
corresponding regression test in [`tests/test_core.py`](../tests/test_core.py).

## Assets

- **Authorization integrity** — an effect must run only when the kernel
  authorized *that specific action*.
- **The one-time credential** — a capability token must authorize one effect,
  once.
- **The audit record** — a truthful, tamper-evident account of every decision.
- **The signing key** — the Ed25519 private key that is the root of all
  authority. Held only by the kernel.

## Attacker model

We assume an attacker who can:

- **Sit on the transport** between kernel, executor, and caller as a
  man-in-the-middle: read and **mutate the result dict** (`decision`,
  `signature`, `token`) in flight.
- **Call the API as any actor** — submit arbitrary actions with any `actor`,
  `capability`, `purpose`, `labels`, or `payload`.
- **Hold insider file access to the audit log** — read, edit, insert, delete,
  or reorder lines in the `audit.jsonl` file on disk.

We assume the attacker **does *not***:

- Possess the kernel's Ed25519 private key.
- Have code execution *inside the kernel process* (see residual risks).

## Threats and how the design counters them

### 1. Forged or altered decision

**Threat.** The attacker fabricates a decision, or flips a DENY to ALLOW / edits
a field in a legitimate one.

**Counter.** [`Executor.execute`](../decision_os_min/execute.py) calls
[`verify`](../decision_os_min/kernel.py), which requires `issued_by ==
KERNEL_IDENTITY` *and* a valid Ed25519 signature over the canonical bytes of the
decision. Without the private key the attacker cannot produce a valid signature;
any mutated field changes the canonical bytes and fails verification →
`ExecutionRefused("decision not authenticated by the kernel")`.
*Test:* `test_forged_decision_refused`.

### 2. Confused deputy / re-attaching a token to another action

**Threat.** The attacker takes a legitimate ALLOW + token issued for a benign
action and presents it alongside a *different*, more dangerous action (e.g.
swap the payload to exfiltrate).

**Counter.** The decision and the token both carry
`action_binding = action_fingerprint(action)` — a sha256 over `actor`,
`capability`, `action_purpose`, sorted `data_labels`, and `payload`. Before
executing, the executor recomputes `action_fingerprint(action)` for the action
actually presented and refuses on mismatch → `ExecutionRefused("... binding
mismatch")`. A signed authorization is welded to one action's content.
*Test:* `test_confused_deputy_refused`.

### 3. Replay

**Threat.** The attacker resubmits a valid decision + token to run the effect a
second time.

**Counter.** Each token has a unique `token_id`. The executor keeps a `_spent`
set; the first execution marks the token spent, and any re-use raises
`ExecutionRefused("token already spent (replay)")`. Tokens also carry a 30-second
`expires_at` that the executor enforces. No token, or a non-permitting verdict,
means no execution at all.
*Tests:* `test_replayed_token_refused`, and no-token paths in `test_deny_blocks`.

### 4. Audit tampering

**Threat.** The insider edits, inserts, deletes, or reorders entries in the log
to hide or fabricate a decision.

**Counter.** [`HashLog`](../decision_os_min/audit.py) is append-only and
hash-chained: each entry's `entry_hash` covers its contents plus the previous
entry's hash (`prev_hash`), and `seq` is monotonic. `verify()` walks the chain
and returns `False` if any `seq`, `prev_hash`, or recomputed `entry_hash` is
inconsistent — so any retroactive change is *detectable*. The record is written
**before** the side effect, so a crash cannot erase an authorization.
*Test:* `test_audit_tamper_detected`.

> Detectability, not prevention. The hash chain makes tampering *evident* to
> anyone who runs `verify()`; it does not stop an insider from truncating the
> file. External anchoring / notary is out of scope here (it lives in the full
> system).

### 5. Privilege / policy evasion at decision time

**Threat.** The attacker submits an action for a capability it was not granted,
mismatches capability and tool, or uses a purpose that does not match the data
label.

**Counter.** [`Kernel._evaluate`](../decision_os_min/kernel.py) enforces, in
order: capability/tool agreement, capability grant, and purpose binding, with a
configurable default-deny for unknown labels. A hard DENY here **dominates**
containment — advisory input can never loosen it.
*Tests:* `test_deny_blocks`, `test_ambiguous_capability_tool_denied`,
`test_advisory_never_loosens_a_deny`.

### 6. Advisor as a false authority

**Threat.** A compromised or hostile advisor tries to authorize an action.

**Counter.** An advisor only returns a `threat_class`; the kernel maps that to
CONTAIN or ignores it, and it can only *tighten* an otherwise-permitted verdict.
It cannot turn a DENY into anything permissive and cannot mint tokens.
*Test:* `test_advisor_plugin_can_only_tighten`. See
[TRUST_MODEL.md](TRUST_MODEL.md).

## Residual risks / out of scope

Stated plainly — these are *not* defended by this core:

- **Kernel process compromise.** The signing key lives in the kernel process
  (`Kernel._key`). Code execution inside that process reads the key and can sign
  anything. The whole model rests on the kernel process being trustworthy; there
  is no HSM, key isolation, or attestation here.
- **Network / TLS / key management.** No transport security, key distribution,
  rotation, or storage is provided. The public key is handed to the executor
  in-process (`DecisionOS.__init__`); securing that channel in a distributed
  deployment is out of scope.
- **Load, scale, concurrency.** The `_spent` set is in-memory and per-executor
  instance; there is no shared spend-store, so replay protection does not span
  multiple executor processes. Audit writes are single-file appends with no
  concurrency control. This is a single-process reference core.
- **Formal proofs.** Correctness is demonstrated by tests, not by machine-checked
  proof. There is no TLA+/Kani/Lean artifact in this repo.
- **Denial of service and side channels.** Not modeled.
- **Notary / external trust root.** The log is self-contained and
  self-verifying; there is no anchoring to an external, append-only authority.

For the distributed, notarized, and research-extended versions of these, use the
full multi-repo Decision OS, which extends the *same* decision logic (see
[README](../README.md#relationship-to-the-full-decision-os)).
