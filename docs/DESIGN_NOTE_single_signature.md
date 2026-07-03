# Design Note: fold the capability token into the signed decision (one signature)

**Status:** implemented in `decision-os-min`, validated (see gate below). Not yet
propagated to the enterprise `decision-kernel-core` (governance: stabilize in the
reference core first).

## Problem (measured, not guessed)

The benchmark (`BENCHMARKS.md`) showed Ed25519 sign/verify dominates the request
path, and the design paid it **twice on each side**:

- `kernel.decide()` produced **two** signatures — one over the decision, one over a
  separately-minted token (~54 µs ≈ 2× a single verify).
- `executor.execute()` performed **two** verifications — decision *and* token
  (~78 µs).

## Proposal

Mint the one-time capability grant **inside** the decision (`capability`,
`token_id`, `token_expires_at`) and sign it with the decision's single signature.
The returned `token` object becomes a **convenience view only**; the executor reads
`token_id` / `capability` / `expiry` / `action_binding` **exclusively from the
signed decision**. Result: **one sign per decide, one verify per execute.**

## The reviewer's three questions (answered with tests, not prose)

**1. Is replay still impossible?**
Yes. `token_id` is now a field of the signed decision, so it is **unique** (fresh
`uuid` per decide), **signed** (covered by the decision signature), **immutable**
(any change breaks the signature), and **one-time** (spent in the executor's
`_spent` set). Evidence: `test_replayed_token_refused` (second execute → "already
spent") and the new `test_tampering_signed_token_id_breaks_signature` (swapping in
a fresh `token_id` to dodge the spent-set → "not authenticated").

**2. Is the confused-deputy attack still closed?**
Yes. `action_binding` was previously present in *both* the token and the decision;
it now lives in the decision, which the executor already verifies and then checks
against a fresh `action_fingerprint(action)`. Evidence: `test_confused_deputy_refused`
(a valid ALLOW for a benign action cannot execute a different action → "binding
mismatch") still passes unchanged.

**3. Is anything security-relevant read from outside the signature?**
No. The executor no longer references `result["token"]` at all — the line was
removed. Every field it acts on (`verdict`, `action_binding`, `token_id`,
`capability`, `token_expires_at`, `containment`) is read from the **signed**
decision. The `token` view is purely for callers/ergonomics.

## Did the two signatures protect different trust boundaries?

**No.** Both were produced by the *same* kernel key, verified by the *same*
executor, at the *same* moment, and shared the same `action_binding`. The split was
**structural, not a trust boundary** — so collapsing it removes redundancy, not a
security domain.

## What is genuinely traded away (honest)

- **Independent token revocation / lifecycle:** the reference core has **no**
  revocation today (expiry is the only lifecycle control), so nothing *current* is
  lost. But a future "revoke a token without re-issuing the decision" feature is
  now less natural — it would want the token re-split. Documented so we don't
  rediscover it.
- **Delegation / attenuation:** not supported in either design (that is
  macaroons/Biscuit territory); no change.
- **Separation of concerns:** conceptually the "ruling" and the "bearer credential"
  are now one signed object. Acceptable for a minimal reference core; noted as the
  main philosophical cost.

## Validation gate (all green after the change)

| Check | Result |
|---|---|
| `ruff check decision_os_min/` | ✅ All checks passed |
| `mypy decision_os_min/` | ✅ no issues (6 files) |
| `pytest` (security + core) | ✅ 13 passed (replay, confused-deputy, forgery, tamper included) |
| conformance min ↔ core (verdicts) | ✅ 4 passed (verdicts unchanged) |
| integration + red-team regressions | ✅ 29 passed |
| benchmark before → after | ⚠️ **unverified** — clean re-measure required (see below) |

### Benchmark status — honest

The **baseline** (measured on an idle machine) is trustworthy: `handle` ≈ 148 µs,
`decide` ≈ 54 µs (two signs), `execute` ≈ 78 µs (two verifies), `verify` ≈ 28 µs.

The **after** measurement is **not yet trustworthy.** Repeated attempts on this
2-core laptop were contaminated by CPU/disk contention — `verify` (which this
change does *not* touch) drifted from 28 µs to 150–300 µs across runs, and `handle`
blew up to 12–26 ms (Windows Defender scanning the rapid temp audit-file writes).
When an *unchanged* operation regresses 5–10×, the whole run is invalid, so no
after-number is reported rather than a fabricated one.

**Predicted** improvement (arithmetic, not measured): removing one sign from
`decide` (~27 µs) and one verify from `execute` (~27 µs) should take the end-to-end
`handle` path from ~148 µs to **~95 µs (~35% faster)**. This is a hypothesis to be
**confirmed by a clean single-process run on an idle machine** before any speedup is
claimed. The optimization ships on its *correctness* evidence (all tests green); the
*performance* claim is explicitly pending clean measurement.

## Decision

Accept for `decision-os-min`: it preserves every current security invariant (proven
by the unchanged, still-green attack tests), simplifies the code, and removes one
sign + one verify from the hot path. The enterprise `decision-kernel-core` keeps
the two-signature form for now; if a future need for independent token lifecycle
does **not** materialize, it should adopt the same single-signature model so the
two tracks stay behaviorally aligned.
