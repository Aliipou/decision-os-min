# Composition note — three *authority* axes, not the legitimacy floor

This note is **only** how a named call, a live PEP, and a signed receipt
compose. It does not replace the Theory of Freedom, FDK, or the rule
*empty legitimate set → DEFER, never lesser-evil ALLOW*. Ethics stay
injected. Cedar/OPA stay replaceable PDPs. They do not mint.

Joint-authorship **of this note only**. No shared ownership of mint, bind,
spend, or refuse. Not a merge and not a standard.

Named with [giskard09](https://github.com/giskard09) (`action_ref`) and
[babyblueviper1](https://github.com/babyblueviper1) (`execution_binding:
external`).

## Sequence

| Step | Axis | What it answers | Where the guarantee **stops** |
|---|---|---|---|
| 0 | Legitimacy (FDK, injected) | May this effect happen at all? | DENY-only on each candidate. Empty **set** still DEFERs to a human. Not this note. |
| 1 | Schema / action-ref marker | Which exact call was **named** | Does not authorize running. Does not prove the effect occurred. Does not answer legitimacy. |
| 2 | Live PEP ([decision-os-min](https://github.com/Aliipou/decision-os-min)) | Will this effect run without a signed, unspent, action-bound grant? | Does not prove legitimacy. Grant-alone does not reconstruct the full preimage. TM-A full is PARTIAL. |
| 3 | Signed receipt / ledger | Was the verdict **published**, including misses? | A valid proof that a verdict was issued is not proof the effect ran. `execution_binding: external` is the honest disclosure. |

A reader who collapses 1–3 into one object will over-read every signature.
A reader who uses 1–3 to skip step 0 has left the subject.

## `action_fingerprint` vs recompute-from-cited-fields

At the PEP we **recompute** `action_fingerprint` from the live action
(`actor`, `capability`, `action_purpose`, `data_labels`, `action_ref`/`nonce`,
`payload`) and refuse if it does not match `decision.action_binding`. That is
not compare-only of two hashes the caller handed us.

The signed grant currently carries the **hash** (`action_binding`) and
`action_ref`, not the full cited preimage. A third party holding **only** the
grant cannot reconstruct the fingerprint. Their artifacts are stricter for
grant-only audit. This repo does **not** claim that property today. Embedding
a full preimage would be composition/audit, not a new mint path.

## Interop test (this tree, no fork of theirs)

A foreign proof is an **input** to a refuse-check. It cannot mint a grant and
it cannot override a legitimacy DENY. Refuse if:

- the cited preimage does not recompute to `decision_ref`, or
- `artifact_hash` does not match the effect being minted
  (`action_fingerprint` of the live action).

A passing check proves the proof is self-consistent with that effect. It does
**not** prove the effect ran, and it does **not** make the effect legitimate.
Tests are local fixtures (no live `/verify-proof` in CI).

See `decision_os_min/interop_receipt.py` and
`tests/test_interop_receipt.py`.
