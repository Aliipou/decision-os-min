# Design principles

> Reference core: [`decision_os_min/`](../decision_os_min). See also
> [WHY.md](WHY.md) · [ARCHITECTURE.md](ARCHITECTURE.md) ·
> [THREAT_MODEL.md](THREAT_MODEL.md) · [TRUST_MODEL.md](TRUST_MODEL.md) ·
> [README](../README.md)

These are the principles the code actually embodies — each is pointed at the
place it is enforced, not aspirational.

## 1. Single authority

There is exactly one signer. The kernel alone holds the Ed25519 private key
([`Kernel._key`](../decision_os_min/kernel.py)), and nothing is honored unless it
carries `issued_by == KERNEL_IDENTITY` *and* a valid kernel signature
([`verify`](../decision_os_min/kernel.py)). Authority is possession of the key,
not a claim in a request. See [TRUST_MODEL.md](TRUST_MODEL.md).

## 2. Deterministic decision engine — no ML in the decision path

[`Kernel._evaluate`](../decision_os_min/kernel.py) is pure, ordered policy
evaluation: capability/tool agreement, capability grant, purpose binding,
containment, redaction. The same `(policy, action, advice)` always yields the
same verdict. Any machine learning or heuristics live *outside* the decision
path, in an optional advisor whose output is only an input to the deterministic
kernel — never the decision itself.

## 3. Separation of authority, execution, and audit

Three responsibilities, three components:

- **Authority** decides and signs — [`kernel.py`](../decision_os_min/kernel.py).
- **Execution** enforces and runs the effect — [`execute.py`](../decision_os_min/execute.py).
- **Audit** records — [`audit.py`](../decision_os_min/audit.py).

The executor holds only the *public* key and cannot make policy; the kernel takes
no side effects; the log is written by neither's decision logic. Separating them
means no single component both authorizes and executes without an independent
record.

## 4. Advice is not authority

An advisor is an optional `(action) -> threat_class | None` plugin
([`advisors.py`](../decision_os_min/advisors.py)). The kernel *consults* it, then
decides. Structurally, advice can only **tighten** — a threat class maps to
CONTAIN only for otherwise-permitted actions, and a hard DENY dominates
containment ([`Kernel._evaluate`](../decision_os_min/kernel.py), `PERMITTING`
set). An advisor can never loosen a DENY and never mints a token.
*Test:* `test_advisor_plugin_can_only_tighten`,
`test_advisory_never_loosens_a_deny`.

## 5. Fail-closed

The system refuses by default:

- Policy `default: "deny"` denies unknown data purposes
  ([`Kernel._evaluate`](../decision_os_min/kernel.py)).
- Non-permitting verdicts mint no token; no valid token ⇒ no execution
  ([`Executor.execute`](../decision_os_min/execute.py)).
- Any failed check — bad signature, binding mismatch, expired/spent/malformed
  token, unregistered tool, or a CONTAIN tool not on the allowlist — raises
  `ExecutionRefused` rather than proceeding.
- The default containment allowlist is empty (`_CONTAINMENT["allowed_tools"] =
  []`), so CONTAIN blocks unless policy explicitly widens it.

The safe path is the path of least resistance; the effect happens only when
*every* gate is satisfied.

## 6. One source of truth

There is one audit log ([`HashLog`](../decision_os_min/audit.py)) — no dual
notary, no second ledger to reconcile. And the decision *shapes* have one
definition: the `TypedDict`s in [`contracts.py`](../decision_os_min/contracts.py)
are the formal contract for every boundary message. One log, one contract, one
answer to "what was authorized."

## 7. Minimalism (and the no-fork rule)

This is the **reference core** — the distilled subset that carries the security
invariants, in ~400 lines with stdlib + `cryptography` only. It deliberately cuts
the control-plane repo, the notary, the advisory-research repo, and the schema
package (see [README](../README.md#what-was-deliberately-cut-and-why-its-fine)).

The critical governance rule: the full multi-repo Decision OS **extends the same
decision logic — it must not fork it.** Decision semantics are stabilized *here
first*, then the enterprise/research track adds capability (distribution,
integration, notary, formal proofs) *around* the same behavior. The two versions
must never diverge in what a given `(policy, action)` decides. Keeping this core
small is what makes that single-source-of-truth rule enforceable.
