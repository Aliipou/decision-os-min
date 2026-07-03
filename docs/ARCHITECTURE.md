# Architecture

> Reference core: [`decision_os_min/`](../decision_os_min). See also
> [WHY.md](WHY.md) · [THREAT_MODEL.md](THREAT_MODEL.md) ·
> [TRUST_MODEL.md](TRUST_MODEL.md) · [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) ·
> [README](../README.md)

## Components

| Component | File | Role |
|---|---|---|
| **Kernel** | [`kernel.py`](../decision_os_min/kernel.py) | The single authority. Holds the Ed25519 signing key and the policy; evaluates an action, signs a decision bound to the action's content, and mints a one-time capability token on a permitting verdict. |
| **Executor (PEP)** | [`execute.py`](../decision_os_min/execute.py) | The Policy Enforcement Point. Runs a tool effect *only* against a signed, action-bound decision and a valid, unspent token. |
| **Audit log** | [`audit.py`](../decision_os_min/audit.py) | One append-only, hash-chained log. The sole audit mechanism; `verify()` detects any tampering. |
| **Contracts** | [`contracts.py`](../decision_os_min/contracts.py) | The formal contract as `TypedDict`s — the shape of every message that crosses a boundary. |
| **Advisor** | [`advisors.py`](../decision_os_min/advisors.py) | An *optional* plugin: `(action) -> threat_class \| None`. Advice, never authority. |
| **DecisionOS** | [`__init__.py`](../decision_os_min/__init__.py) | Composes the above. `handle()` runs decide → audit → execute as one call. |

## The 3-gate flow

One action passes **three gates** against **one central policy**, all inside
[`DecisionOS.handle`](../decision_os_min/__init__.py). In the full multi-repo
system these gates are separate services; here they collapse into one call — the
same gate-passes, fewer layers.

```text
                 Action (dict, shape = contracts.Action)
                   │
                   ▼
          ┌───────────────────────────────────────────────┐
          │  DecisionOS.handle(action, tools, advisor?)    │
          └───────────────────────────────────────────────┘
                   │
                   ▼
          ┌───────────────────────────────────────────────┐
          │  GATE 1 — pre-decision  (Kernel.decide)        │
          │    advisor(action) -> threat_class (optional)  │
          │    _evaluate():                                │
          │      · capability/tool agreement               │
          │      · capability grant  (actor may do cap?)   │
          │      · purpose binding    (label ⇄ purpose)    │
          │      · containment  (threat_class -> CONTAIN)  │
          │      · redaction    (-> LIMIT)                 │
          │    sign(decision), bind action_fingerprint,    │
          │    mint one-time token if verdict PERMITTING   │
          └───────────────────────────────────────────────┘
                   │  result = {decision(signed), signature, token}
                   ▼
          ┌───────────────────────────────────────────────┐
          │  GATE 3 — audit/commit  (HashLog.record)       │
          │    append {seq, ts, actor, tool, verdict,      │
          │            reason, prev_hash, entry_hash}      │
          │    BEFORE the side effect (crash-safe record)  │
          └───────────────────────────────────────────────┘
                   │
                   ▼
          ┌───────────────────────────────────────────────┐
          │  GATE 2 — pre-execution  (Executor.execute)    │
          │    · verify decision signature + kernel id     │
          │    · action_binding == fingerprint(action)?    │
          │    · verdict PERMITTING and token present?     │
          │    · verify token signature + binding + expiry │
          │    · token_id unspent? (one-time) -> mark spent│
          │    · CONTAIN: tool in allowed_tools?           │
          │    · LIMIT: run against transformed_payload    │
          │    call tools[tool_name](payload)              │
          └───────────────────────────────────────────────┘
                   │
                   ▼
                 Outcome{verdict, executed, output | refused_reason}
```

Note the ordering: Gate 1 produces the signed decision, Gate 3 commits it
durably, then Gate 2 enforces it at the moment of execution. Audit is written
**before** the effect so a crash can never erase the authorization record.

## The verdicts

Defined in [`kernel.py`](../decision_os_min/kernel.py):

| Verdict | Meaning | Token minted? | Executor behavior |
|---|---|---|---|
| `ALLOW` | Run as-is | yes | run tool on `action.payload` |
| `LIMIT` | Minimized payload | yes | run tool on `decision.transformed_payload` (redacted) |
| `CONTAIN` | Sandbox posture, advisory-driven | yes | run only if tool ∈ `containment.allowed_tools` |
| `DENY` | Refuse | no | `ExecutionRefused` |
| `DEFER` | Escalate | no | `ExecutionRefused` |

`PERMITTING = {ALLOW, LIMIT, CONTAIN}` — only these mint a token. Because the
default `_CONTAINMENT` allowlist is empty (`allowed_tools: []`), a CONTAIN
verdict refuses execution unless policy widens the allowlist.

## Data shapes (contracts.py)

Every boundary message is pinned by a `TypedDict` in
[`contracts.py`](../decision_os_min/contracts.py). They cost nothing at runtime
and let a type-checker catch drift.

- **`Action`** — a request to run one tool: `actor`, `tool`,
  optional `capability` (canonical `"tool:<name>"`), `action_purpose`,
  `data_labels`, `payload`, `nonce`. `capability` and `tool` must agree if both
  are set.
- **`Decision`** — the kernel's signed ruling: `verdict`, `reason`,
  `action_ref`, `issued_by`, `action_binding` (sha256 of the action's security
  content), plus `transformed_payload` (LIMIT only) and `containment` (CONTAIN
  only). Only the kernel produces these.
- **`CapabilityToken`** — the one-time credential minted on a permitting
  decision: `token_id`, `actor`, `capability`, `action_ref`, `action_binding`,
  `issued_by`, `expires_at`, `signature`.
- **`AuditEntry`** — one hash-chained record: `seq`, `ts`, `actor`, `tool`,
  `verdict`, `reason`, `prev_hash`, `entry_hash`.

## How `handle()` ties it together

[`DecisionOS.handle`](../decision_os_min/__init__.py):

1. `result = self.kernel.decide(action, threat_class, advisor=advisor)` — Gate 1.
   If an advisor is passed it is consulted first and takes precedence over an
   explicit `threat_class`; the kernel, not the advisor, maps a threat class to
   CONTAIN.
2. `self.log.record(actor, tool, verdict, reason)` — Gate 3. The tool name is
   derived from the *capability* (`cap.split("tool:")[-1]`), never from a raw
   caller-supplied field, so the audit records the authority-bound tool.
3. `self.executor.execute(action, result, tools)` — Gate 2 plus the effect.
   Wrapped in `try/except ExecutionRefused`, so a refusal returns
   `Outcome(verdict, executed=False, refused_reason=...)` rather than raising.

## Key implementation details worth knowing

- **Canonicalization.** Both signing and hashing use `_canonical` /
  `_hash`: JSON with `sort_keys=True, separators=(",", ":")`, excluding the
  `signature`/`entry_hash` field. Verification recomputes the same bytes, so any
  field mutation invalidates the signature or breaks the chain.
- **`action_fingerprint`** ([`kernel.py`](../decision_os_min/kernel.py)) is the
  sha256 over the security-relevant content (`actor`, `capability`,
  `action_purpose`, sorted `data_labels`, `payload`). It is bound into both the
  decision and the token, and re-checked in the executor — this is what closes
  the confused-deputy gap (see [THREAT_MODEL.md](THREAT_MODEL.md)).
- **`verify`** requires *both* `issued_by == KERNEL_IDENTITY` *and* a valid
  Ed25519 signature. Identity alone is not enough.
