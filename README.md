# decision-os-min

**A minimal reference implementation of the Decision OS: it preserves the core
security invariants in a single package, collapsing the multi-repo architecture
into one `handle()` call.**

> **What "OS" means here:** an *execution-governance / decision-enforcement layer*
> — the authority + audit plane for an agent's tool calls — **not** an operating
> system in the classic sense. It's a research-*oriented* architecture: its
> advantages over existing tools are not yet proven by independent evaluation.

> **Value-neutral by design.** This is a *policy runtime*, not a worldview. Any
> normative framework — GDPR, HIPAA, the EU AI Act, ISO 42001, NIST AI RMF, or a
> research theory — sits *on top* of it as an enforceable, auditable **policy**.
> The kernel decides nothing on its own; it enforces the policy you give it. The
> runtime is the *bottom* layer, not the top.

> **Legitimacy ⊥ Authority.** `LegitimacyAuthorityPipeline` (shipped here) puts a
> DENY-only *legitimacy* gate — "should this happen at all?" (the FDK role) — in
> front of the kernel's *authority* — "does this actor hold the capability?".
> **Invariant, enforced by structure:** legitimacy may only DENY (it returns just
> `(ok, reason)`, never a grant); authority never overrides a legitimacy denial.
> The legitimacy *rule* is injected policy — never baked into the kernel. A
> proposed architecture, not a proven paradigm.

```python
from decision_os_min import DecisionOS

dos = DecisionOS(policy, audit_path="audit.jsonl")
outcome = dos.handle(action, tools)          # one call: gates → decision → audit → execute
```

A single authority (the kernel) signs a decision **bound to the action's
content** and mints a **one-time** capability token; the executor (PEP) runs an
effect ONLY against that signed, bound decision and unspent token; every decision
is appended to **one** tamper-evident hash-chained log. That is the whole security
model — in ~400 lines, stdlib + `cryptography` only.

## How it flows

```text
        Action
          │
          ▼
    DecisionOS.handle()
          │
          ▼
        Kernel  ── Gate 1: identity + capability + purpose
          │
          ├── Decision (signed)
          ├── Capability Token (one-time, action-bound)
          │
          ▼
        Audit   ── Gate 3: durable, tamper-evident commit
          │
          ▼
        Execute ── Gate 2: signature + action binding + token
```

**One action, three gates, one central policy.** The full multi-repo system runs
the same gates across separate services; here they are collapsed into one call —
fewer layers, same gate-passes.

## Govern your agent's tools — signed authorization + audit

The wedge: **safe tool execution for production AI agents.** You write a policy
once and wrap your tool registry; from then on there is **no way to call a tool
that skips the kernel** — the wrapped callable *is* the governed tool. (Not
literally "one line": you define a policy, create a `Governor`, wrap your tools,
and set the agent identity — a handful of lines, shown below.)

```python
from decision_os_min import Governor, set_actor, GovernanceRefused

gov = Governor(policy, audit_path="audit.jsonl")

@gov.tool("send_email", capability="tool:send_email", purpose="support_reply",
          data_labels=["customer_support"])
def send_email(to: str, body: str) -> str:
    ...                         # only ever runs if the kernel permits it

set_actor("agent:bot")          # your app sets the agent identity (admission)
send_email(to="x", body="y")    # decide -> audit -> execute, or GovernanceRefused
```

Or govern a whole agent-framework tool registry at once with `gov.wrap(tools, specs=...)`.
Removing governance means deleting the wrapper and losing your audit trail — the
friction runs the right way. (You still can't *force* the wider ecosystem with
code; that's adoption. But inside any app that adopts it, there is no bypass.)

### Who this is for — and who it isn't

**For you if:** you run AI agents (or are about to) that hold **sensitive tools** —
email, payments, files, internal APIs — and you need *authorization + a
non-repudiable audit trail* on what they do. That's the pain this solves.

**Not for you (yet) if:** your agents only do read-only / harmless things, or you
have no compliance/audit need — then this is overhead you don't need, and OPA/Cedar
or your own middleware may fit better. That's an honest answer, and knowing it is
more useful than a star.

## Security Guarantees (proven in `tests/`)

- **Single authority** — only the kernel's Ed25519-signed decisions authorize anything.
- **Deterministic decision engine** — same (policy, action, advice) ⇒ same verdict; no ML in the decision path.
- **Action-bound authorization** — a decision/token cannot be re-attached to a different action (confused-deputy defense).
- **One-time capability tokens** — replay is refused; no valid token ⇒ no execution; DENY/DEFER never run.
- **Graduated enforcement** — LIMIT redacts before the tool sees the payload; CONTAIN runs only allowlisted tools.
- **Advisory ≠ authority** — an advisor can only tighten a verdict, never loosen a DENY.
- **Tamper-evident audit** — any retroactive edit/insert/delete/reorder is detected.

## Run it as a service (deployable starter)

A REST service (OpenAPI + health + Prometheus metrics) ships as an **optional**
extra — the core stays dependency-pure.

```bash
pip install "decision-os-min[service]"
DECISION_OS_POLICY=policy.json decision-os-serve      # -> http://localhost:8080

curl localhost:8080/healthz
curl -X POST localhost:8080/v1/decide -H 'content-type: application/json' \
  -d '{"actor":"agent:bot","tool":"send_email","capability":"tool:send_email",
       "action_purpose":"support_reply","data_labels":["customer_support"],"nonce":"n1"}'
# -> {"decision":{"verdict":"ALLOW",...},"signature":"...","token":{...},"audit_seq":0}
```

Endpoints: `POST /v1/decide` (signed decision + audit), `GET /v1/pubkey` (verify
key), `GET /v1/audit` + `/v1/audit/verify` (tamper-evident trail), `GET /healthz`,
`GET /metrics`, `GET /openapi.json`. The service is the **authority + audit** — it
does not execute your tools; the caller's PEP enforces the verdict + one-time
token locally.

Docker:

```bash
docker build -t decision-os-min .
docker run -p 8080:8080 -v $PWD/policy.json:/config/policy.json \
  -e DECISION_OS_POLICY=/config/policy.json decision-os-min
```

**This is a *starter*, not production-grade.** Auth, TLS, rate limiting, and
horizontal scale belong at the ingress in front of it (see Out of Scope).

## Extending it (plugins)

The kernel is fixed; capability grows in plugins *around* it. A plugin is just a
package that fits a **seam** (advisor, signer, policy-compiler, identity-verifier,
tool-adapter) — and may advise/adapt/provide a backend, but **never decide or
bypass the kernel**. See [`docs/PLUGIN_API.md`](docs/PLUGIN_API.md) for the stable
contract. No plugin framework to learn — it's the library model.

## Out of Scope (use the full Decision OS for these)

- Distributed deployment / multi-node consensus
- Enterprise integrations and cross-service orchestration
- Research modules (FDK advisory research beyond the simple plugin)
- Notary anchoring / external trust roots
- Auth / TLS / rate limiting (do these at the ingress), Helm/K8s, Grafana dashboards
- Network-level threat model, real load/scale numbers, and formal proofs

## What was deliberately cut (and why it's fine)

| Full multi-repo system | Here |
|---|---|
| `control-plane` as its own repo | one `handle()` |
| `fdk-research` advisory repo | an **optional plugin**: `decide(action, advisor=fn)` |
| `audit-ledger` + notary (dual truth) | **one** hash-chained log |
| `contracts-spec` package + JSON Schema | formal **types** in `contracts.py` |
| 7 repos + venv + integration harness | `pip install decision-os-min` |

The contract is still **formal** — `Action`, `Decision`, `CapabilityToken`,
`AuditEntry` are typed (`contracts.py`); they cost nothing at runtime but stop
drift. The FDK is **not deleted**, just right-sized: an advisor is a plain
`(action) -> threat_class | None` function; omit it and the system works fully.

## Relationship to the full Decision OS

This does **not** replace the multi-repo system — it is its **reference core**.

```
Decision OS
├── decision-os-min        ← reference core: small, stable, educational, product starter
├── decision-kernel-core   ┐
├── control-plane          │
├── audit-ledger           ├─ enterprise / research track: distribution,
├── authgate               │  integration, notary, advisory research, formal proofs
├── fdk-research           │
└── decision-os-integration┘
```

**Governance rule (single source of decision-logic truth):** when the decision
logic changes, it is stabilized **here first**, then the enterprise track extends
the *same* behavior with more capability (distribution, integration, research).
The two versions must never fork their decision semantics.

## Trusted core (Rust)

Both distributions of the Decision OS — this minimal one and the full
[`decision-os-integration`](https://github.com/Aliipou/decision-os-integration)
harness — **link the same two rustified trusted-core components** rather than
carrying divergent copies. Minimal links them for compact embedding; the integration
harness links them for the full multi-repo deployment.

- **[authgate-kernel](https://github.com/Aliipou/authgate-kernel)** — the Rust
  *authority* TCB (the decision + capability core), with machine-checked models
  (Lean 4 / TLA+ / Kani).
- **[freedom-decision-kernel/rust](https://github.com/Aliipou/freedom-decision-kernel)**
  — the Rust *legitimacy-kernel* parity port.

Honest scope: the Rust components are the **trusted computing base** (authority +
the legitimacy-kernel primitive). The legitimacy **policy** — the injected rule
that fills the DENY-only gate — stays Python: it is policy, not TCB, and is
contained by the Rust authority backstop. This is **not** a full Rust rewrite of
the system, and the Python reference implementation in this repo remains the
primary, self-contained artifact.
