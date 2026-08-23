# decision-os-min

**Live (graph):** [https://ali-decision-os-min.vercel.app](https://ali-decision-os-min.vercel.app)

**An evidence-driven agent governance runtime: signed decisions, mandatory
Hosted effect mediation, tamper-evident audit, and an optional Linux/Docker
isolation profile for untrusted agent code.**

> **What "OS" means here:** an *execution-governance / decision-enforcement layer*
> — the authority + audit plane for an agent's tool calls — **not** an operating
> system in the classic sense. It's a research-*oriented* architecture: its
> advantages over existing tools are not yet proven by independent evaluation.

> **Legitimacy ⊥ Authority — two independent constraints**
> (see [contracts-spec/POSITIONING.md](https://github.com/Aliipou/contracts-spec/blob/main/POSITIONING.md)):
> - **FDK — legitimacy** (ownership / consent / verifier): *should this happen at
>   all?* A **DENY-only** gate.
> - **AuthGate — authority** (delegated machine property rights: tool-permission +
>   runtime enforcement): *does this actor hold the capability?* Grants only
>   within legitimacy.
>
> `LegitimacyAuthorityPipeline` provides a sequential helper; the general
> evaluator composer uses a commutative, deny-dominant meet. The security
> invariant is not evaluator order: legitimacy may only deny and authority can
> never override that denial.
> The *normative rule* filling each slot is injected policy — never baked into the
> kernel — so operational frameworks (GDPR, HIPAA, the EU AI Act, ISO 42001, NIST
> AI RMF) also express as enforceable, auditable policy on top. A proposed
> architecture, not a proven paradigm.

```python
from decision_os_min import DecisionOS

dos = DecisionOS(policy, audit_path="audit.jsonl")
outcome = dos.handle(action, tools)          # one call: gates → decision → audit → execute
```

A single authority (the kernel) signs a decision **bound to the action's
content** and mints a **one-time** capability token; the executor (PEP) runs an
effect ONLY against that signed, bound decision and unspent token; every decision
is appended to **one** tamper-evident hash-chained log. Hosted agents add a
separate trust domain; OS isolation remains an explicit, qualified profile.

## Status — infrastructure claims (2026-08-23)

Do **not** read “AI infrastructure” as “fully non-bypassable.” Claims are sliced:

| Layer | Claim | Status |
|---|---|---|
| Decision core / PEP / composition | Signed authority + audit + red-team regressions | **PASS** (in-repo tests) |
| **TM-H** Hosted agent plane | Host-registered effects only via Intent → Admission→FDK→Auth→PEP | **PASS** — `docs/HOSTED_AGENT_PLANE.md` |
| **TM-A-v1 FS/NET** | No durable FS write / outbound net / ambient product creds under Docker profile | **PASS** — `sandbox/` |
| **AgentCreatedProcess + W^X/ptrace** | Actual post-lock fork/exec/thread/mmap/ptrace attempts | **BLOCKED** under declared Linux/Docker profile |
| **Combined boundary** | Locked Docker agent → Intent JSONL → outside `AgentHost` → governed host effect | **PASS** — real IPC/destructors in `tests/test_e2e_agent_boundary.py` |
| **IPC abuse** | identity spoof, malformed/oversized frames, request replay, unresponsive Host | **BLOCKED** in tested cases |
| **Resource probes** | thread creation and FD exhaustion | **BLOCKED/LIMITED**; memory/CPU cgroups configured |
| **TM-A full** `DirectEffect(Agent)=∅` | Absolute ambient isolation | **PARTIAL** — breakout/Host residuals |
| SealedRuntime alone vs ambient Python | In-process sealing stops sealed-surface bypasses; ambient `open`/`socket` still exist without OS jail | intentional limit |

Threat-model source of truth: [`docs/THREAT_MODELS.md`](docs/THREAT_MODELS.md).
Per-layer negative contract: [`docs/FORBIDDEN_ACTIONS.md`](docs/FORBIDDEN_ACTIONS.md).

### Earlier composition / red-team results (still held)

Three claims tested earlier. One held, one corrected, one falsified and fixed twice:

**1. Pipeline order is NOT a security meet.** Composition is the meet of a bounded
verdict lattice (`ALLOW ≺ LIMIT ≺ CONTAIN ≺ DEFER ≺ DENY`); order is performance.

**2. Stacking two engines that each mint is incorrect** — compose before mint.
See `tests/test_authority_convergence.py`.

**3. “Untrusted evaluator can at worst deny” was FALSE twice** — closed; kept as
regressions in `tests/test_redteam_composition.py` and `tests/test_redteam_round2.py`.

**Conformance:** Authority Enforcement Profile (`contracts-spec/conformance/`).
AE-4/AE-5 use a macaroon-inspired attenuation graph (`decision_os_min/attenuation.py`)
— caveats only narrow; child expiry clamped to parent.

## How it flows

```text
        Action
          │
          ▼
    DecisionOS.handle()
          │
          ▼
      Identity  ── admission: is this a known principal?
          │
          ▼
   FDK legitimacy ── DENY-only: should this happen at all? (may only refuse)
          │
          ▼
   AuthGate authority ── Gate 1: capability + purpose, grant WITHIN legitimacy
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

The sequential helper evaluates identity admission → FDK legitimacy (DENY-only)
→ AuthGate authority → PEP execution and audit. General evaluator composition is
order-independent and deny-dominant; no ordering grants precedence over a denial.

## Govern your agent's tools — signed authorization + audit

The wedge: **governed tool execution for AI agents** under an explicit threat model.
You write a policy and wrap tools / use the Hosted plane; host-registered effects
cannot skip Admission→legitimacy→authority→PEP. **Ambient OS effects** (files,
sockets, subprocess) are **not** closed by the Python library alone — use the
Docker + `lock_and_run` profile (`sandbox/`) for TM-A slices.

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
friction runs the right way. Within the Hosted plane, registered Host adapters
have no path that skips governed mediation. This is **not** a claim that arbitrary
ambient effects elsewhere in the application are closed.

### Who this is for — and who it isn't

**For you if:** you run AI agents (or are about to) that hold **sensitive tools** —
email, payments, files, internal APIs — and you need *authorization + a
verifiable execution trail* on what they do. That's the pain this solves.

**Not for you (yet) if:** your agents only do read-only / harmless things, or you
have no compliance/audit need — then this is overhead you don't need, and OPA/Cedar
or your own middleware may fit better. That's an honest answer, and knowing it is
more useful than a star.

## Security properties tested

These are executable regression results under the assumptions in
[`docs/THREAT_MODELS.md`](docs/THREAT_MODELS.md), not formal proofs:

- **Single authority** — only the kernel's Ed25519-signed decisions authorize anything.
- **Deterministic decision engine** — same (policy, action, advice) ⇒ same verdict; no ML in the decision path.
- **Action-bound authorization** — a decision/token cannot be re-attached to a different action (confused-deputy defense).
- **One-time capability tokens** — replay is refused; no valid token ⇒ no execution; DENY/DEFER never run.
- **Graduated enforcement** — LIMIT redacts before the tool sees the payload; CONTAIN runs only allowlisted tools.
- **Advisory ≠ authority** — an advisor can only tighten a verdict, never loosen a DENY.
- **Tamper-evident audit** — edits/inserts/reorders are detected; tail truncation
  requires the supported external head anchor.

The Linux/Docker process-isolation results execute real post-`lock_and_run`
fork/exec/thread, executable-mapping, and ptrace attempts and assert kernel
refusal; they do not infer enforcement from configuration files alone. See
`tests/test_os_isolation.py`.

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

Endpoints: `POST /v1/decide`, `GET /v1/pubkey`, `GET /v1/audit` + `/v1/audit/verify`
(audit dump off unless `DECISION_OS_EXPOSE_AUDIT=1`), `GET /healthz`, `GET /readyz`,
`GET /metrics`, `GET /openapi.json`. Authority + audit only — caller's PEP executes.

Docker / Compose:

```bash
docker compose up --build -d
curl -s localhost:8080/readyz
# or:
docker build -t decision-os-min .
docker run -p 8080:8080 -v $PWD/deploy/policy.json:/config/policy.json \
  -e DECISION_OS_POLICY=/config/policy.json \
  -e DECISION_OS_KEY_FILE=/data/kernel_ed25519.pem decision-os-min
```

See [`INFRA.md`](INFRA.md). **Starter, not production-grade** — auth/TLS/rate limits at ingress.

## Hosted agents + OS isolation

```text
Untrusted agent  --Intent IPC-->  AgentHost (SealedRuntime + adapters)
     optional: Docker agent-noambient-v1 + lock_and_run
```

- Host plane: `decision_os_min.host`, `docs/HOSTED_AGENT_PLANE.md`
- Agent sandbox: `sandbox/README.md`, `docs/THREAT_MODELS.md`

## Local development and verification

Python 3.11+ is required.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev,service]"
ruff check .
mypy decision_os_min
pytest -q
```

Linux plus Docker is required for the marked TM-A isolation suite:

```bash
pytest -q -m tm_a tests/test_os_isolation.py tests/test_e2e_agent_boundary.py
```

Service environment:

| Variable | Required | Purpose |
|---|---:|---|
| `DECISION_OS_POLICY` | service only | Policy JSON path |
| `DECISION_OS_AUDIT` | no | Audit JSONL path |
| `DECISION_OS_KEY_FILE` | recommended | Persistent Ed25519 private-key path |
| `DECISION_OS_EVALUATOR_TIMEOUT_S` | no | Fail-closed evaluator timeout |
| `DECISION_OS_EXPOSE_AUDIT` | no | Set `1` to expose the unauthenticated audit dump |

## Product site and Vercel

The public site in `public/` is a dependency-free explanation and interactive,
browser-side walkthrough. The walkthrough is deliberately labeled as a model:
it performs no external effect and is not the Python authority service.

```bash
python -m http.server 4173 --directory public
# production-equivalent static build:
npx vercel build
```

`vercel.json` sets `public/` as the output directory and applies CSP,
clickjacking, MIME-sniffing, referrer, and permissions headers. No environment
variables or backend are required for the explanatory site. A real application
must deploy the Python service/Host separately behind authenticated TLS ingress;
do not expose signing keys or effect adapters to the static site.

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
- Bundled production notary / external WORM service (the `HashLog` anchor seam exists)
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
