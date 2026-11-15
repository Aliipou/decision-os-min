# decision-os-min

**A small Python runtime that lets an autonomous agent act only through a signed, single-use, audited decision.**

An agent that can send email, move money or deploy code should not be able to do it just because it asked. `decision-os-min` puts one authority between the agent and its tools:

1. A **kernel** checks the request against your policy and signs a decision bound to that exact action.
2. It mints a **one-time capability token**.
3. An **executor** (the enforcement point) runs the effect only if the signature, the action binding and the token are all valid.
4. Every outcome, executed or refused, is appended to **one hash-chained audit log**.

```python
from decision_os_min import DecisionOS

dos = DecisionOS(policy, audit_path="audit.jsonl")
outcome = dos.handle(action, tools)   # decide -> sign -> audit -> execute
```

[Explainer site](https://ali-decision-os-min.vercel.app) is a static walkthrough. It does not sign or execute anything.

"OS" here means an execution-governance layer for tool calls. It is not an operating system, and it is not a replacement for general IAM.

## What you get

| Property | How it works |
|---|---|
| One authority | Only the kernel's Ed25519 signature authorizes an effect. |
| Action-bound decisions | A decision cannot be reused for a different action. |
| Single-use tokens | Replays are refused, across processes and restarts when you use a durable spent store. |
| Veto-only composition | Verdicts combine as `ALLOW < LIMIT < CONTAIN < DEFER < DENY`. Any evaluator can tighten a verdict, none can loosen a `DENY`. |
| Graduated enforcement | `LIMIT` redacts fields before the tool sees them. `CONTAIN` allows only allowlisted tools. |
| Deterministic decisions | Same policy, action and advice give the same verdict. No ML in the decision path. |
| Tamper-evident audit | Edits, inserts and reorders are detected. Detecting tail truncation needs an external head anchor. |

## Quick start

Python 3.11 or newer.

```bash
pip install decision-os-min              # core (stdlib + cryptography)
pip install "decision-os-min[service]"   # adds the optional HTTP service
```

Govern tools with a decorator:

```python
from decision_os_min import Governor, set_actor, GovernanceRefused

gov = Governor(policy, audit_path="audit.jsonl")

@gov.tool("send_email", capability="tool:send_email", purpose="support_reply",
          data_labels=["customer_support"])
def send_email(to: str, body: str) -> str:
    ...   # runs only if the kernel permits it

set_actor("agent:bot")
send_email(to="x", body="y")   # decide -> audit -> execute, or GovernanceRefused
```

Use `gov.wrap(tools, specs=...)` to govern a whole tool registry at once.

## Production setup

Two things must survive a restart or you lose security properties:

```python
from decision_os_min import DecisionOS, FileSpentStore

dos = DecisionOS(
    policy,
    audit_path="/var/lib/dos/audit.jsonl",
    key_path="/var/lib/dos/kernel.pem",                 # signing identity
    spent_store=FileSpentStore("/var/lib/dos/spent"),   # used-token record
)
```

- **`key_path`**: without it the signing key is ephemeral. Every restart invalidates all outstanding decisions. The file is created with mode 0600 and is race-safe.
- **`spent_store`**: `FileSpentStore` and `SqliteSpentStore` are atomic and fsync'd, and fail closed if the store is unreachable. They are safe across processes on one shared volume. They are not a distributed consensus store. For replicas on separate disks, implement `SpentStore` over a shared database.
- Operational controls and limits: [SECURITY.md](SECURITY.md).

## Run it as a service

An optional REST service ships with OpenAPI, health checks and Prometheus metrics. It does authority and audit only. Your own enforcement point executes the effect.

```bash
DECISION_OS_POLICY=policy.json decision-os-serve      # http://localhost:8080
curl -X POST localhost:8080/v1/decide -H 'content-type: application/json' \
  -d '{"actor":"agent:bot","tool":"send_email","capability":"tool:send_email",
       "action_purpose":"support_reply","data_labels":["customer_support"],"nonce":"n1"}'
```

Endpoints: `POST /v1/decide`, `GET /v1/pubkey`, `GET /v1/audit` and `/v1/audit/verify` (the dump is off unless `DECISION_OS_EXPOSE_AUDIT=1`), `/healthz`, `/readyz`, `/metrics`, `/openapi.json`.

Docker: `docker compose up --build -d`, then `curl localhost:8080/readyz`. See [INFRA.md](INFRA.md). This is a starter: put auth, TLS and rate limits at your ingress.

| Variable | Purpose |
|---|---|
| `DECISION_OS_POLICY` | Policy JSON path (service only) |
| `DECISION_OS_KEY_FILE` | Persistent Ed25519 key path (recommended) |
| `DECISION_OS_AUDIT` | Audit JSONL path |
| `DECISION_OS_EVALUATOR_TIMEOUT_S` | Fail-closed evaluator timeout |
| `DECISION_OS_AUTHORITY_PDP` | `builtin` (default), `opa` or `cedar` |
| `DECISION_OS_AUTHORITY_TIMEOUT_S` | Fail-closed policy-engine timeout |
| `DECISION_OS_EXPOSE_AUDIT` | Set `1` to expose the unauthenticated audit dump |

## How a request flows

```text
Untrusted agent -> Intent -> AgentHost
                               |- Legitimacy check (can only deny)
                               '- Authority policy (built-in, Cedar or OPA)
                                         |
                              combine verdicts (deny wins)
                                         |
                                       Kernel
                          bind to action, sign, mint one token
                                         |
                                 Executor (enforcement point)
                              verify signature, spend token once
                                         |
                                  Audit + effect
```

Two independent constraints apply to every action:

- **Legitimacy** (ownership, consent): *should this happen at all?* It can only deny.
- **Authority** (a delegated, spendable capability): *does this actor hold the right?* It grants only inside what legitimacy allows.

The rules that fill each slot are injected policy. The kernel does not contain a moral theory. It only makes your policy hard to skip.

You can swap the authority policy engine without touching the execution boundary:

```python
from decision_os_min import DecisionOS, OPAHTTPAuthorityPDP

pdp = OPAHTTPAuthorityPDP("http://127.0.0.1:8181/v1/data/decision/allow",
                          policy_revision="bundle-sha256:...")
dos = DecisionOS({}, audit_path="audit.jsonl", authority_pdp=pdp)
```

Cedar or OPA can grant or deny, but their output is reduced to a verdict and reason. They never see the signing key, the spent store or the enforcement point. Only the kernel can turn a verdict into executable authority.

## What is and is not protected

| Layer | Claim | Status |
|---|---|---|
| Decision core, enforcement point, composition | Signed authority, audit, red-team regressions | Passes in-repo tests |
| Hosted agent plane | Host-registered effects run only through Intent, Admission, legitimacy, authority, enforcement | Passes ([docs](docs/HOSTED_AGENT_PLANE.md)) |
| Docker isolation: filesystem and network | No durable writes, outbound network or ambient credentials | Passes ([`sandbox/`](sandbox/)) |
| Docker isolation: process | Fork, exec, thread, mmap and ptrace attempts after lock | Blocked under the declared Linux/Docker profile |
| Full isolation, `DirectEffect(Agent)=empty` | Nothing the agent does reaches the world except through the host | **Partial**: breakout and host residuals remain |
| In-process sealing alone | Stops bypasses of the sealed surface | Ambient `open` and `socket` still exist without an OS jail |

The Python library alone does not close ambient effects such as raw file or socket access. For that, use the Docker profile in [`sandbox/`](sandbox/). Do not read this project as "fully non-bypassable".

These are executable regression results under the assumptions in [docs/THREAT_MODELS.md](docs/THREAT_MODELS.md), not formal proofs. Per-layer negative contract: [docs/FORBIDDEN_ACTIONS.md](docs/FORBIDDEN_ACTIONS.md).

## Who it is for

For you if you run agents that hold sensitive tools (email, payments, files, internal APIs) and you need an owner to be able to veto an action, plus a verifiable record of what actually ran.

Not for you if you need a general permission language for users and APIs (use Cedar or OPA), or your agents only do harmless read-only work.

## Compared with Cedar, OPA and MCP

This runtime is not a better policy language. Cedar and OPA are more general. This project is the enforcement chain that runs after a policy decision: signed binding, single-use spend, audit.

We run a shared six-case workload to check conformance, not to rank speed. Measured 2026-08-23 on Windows 10 (Intel i5-7300U), Python 3.13.2, 50 timed iterations after 10 warmups:

| System | Verdicts matching expected | What was measured |
|---|---|---|
| decision-os-min | 6 of 6 | in-process policy meet |
| OPA 1.19.1 | 6 of 6 | warm HTTP query |
| Cedar CLI 4.12.0 | 6 of 6 | subprocess per request |
| MCP TypeScript SDK 2.0.0 | no verdict | transport only: its handler ran even on the four cases governance denies |

Per-scope timings, scenarios and reproduction steps: [bench/comparison/README.md](bench/comparison/README.md). Positioning: [docs/COMPARISON.md](docs/COMPARISON.md).

## Performance

`bench/latency.py` reports p50/p95/p99 for a full `handle` call with a durable spent store. On one Windows laptop: about 19 ms p50 and 37 ms p99 single-threaded, dominated by the two fsyncs (spent marker and audit entry). See [BENCHMARKS.md](BENCHMARKS.md). These are one machine's numbers, not a capacity claim.

## Develop and test

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,service]"
ruff check . && mypy decision_os_min && pytest -q
```

Linux with Docker is needed for the isolation suite: `pytest -q -m tm_a tests/test_os_isolation.py tests/test_e2e_agent_boundary.py`.

## Extending it

The kernel is fixed. Plugins attach at typed seams and can advise, adapt or provide a backend, but never grant. A selected authority policy engine is the one labelled exception: trusted for policy meaning, still unable to sign, mint, spend or bypass the enforcement point. See [docs/PLUGIN_API.md](docs/PLUGIN_API.md).

## Out of scope

Distributed consensus, enterprise integrations, a bundled notary or WORM store (the `HashLog` anchor seam exists), auth/TLS/rate limiting (do these at ingress), Kubernetes and dashboards, a network-level threat model, load numbers, and formal proofs.

## Relationship to other repos

This is the Python reference core of the larger Decision OS. Decision logic is stabilized here first, and the larger system extends the same behaviour.

- [authgate-kernel](https://github.com/Aliipou/authgate-kernel) (now [sluicegate](https://github.com/Aliipou/sluicegate)): the Rust authority core with Lean 4, TLA+ and Kani models.
- [freedom-theory](https://github.com/Aliipou/freedom-theory): the constitution (A1 to A7) behind the legitimacy and authority split.

This package contains no Rust and does not call a Rust kernel. A future binding must pass differential decision, binding, minting and enforcement tests before that claim changes.

## Contributing

We want people who will attack this, not decorate it: red-team (mint or run without a valid grant), Linux isolation, the hosted agent plane, and Cedar/OPA adapters that cannot mint. Open a PR with a test that fails on `main` today. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and do not write "no bypass anywhere". Discussion: [discussions/3](https://github.com/Aliipou/decision-os-min/discussions/3).

## License

Apache-2.0 (see `LICENSE` and `NOTICE`). Versions published before this change were released under the PolyForm Noncommercial License 1.0.0 and remain under that license. Contributions are accepted under the Developer Certificate of Origin.
