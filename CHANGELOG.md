# Changelog

All notable changes to `decision-os-min` are documented here. Versions follow
[SemVer](https://semver.org/). This is a `0.x` reference implementation — the API
may change before `1.0`.

## [Unreleased]

### Added
- `semantic_veto(judge)`: optional evaluator that lets an untrusted semantic
  judge refuse an action whose content does not match its declared purpose.
  Veto-only (returns ALLOW or DENY), fail-closed on errors, timeouts, malformed
  output, non-JSON payloads and views over `max_view_chars` (no truncation).
  Judge reasons are flattened to one line, stripped of control and bidi
  characters, bounded, and recorded in the signed decision and audit log.
- `SemanticJudge` protocol, `SemanticJudgment`, and the deterministic
  `PurposeTableJudge` reference judge.
- `evaluator_timeout_s` on `DecisionOS`, `Governor`, `SealedRuntime` and
  `AgentHost`, so slower evaluators can be given a realistic budget.
- `extra_evaluators` on `SealedRuntime` and `AgentHost`. Extra evaluators are
  wrapped by `evidence_free`, so they cannot replace the M5 legitimacy digest or
  axiom ids.
- `examples/semantic_llm_judge.py` (stdlib-only model-backed judge) and
  `docs/SEMANTIC_VETO.md`.

## [0.1.0] — 2026-07-03

Initial public release: the distilled **reference core** of the Decision OS.

### Core
- Single decision authority (kernel) emitting **Ed25519-signed decisions**.
- **Action-content binding** (`action_fingerprint`) folded into the signed
  decision — a signed authorization cannot be re-attached to a different action
  (confused-deputy defense).
- **One-time capability grant** folded into the signed decision (single signature
  authenticates ruling + token); replay is refused by a one-time spend.
- **Policy Enforcement Point** (executor): runs an effect only against a signed,
  action-bound decision with an unspent token. DENY/DEFER never run; LIMIT redacts
  before the tool sees the payload; CONTAIN runs only allowlisted tools.
- **Advisory ≠ authority**: an optional advisor plugin may only *tighten* a
  verdict, never author one or loosen a DENY.
- **Tamper-evident audit**: one append-only, hash-chained log; any retroactive
  edit/insert/delete/reorder is detectable.
- Formal contract as **types** (`Action`, `Decision`, `CapabilityToken`,
  `AuditEntry`).

### Deployable starter (optional `[service]` extra)
- FastAPI service: `POST /v1/decide`, `/v1/pubkey`, `/v1/audit`,
  `/v1/audit/verify`, `/healthz`, `/metrics` (Prometheus), `/openapi.json`.
- `Dockerfile` (non-root, healthcheck) and CI (lint + types + tests + Docker smoke).

### Docs & evidence
- `docs/`: WHY, ARCHITECTURE, THREAT_MODEL, TRUST_MODEL, DESIGN_PRINCIPLES,
  COMPARISON (evidence-backed vs OPA/Cedar/MCP/macaroons), DESIGN_NOTE.
- 18 tests (core + service); ruff + mypy clean.

### Honest status
Reference implementation at **SIV (System Integration Validation)** stage — **not
production-grade**. No external validation, no real-workload comparison numbers,
and no independent security audit yet. Auth/TLS/rate-limiting/scale are out of
scope for the starter (do them at the ingress).

[0.1.0]: https://github.com/Aliipou/decision-os-min/releases/tag/v0.1.0
