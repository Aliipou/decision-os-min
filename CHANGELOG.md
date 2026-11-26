# Changelog

All notable changes to `decision-os-min` are documented here. Versions follow
[SemVer](https://semver.org/). This is a `0.x` reference implementation — the API
may change before `1.0`.

## Unreleased

### Gateway: one command for every agent and every model (`decision_os_min.gateway`)
- `decision-os install` wraps every stdio MCP server of 13 apps (Claude Desktop, Claude Code, Cursor, VS Code, Copilot CLI, Windsurf, Gemini CLI, Codex, LM Studio, Kiro, Amazon Q, Cline, Roo Code) behind `decision-os mcp-proxy`. Atomic, verified, backed-up writes; `uninstall` restores byte for byte when the app has not edited the file since.
- MCP proxy: every `tools/call` becomes a governed action; the forward to the real server is the executor's effect. Refusals return `isError` results; hard-denied tools are hidden from `tools/list`; server-initiated requests, notifications, batches and cancellation pass through.
- Model gateway (`decision-os run -- <agent>`, `decision-os llm`): gates tool calls in OpenAI Chat Completions, OpenAI Responses and Anthropic Messages, streamed or not, for any OpenAI-compatible upstream.
- TOML policy (allow / ask / deny rules with argument globs and redaction, three profiles, observe mode) compiled into a trusted `AuthorityPDP`; a deterministic guardrail pack as a veto-only evaluator; self-protection of the gateway's own state and every MCP client config.
- Human approvals bound to the action fingerprint; local dashboard (`decision-os ui`) and terminal (`decision-os approve`); remembered choices.
- `LockedHashLog`: one hash chain shared safely by many processes.
- One-click installers: `install.sh`, `install.ps1`, `Install-DecisionOS.cmd`.
- The kernel, executor, audit and spent-store modules are unchanged; the gateway only consumes their public API.

- `DecisionOS` accepts `key_path` and `spent_store`; signing-key creation is race-safe (`O_EXCL`, mode 0600).
- Cross-process double-spend tests for `FileSpentStore` and `SqliteSpentStore`; restart and replay tests.
- `bench/latency.py` (p50/p95/p99); package metadata and `py.typed`; README rewritten; SECURITY.md operational model.

- License changed from PolyForm Noncommercial 1.0.0 to **Apache-2.0**. Earlier releases keep their original license.

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
