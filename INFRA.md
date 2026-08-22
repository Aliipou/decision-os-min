# Infra readiness — decision-os-min

## What “infra-ready” means here

A **deployable reference PEP/authority service**, not a full enterprise gateway.

| Included | Deliberately at the ingress (not here) |
|---|---|
| Docker image + compose | TLS termination |
| Persistent Ed25519 key (`DECISION_OS_KEY_FILE`) | mTLS / OAuth for callers |
| Hash-chained audit volume | Multi-region audit notary |
| `/healthz`, `/readyz`, Prometheus `/metrics` | WAF / rate limits |
| Policy file mount | Policy editor UI |
| Evaluator timeout | Horizontal shard of spent-store |

## Quick start

```bash
cd decision-os-min
docker compose up --build -d
curl -s localhost:8080/readyz
curl -s localhost:8080/v1/pubkey
curl -s -X POST localhost:8080/v1/decide -H 'content-type: application/json' \
  -d '{"actor":"agent:bot","tool":"send_email","capability":"tool:send_email","action_purpose":"support_reply","data_labels":["customer_support"],"payload":{"to":"a@b.test"},"nonce":"n1"}'
```

## Env

| Var | Role |
|---|---|
| `DECISION_OS_POLICY` | Path to policy JSON |
| `DECISION_OS_AUDIT` | Audit JSONL path |
| `DECISION_OS_KEY_FILE` | Persist signing key across restarts |
| `DECISION_OS_EVALUATOR_TIMEOUT_S` | Fail-closed timeout for untrusted evaluators (`none` = off) |
| `DECISION_OS_EXPOSE_AUDIT` | Set `1` to enable unauthenticated `GET /v1/audit` dump (off by default) |

## MCP loop

Use sibling `plugin-mcp` `MCPMediator.wrap_handler` so tool dispatch cannot skip `DecisionOS.handle`.

## Conformance gate

```bash
cd contracts-spec && python -m conformance.suite
# expect: 10 pass · 0 fail · 0 N/A
```
