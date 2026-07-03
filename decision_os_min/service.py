"""A minimal, deployable HTTP service around the decision core.

This is the "infra-ready starter": it makes `decision-os-min` runnable as a real
REST service (with OpenAPI, health, and Prometheus metrics) so it can be deployed
and load-tested — NOT a production-grade, hardened, authenticated gateway. Auth,
rate limiting, TLS termination, and horizontal scaling are deliberately OUT of the
starter (do them at the ingress / in front of this).

FastAPI is imported here, never by `decision_os_min/__init__.py`, so
`import decision_os_min` stays dependency-pure. Install the service deps with:

    pip install "decision-os-min[service]"
    decision-os-serve            # or: uvicorn decision_os_min.service:app

The service exposes the AUTHORITY (the kernel's decision) and the tamper-evident
AUDIT. It does NOT execute your tools — execution belongs at the caller's PEP,
where the side effect actually happens. A client verifies the returned signature
with GET /v1/pubkey and enforces the verdict + one-time token locally.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .kernel import Kernel

logging.basicConfig(
    level=os.environ.get("DECISION_OS_LOG_LEVEL", "INFO"),
    format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
log = logging.getLogger("decision-os")

_DEFAULT_POLICY: dict[str, Any] = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def _load_policy() -> dict[str, Any]:
    path = os.environ.get("DECISION_OS_POLICY")
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    log.warning("no DECISION_OS_POLICY set — using the built-in demo policy")
    return _DEFAULT_POLICY


class ActionIn(BaseModel):
    actor: str
    tool: str
    capability: str | None = None
    action_purpose: str | None = None
    data_labels: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    nonce: str | None = None
    threat_class: str | None = Field(
        default=None, description="Optional advisory input; the kernel decides, not the caller."
    )


class DecisionOut(BaseModel):
    decision: dict[str, Any]
    signature: str
    token: dict[str, Any] | None
    audit_seq: int


def create_app() -> FastAPI:
    kernel = Kernel(_load_policy())
    from .audit import HashLog

    audit = HashLog(os.environ.get("DECISION_OS_AUDIT", "audit.jsonl"))
    metrics: Counter[str] = Counter()

    app = FastAPI(
        title="decision-os-min",
        version="0.1.0",
        description="Reference authority + audit service for governing agent tool actions.",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/pubkey")
    def pubkey() -> dict[str, str]:
        """The kernel's Ed25519 public key — clients verify decisions/tokens with it."""
        return {"kernel_public_key": kernel.public_key_hex()}

    @app.post("/v1/decide", response_model=DecisionOut)
    def decide(action: ActionIn) -> DecisionOut:
        a = action.model_dump(exclude_none=True)
        threat = a.pop("threat_class", None)
        result = kernel.decide(a, threat)
        d = result["decision"]
        cap = a.get("capability") or f"tool:{a.get('tool', '')}"
        entry = audit.record(a.get("actor", ""), cap.split("tool:")[-1], d["verdict"], d["reason"])
        metrics[d["verdict"]] += 1
        log.info(f"decide actor={a.get('actor')} verdict={d['verdict']} seq={entry['seq']}")
        return DecisionOut(
            decision=d, signature=result["signature"], token=result["token"],
            audit_seq=entry["seq"],
        )

    @app.get("/v1/audit")
    def get_audit(limit: int = 100) -> list[dict[str, Any]]:
        return audit.entries()[-limit:]

    @app.get("/v1/audit/verify")
    def verify_audit() -> dict[str, bool]:
        return {"chain_intact": audit.verify()}

    @app.get("/metrics")
    def prometheus_metrics() -> Any:
        from fastapi.responses import PlainTextResponse

        lines = [
            "# HELP decision_os_decisions_total Decisions issued, by verdict.",
            "# TYPE decision_os_decisions_total counter",
        ]
        for verdict, n in sorted(metrics.items()):
            lines.append(f'decision_os_decisions_total{{verdict="{verdict}"}} {n}')
        return PlainTextResponse("\n".join(lines) + "\n")

    return app


app = create_app()


def main() -> None:
    """Entry point for `decision-os-serve` (see pyproject scripts)."""
    import uvicorn

    uvicorn.run(
        "decision_os_min.service:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8080")),
    )


if __name__ == "__main__":
    main()
