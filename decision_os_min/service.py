"""Infra-ready HTTP service: policy, persistent key, audit, health/ready, metrics.

NOT a hardened production gateway — put auth/TLS/rate-limits at the ingress.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
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
    key_path = os.environ.get("DECISION_OS_KEY_FILE")
    timeout_raw = os.environ.get("DECISION_OS_EVALUATOR_TIMEOUT_S", "1.0").strip().lower()
    if timeout_raw in ("", "none", "off"):
        timeout: float | None = None
    else:
        timeout = float(timeout_raw)

    kernel = Kernel(_load_policy(), key_path=key_path, evaluator_timeout_s=timeout)
    from .audit import HashLog

    audit_path = os.environ.get("DECISION_OS_AUDIT", "audit.jsonl")
    audit = HashLog(audit_path)
    metrics: Counter[str] = Counter()
    expose_audit = os.environ.get("DECISION_OS_EXPOSE_AUDIT", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    app = FastAPI(
        title="decision-os-min",
        version="0.2.0",
        description="Reference authority + audit service for governing agent tool actions.",
    )

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, Any]:
        """Readiness: audit path writable + signing key loaded."""
        errs: list[str] = []
        try:
            p = Path(audit_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            if not os.access(p.parent, os.W_OK):
                errs.append(f"audit parent not writable: {p.parent}")
        except OSError as e:
            errs.append(f"audit path: {e}")
        try:
            _ = kernel.public_key_hex()
        except Exception as e:  # noqa: BLE001
            errs.append(f"signing key: {e}")
        ok = not errs
        return {
            "status": "ready" if ok else "not_ready",
            "errors": errs,
            "key_persisted": bool(key_path),
        }

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
        # Audit the caller-named tool — do not rewrite identity from capability
        # when capability≠tool (that case is already a DENY).
        tool_name = a.get("tool") or ""
        try:
            entry = audit.record(
                a.get("actor", ""), tool_name, d["verdict"], d["reason"]
            )
        except OSError as e:
            # Fail closed: never return a live signed token if the audit sink died.
            raise HTTPException(
                status_code=503, detail=f"audit sink unavailable: {e}"
            ) from e
        metrics[d["verdict"]] += 1
        log.info(f"decide actor={a.get('actor')} verdict={d['verdict']} seq={entry['seq']}")
        return DecisionOut(
            decision=d,
            signature=result["signature"],
            token=result["token"],
            audit_seq=entry["seq"],
        )

    @app.get("/v1/audit")
    def get_audit(limit: int = 100) -> list[dict[str, Any]]:
        if not expose_audit:
            raise HTTPException(
                status_code=404,
                detail="audit dump disabled (set DECISION_OS_EXPOSE_AUDIT=1 to enable)",
            )
        return audit.entries()[-limit:]

    @app.get("/v1/audit/verify")
    def verify_audit() -> dict[str, bool]:
        return {"chain_intact": audit.verify()}

    @app.get("/metrics")
    def prometheus_metrics() -> Any:
        from fastapi.responses import PlainTextResponse

        # Verdict counters only — never label with actor/tool/payload.
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
