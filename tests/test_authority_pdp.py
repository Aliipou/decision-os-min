"""Trusted replaceable PDP contract and no-second-mint adversarial tests."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest
from fastapi.testclient import TestClient

from decision_os_min import (
    AuthorityMutationUnsupported,
    CedarCLIAuthorityPDP,
    DecisionOS,
    Kernel,
    OPAHTTPAuthorityPDP,
    legitimacy,
    verify,
)
from decision_os_min.compose import ALLOW, CONTAIN, DENY, LIMIT
from decision_os_min.host import AgentHost, Intent
from decision_os_min.spentstore import InMemorySpentStore


def _action(**updates: Any) -> dict[str, Any]:
    action = {
        "actor": "agent:external",
        "tool": "send_email",
        "capability": "tool:send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {"body": "hello"},
        "nonce": "pdp-case",
    }
    action.update(updates)
    return action


@dataclass
class FakePDP:
    output: Any = ALLOW
    name: str = "fake-pdp"
    mutable: bool = False
    policy_revision: str = "fake-v1"

    def evaluate(self, action: dict[str, Any]) -> Any:
        return self.output

    def healthcheck(self) -> tuple[bool, str]:
        return (True, self.policy_revision)


def test_external_allow_replaces_builtin_grants_but_kernel_alone_mints(tmp_path):
    pdp = FakePDP()
    dos = DecisionOS({}, audit_path=str(tmp_path / "audit.jsonl"), authority_pdp=pdp)
    action = _action()

    result = dos.kernel.decide(action)
    decision = result["decision"]
    assert decision["verdict"] == ALLOW
    assert result["token"] is not None
    assert decision["authority_provider"] == "fake-pdp"
    assert decision["authority_policy_revision"] == "fake-v1"
    assert decision["issued_by"] == "decision-os-min-kernel"
    assert verify(decision, result["signature"], dos.kernel.public_key_hex())

    outcome = dos.handle(
        _action(nonce="execute-once"),
        {"send_email": lambda payload: payload["body"]},
    )
    assert outcome.executed and outcome.output == "hello"


def test_provider_field_injection_is_stripped_before_kernel_signs():
    injected = {
        "verdict": ALLOW,
        "reason": "grant",
        "issued_by": "attacker",
        "signature": "00",
        "token_id": "attacker-token",
        "token_expires_at": "2999-01-01T00:00:00Z",
        "action_binding": "attacker-binding",
        "transformed_payload": {"body": "attacker"},
        "containment": {"allowed_tools": ["wire_money"]},
        "authority_provider": "attacker",
    }
    kernel = Kernel({}, authority_pdp=FakePDP(injected))
    result = kernel.decide(_action())
    decision = result["decision"]

    assert decision["issued_by"] == "decision-os-min-kernel"
    assert decision["token_id"] != "attacker-token"
    assert decision["action_binding"] != "attacker-binding"
    assert decision["authority_provider"] == "fake-pdp"
    assert "transformed_payload" not in decision
    assert "containment" not in decision
    assert verify(decision, result["signature"], kernel.public_key_hex())


def test_provider_receives_copy_and_cannot_mutate_executed_action(tmp_path):
    class Mutating(FakePDP):
        def evaluate(self, action):
            action["tool"] = "wire_money"
            action["capability"] = "tool:wire_money"
            action["payload"]["body"] = "mutated"
            return ALLOW

    original = _action(nonce="copy-isolation")
    dos = DecisionOS(
        {}, audit_path=str(tmp_path / "copy.jsonl"), authority_pdp=Mutating()
    )
    outcome = dos.handle(
        original,
        {
            "send_email": lambda payload: f"email:{payload['body']}",
            "wire_money": lambda payload: pytest.fail("mutated tool executed"),
        },
    )
    assert outcome.executed and outcome.output == "email:hello"
    assert original["tool"] == "send_email"
    assert original["payload"]["body"] == "hello"


def test_decide_has_one_kernel_signature_and_provider_cannot_trigger_effect(monkeypatch):
    effects: list[str] = []
    kernel = Kernel({}, authority_pdp=FakePDP(ALLOW))
    original_sign = kernel._sign
    signs = 0

    def counted(obj):
        nonlocal signs
        signs += 1
        return original_sign(obj)

    monkeypatch.setattr(kernel, "_sign", counted)
    result = kernel.decide(_action())
    assert result["token"] is not None
    assert signs == 1
    assert effects == []


@pytest.mark.parametrize("output", [None, 42, {}, "ROOT", {"verdict": object()}])
def test_malformed_or_off_lattice_provider_output_fails_closed(output):
    result = Kernel({}, authority_pdp=FakePDP(output)).decide(_action())
    assert result["decision"]["verdict"] == DENY
    assert result["token"] is None


def test_provider_error_and_timeout_fail_closed():
    class Raising(FakePDP):
        def evaluate(self, action):
            raise RuntimeError("PDP unavailable")

    class Sleeping(FakePDP):
        def evaluate(self, action):
            time.sleep(0.1)
            return ALLOW

    raised = Kernel({}, authority_pdp=Raising()).decide(_action())
    timed = Kernel(
        {}, authority_pdp=Sleeping(), authority_timeout_s=0.001
    ).decide(_action())
    assert raised["decision"]["verdict"] == DENY and raised["token"] is None
    assert timed["decision"]["verdict"] == DENY and timed["token"] is None
    assert "timeout" in timed["decision"]["reason"]


def test_legitimacy_deny_absorbs_trusted_provider_allow():
    kernel = Kernel({}, authority_pdp=FakePDP(ALLOW))
    result = kernel.decide(
        _action(),
        evaluators=[legitimacy(lambda action: (False, "consent absent"))],
    )
    assert result["decision"]["verdict"] == DENY
    assert result["decision"]["authority_provider"] == "fake-pdp"
    assert result["token"] is None


def test_limit_requires_and_uses_host_owned_transformation(tmp_path):
    no_rule = Kernel({}, authority_pdp=FakePDP(LIMIT)).decide(_action())
    assert no_rule["decision"]["verdict"] == DENY
    assert no_rule["token"] is None

    policy = {
        "redactions": [
            {"action_purpose": "support_reply", "redact_fields": ["ssn"]}
        ]
    }
    dos = DecisionOS(
        policy,
        audit_path=str(tmp_path / "limit.jsonl"),
        authority_pdp=FakePDP(LIMIT),
    )
    outcome = dos.handle(
        _action(payload={"body": "ok", "ssn": "123"}, nonce="limit"),
        {"send_email": lambda payload: payload},
    )
    assert outcome.executed
    assert outcome.output == {"body": "ok", "ssn": "[REDACTED]"}


def test_containment_is_kernel_owned_not_provider_owned():
    result = Kernel(
        {},
        authority_pdp=FakePDP(
            {
                "verdict": CONTAIN,
                "containment": {"allowed_tools": ["wire_money"], "network": "host"},
            }
        ),
    ).decide(_action())
    assert result["decision"]["verdict"] == CONTAIN
    assert result["decision"]["containment"] == {
        "sandbox": True,
        "network": "none",
        "allowed_tools": [],
        "time_limit_seconds": 5,
    }


def test_external_policy_cannot_be_mutated_through_kernel():
    kernel = Kernel({}, authority_pdp=FakePDP())
    with pytest.raises(AuthorityMutationUnsupported):
        kernel.grant("agent:x", "tool:y")
    with pytest.raises(AuthorityMutationUnsupported):
        kernel.revoke("agent:x", "tool:y")
    with pytest.raises(AuthorityMutationUnsupported):
        kernel.delegate("agent:x", "agent:y", ["send_email"])


class _OPAHandler(BaseHTTPRequestHandler):
    result: Any = True

    def log_message(self, format, *args):
        return

    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        request = self.rfile.read(length)
        assert "input" in json.loads(request)
        body = json.dumps({"result": self.result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def opa_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OPAHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_opa_http_adapter_maps_real_data_api_shape(opa_server):
    pdp = OPAHTTPAuthorityPDP(
        f"{opa_server}/v1/data/decision/allow",
        policy_revision="opa-test-v1",
    )
    _OPAHandler.result = True
    allow = pdp.evaluate(_action())
    _OPAHandler.result = {"verdict": "DEFER", "reason": "review"}
    defer = pdp.evaluate(_action())
    healthy, _ = pdp.healthcheck()

    assert allow.verdict == ALLOW
    assert defer.verdict == "DEFER"
    assert healthy


def test_opa_oversized_or_malformed_response_fails_closed(opa_server):
    pdp = OPAHTTPAuthorityPDP(
        f"{opa_server}/v1/data/decision/allow",
        policy_revision="opa-test-v1",
        max_response_bytes=32,
    )
    _OPAHandler.result = "A" * 100
    result = Kernel({}, authority_pdp=pdp).decide(_action())
    assert result["decision"]["verdict"] == DENY
    assert result["token"] is None


def _cedar_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    policy = tmp_path / "policy.cedar"
    entities = tmp_path / "entities.json"
    schema = tmp_path / "schema.cedarschema"
    policy.write_text("permit(principal, action, resource);", encoding="utf-8")
    entities.write_text("[]", encoding="utf-8")
    schema.write_text("entity Agent;", encoding="utf-8")
    return policy, entities, schema


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [(0, ALLOW), (2, DENY), (1, DENY), (3, DENY)],
)
def test_cedar_cli_exit_contract_is_fail_closed(
    monkeypatch, tmp_path, returncode, expected
):
    policy, entities, schema = _cedar_files(tmp_path)
    captured: dict[str, Any] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        request_index = command.index("--request-json") + 1
        captured["request"] = json.loads(
            Path(command[request_index]).read_text(encoding="utf-8")
        )
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout="ALLOW" if returncode == 0 else "DENY",
            stderr="validation failed" if returncode not in {0, 2} else "",
        )

    monkeypatch.setattr("decision_os_min.authority_pdp.subprocess.run", fake_run)
    pdp = CedarCLIAuthorityPDP(
        "cedar",
        policies=policy,
        entities=entities,
        schema=schema,
        policy_revision="cedar-test-v1",
    )
    result = Kernel({}, authority_pdp=pdp).decide(_action())

    assert result["decision"]["verdict"] == expected
    assert ("--schema" in captured["command"]) is True
    assert captured["request"]["principal"] == 'Agent::"agent:external"'
    assert captured["request"]["action"] == 'Action::"send_email"'
    if returncode not in {0, 2}:
        assert result["token"] is None


def test_agent_host_accepts_replaceable_authority_without_exposing_effects(tmp_path):
    effects: list[str] = []
    host = AgentHost(
        policy={},
        legitimacy=lambda action: (True, "legitimate", ()),
        adapters={
            "deploy_ranking": lambda *, model: effects.append(model) or f"deployed:{model}"
        },
        audit_path=str(tmp_path / "host.jsonl"),
        spent_store=InMemorySpentStore(),
        authority_pdp=FakePDP(ALLOW),
    )
    host.register_agent("bot-1", actor="agent:external", stakeholder="ops")

    outcome = host.handle_intent(
        Intent("bot-1", "deploy_ranking", {"model": "v1"}, "deploy", "ranking")
    )
    assert outcome.ok and outcome.output == "deployed:v1"
    assert effects == ["v1"]
    with pytest.raises(RuntimeError, match="not available to agents"):
        host.adapters["deploy_ranking"](model="bypass")


def test_service_selects_opa_and_reports_readiness(monkeypatch, opa_server):
    from decision_os_min.service import create_app

    _OPAHandler.result = True
    monkeypatch.setenv("DECISION_OS_AUTHORITY_PDP", "opa")
    monkeypatch.setenv(
        "DECISION_OS_OPA_DECISION_URL",
        f"{opa_server}/v1/data/decision/allow",
    )
    monkeypatch.setenv("DECISION_OS_OPA_POLICY_REVISION", "bundle-sha-1")
    app = create_app()
    client = TestClient(app)

    ready = client.get("/readyz").json()
    decided = client.post(
        "/v1/decide",
        json={
            "actor": "agent:not-in-builtin-policy",
            "tool": "send_email",
            "capability": "tool:send_email",
            "action_purpose": "support_reply",
            "data_labels": [],
            "payload": {},
            "nonce": "opa-service",
        },
    ).json()
    assert ready["status"] == "ready"
    assert ready["authority_provider"] == "opa"
    assert ready["authority_policy_revision"] == "bundle-sha-1"
    assert decided["decision"]["verdict"] == ALLOW
    assert decided["token"] is not None


def test_service_constructs_cedar_provider_from_explicit_env(monkeypatch, tmp_path):
    from decision_os_min.authority_pdp import CedarCLIAuthorityPDP
    from decision_os_min.service import _load_authority_pdp

    policy, entities, schema = _cedar_files(tmp_path)
    monkeypatch.setenv("DECISION_OS_AUTHORITY_PDP", "cedar")
    monkeypatch.setenv("DECISION_OS_CEDAR_BIN", "cedar")
    monkeypatch.setenv("DECISION_OS_CEDAR_POLICIES", str(policy))
    monkeypatch.setenv("DECISION_OS_CEDAR_ENTITIES", str(entities))
    monkeypatch.setenv("DECISION_OS_CEDAR_SCHEMA", str(schema))
    monkeypatch.setenv("DECISION_OS_CEDAR_POLICY_REVISION", "cedar-sha-1")
    monkeypatch.setenv(
        "DECISION_OS_CEDAR_CONTEXT_MAP",
        '{"purpose":"action_purpose","consent":"payload.consent"}',
    )
    provider = _load_authority_pdp()

    assert isinstance(provider, CedarCLIAuthorityPDP)
    assert provider.policy_revision == "cedar-sha-1"
    assert provider.context_map["consent"] == "payload.consent"
